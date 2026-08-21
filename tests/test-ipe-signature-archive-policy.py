#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

from pathlib import Path
import stat
import subprocess
import sys
import tempfile


HELPER = (
    Path(__file__).resolve().parents[1]
    / ".obs/ipe-policy-containerhost/extract-ipe-signature.py"
)


def pad4(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def member(name: str, data: bytes, mode: int = stat.S_IFREG | 0o644, nlink: int = 1) -> bytes:
    encoded = name.encode() + b"\0"
    fields = (1, mode, 0, 0, nlink, 0, len(data), 0, 0, 0, 0, len(encoded), 0)
    header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields)
    assert len(header) == 110
    name_padding = b"\0" * (-(len(header) + len(encoded)) % 4)
    data_padding = b"\0" * (-len(data) % 4)
    return header + encoded + name_padding + data + data_padding


def archive(entries: list[bytes], trailer: bool = True) -> bytes:
    result = b"".join(entries)
    if trailer:
        result += member("TRAILER!!!", b"", mode=0, nlink=1)
    return result + b"\0" * 512


def run_case(root: Path, name: str, payload: bytes, ok: bool) -> None:
    source = root / f"{name}.cpio"
    destination = root / name
    source.write_bytes(payload)
    destination.mkdir()
    result = subprocess.run(
        [sys.executable, str(HELPER), str(source), str(destination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if (result.returncode == 0) != ok:
        raise AssertionError(f"{name}: rc={result.returncode}: {result.stderr}")
    if ok:
        assert (destination / "ipe-policy.sig").read_bytes() == b"signature"


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="particleos-ipe-archive-test.") as temporary:
        root = Path(temporary)
        good = member("./ipe-policy.sig", b"signature")
        run_case(root, "good", archive([good]), True)
        symlink_source = root / "source-symlink.cpio"
        symlink_source.symlink_to(root / "good.cpio")
        symlink_destination = root / "source-symlink"
        symlink_destination.mkdir()
        result = subprocess.run(
            [sys.executable, str(HELPER), str(symlink_source), str(symlink_destination)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            raise AssertionError("source-symlink: archive symlink was accepted")
        cases = {
            "absolute": archive([member("/tmp/ipe-policy.sig", b"signature")]),
            "traversal": archive([member("../ipe-policy.sig", b"signature")]),
            "unexpected": archive([member("other.sig", b"signature")]),
            "duplicate": archive([good, good]),
            "symlink": archive([member("ipe-policy.sig", b"x", stat.S_IFLNK | 0o777)]),
            "device": archive([member("ipe-policy.sig", b"x", stat.S_IFCHR | 0o600)]),
            "hardlink": archive([member("ipe-policy.sig", b"x", nlink=2)]),
            "oversize": archive([member("ipe-policy.sig", b"x" * (8 * 1024 + 1))]),
            "no-trailer": archive([good], trailer=False).rstrip(b"\0"),
        }
        for name, payload in cases.items():
            run_case(root, name, payload, False)

    print("hostile IPE signer-response archive policy tests passed")


if __name__ == "__main__":
    main()
