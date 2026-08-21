#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import io
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile


HELPER = Path(__file__).resolve().parents[1] / "mkosi.scripts/repart-archive"
TEMPLATES = Path(__file__).resolve().parents[1] / "mkosi.repart"


def archive(path: Path, entries: list[tuple[str, bytes, str]]) -> None:
    with tarfile.open(path, "w") as output:
        for name, data, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode = 0o644
            if kind == "file":
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
            elif kind == "symlink":
                member.type = tarfile.SYMTYPE
                member.linkname = "40-root.conf"
                output.addfile(member)
            elif kind == "fifo":
                member.type = tarfile.FIFOTYPE
                output.addfile(member)
            else:
                raise AssertionError(kind)


def run_case(
    root: Path,
    name: str,
    entries: list[tuple[str, bytes, str]],
    ok: bool,
    label: str | None = None,
) -> None:
    source = root / f"{name}.tar"
    target = root / name
    archive(source, entries)
    command = [str(HELPER), str(source), str(target)]
    if label is not None:
        command.append(label)
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if (result.returncode == 0) != ok:
        raise AssertionError(f"{name}: rc={result.returncode}: {result.stderr}")


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="particleos-repart-test.") as temporary:
        root = Path(temporary)
        expected = [
            (f"./{path.name}", path.read_bytes(), "file")
            for path in sorted(TEMPLATES.glob("*.conf"))
        ]
        run_case(root, "good", expected, True)
        symlink_source = root / "source-symlink.tar"
        symlink_source.symlink_to(root / "good.tar")
        result = subprocess.run(
            [str(HELPER), str(symlink_source), str(root / "source-symlink")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            raise AssertionError("source-symlink: archive symlink was accepted")
        versioned = [
            (
                name,
                data.replace(b"Label=%M_%A_vsig", b"Label=ParticleOS-Host_44.85.0_vsig"),
                kind,
            )
            for name, data, kind in expected
        ]
        run_case(
            root,
            "versioned",
            versioned,
            True,
            label="ParticleOS-Host_44.85.0_vsig",
        )
        run_case(root, "versioned-without-label", versioned, False)
        run_case(root, "unsafe-label", versioned, False, label="../unsafe")
        for _, data, _ in expected:
            assert data

        bad_cases = {
            "absolute": [("/etc/shadow.conf", b"x", "file")],
            "traversal": [("../escape.conf", b"x", "file")],
            "nested": [("nested/40-root.conf", b"x", "file")],
            "suffix": [("40-root.txt", b"x", "file")],
            "symlink": [("40-root.conf", b"", "symlink")],
            "fifo": [("40-root.conf", b"", "fifo")],
            "oversize": [("40-root.conf", b"x" * (64 * 1024 + 1), "file")],
            "duplicate": [
                ("40-root.conf", b"one", "file"),
                ("./40-root.conf", b"two", "file"),
            ],
            "extra-valid-definition": expected
            + [("99-extra.conf", b"[Partition]\nType=root\n", "file")],
            "changed-directive": [
                (name, data.replace(b"CopyFiles=/usr:/", b"CopyFiles=/etc:/"), kind)
                for name, data, kind in expected
            ],
            "missing-definition": expected[:-1],
        }
        for name, entries in bad_cases.items():
            run_case(root, name, entries, False)

    print("hostile repart archive policy tests passed")


if __name__ == "__main__":
    main()
