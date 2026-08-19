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


def run_case(root: Path, name: str, entries: list[tuple[str, bytes, str]], ok: bool) -> None:
    source = root / f"{name}.tar"
    target = root / name
    archive(source, entries)
    result = subprocess.run(
        [str(HELPER), str(source), str(target)],
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
        run_case(root, "good", [("./40-root.conf", b"[Partition]\nType=root\n", "file")], True)
        assert (root / "good/40-root.conf").read_bytes() == b"[Partition]\nType=root\n"

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
        }
        for name, entries in bad_cases.items():
            run_case(root, name, entries, False)

    print("hostile repart archive policy tests passed")


if __name__ == "__main__":
    main()
