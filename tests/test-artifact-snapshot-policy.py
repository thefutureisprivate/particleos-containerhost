#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import sys
import tempfile


HELPER = Path(__file__).resolve().parents[1] / "scripts/snapshot-artifacts.py"
PREFIX = "ParticleOS-Host_44.85.0_x86-64"
UUIDS = {
    "usr": "0123456789abcdef0123456789abcdef",
    "verity": "123456789abcdef0123456789abcdef0",
    "verity-sig": "23456789abcdef0123456789abcdef01",
}


def names() -> set[str]:
    result = {
        f"{PREFIX}.efi",
        f"{PREFIX}.esp.raw.zst",
        f"{PREFIX}.manifest.gz",
        f"{PREFIX}.osrelease",
        f"{PREFIX}.raw.zst",
        f"{PREFIX}.repart.tar",
        f"{PREFIX}.SHA256SUMS",
        f"{PREFIX}.SHA256SUMS.sha256",
        f"{PREFIX}.SHA256SUMS.sha256.asc",
    }
    result.update(
        {
            f"{PREFIX}.usr-x86-64.{UUIDS['usr']}.raw.zst",
            f"{PREFIX}.usr-x86-64-verity.{UUIDS['verity']}.raw.zst",
            f"{PREFIX}.usr-x86-64-verity-sig.{UUIDS['verity-sig']}.raw.zst",
        }
    )
    return result


def populate(source: Path) -> None:
    source.mkdir()
    for name in names():
        (source / name).write_bytes((name + "\n").encode())


def run_case(root: Path, case: str, mutate, accepted: bool) -> None:
    source = root / f"{case}-source"
    destination = root / f"{case}-snapshot"
    populate(source)
    mutate(source)
    result = subprocess.run(
        [sys.executable, str(HELPER), str(source), str(destination)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"{case}: rc={result.returncode}: {result.stderr}")
    if accepted:
        assert {entry.name for entry in os.scandir(destination)} == names()
        assert stat_mode(destination) == 0o700
        assert all(stat_mode(destination / name) == 0o600 for name in names())
    else:
        assert not destination.exists()


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="particleos-artifact-snapshot-test.") as temporary:
        root = Path(temporary)
        run_case(root, "good", lambda source: None, True)
        run_case(
            root,
            "extra",
            lambda source: (source / f"{PREFIX}.unexpected").write_bytes(b"x"),
            False,
        )
        run_case(
            root,
            "missing",
            lambda source: (source / f"{PREFIX}.efi").unlink(),
            False,
        )

        def replace_with_symlink(source: Path) -> None:
            target = source / f"{PREFIX}.efi"
            target.unlink()
            target.symlink_to("/etc/passwd")

        run_case(root, "symlink", replace_with_symlink, False)
        run_case(
            root,
            "version-mix",
            lambda source: (source / f"{PREFIX}.efi").rename(
                source / "ParticleOS-Host_44.84.9_x86-64.efi"
            ),
            False,
        )

    print("exact immutable artifact snapshot policy tests passed")


if __name__ == "__main__":
    main()
