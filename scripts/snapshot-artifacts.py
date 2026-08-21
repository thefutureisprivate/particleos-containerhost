#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Copy one release into a private, stable validation snapshot."""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import stat
import sys


DIGEST_NAME = re.compile(
    r"^(ParticleOS-Host_[0-9]+\.[0-9]+\.[0-9]+_x86-64)\.SHA256SUMS\.sha256$"
)
UUID = r"[0-9a-f]{32}"


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"unsafe artifact directory: {message}")


def fixed_names(prefix: str) -> set[str]:
    return {
        f"{prefix}.efi",
        f"{prefix}.esp.raw.zst",
        f"{prefix}.manifest.gz",
        f"{prefix}.osrelease",
        f"{prefix}.raw.zst",
        f"{prefix}.repart.tar",
        f"{prefix}.SHA256SUMS",
        f"{prefix}.SHA256SUMS.sha256",
        f"{prefix}.SHA256SUMS.sha256.asc",
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} SOURCE_DIRECTORY DESTINATION_DIRECTORY")
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    if source.is_symlink() or not source.is_dir() or destination.exists():
        fail("source must be a real directory and destination must not exist")

    entries = {entry.name: entry for entry in os.scandir(source)}
    digest_names = [name for name in entries if DIGEST_NAME.fullmatch(name)]
    if len(digest_names) != 1:
        fail(f"expected one canonical signed-digest name, found {len(digest_names)}")
    match = DIGEST_NAME.fullmatch(digest_names[0])
    assert match is not None
    prefix = match.group(1)
    selected = fixed_names(prefix)
    patterns = [
        re.compile(rf"^{re.escape(prefix)}\.usr-x86-64\.{UUID}\.raw\.zst$"),
        re.compile(rf"^{re.escape(prefix)}\.usr-x86-64-verity\.{UUID}\.raw\.zst$"),
        re.compile(rf"^{re.escape(prefix)}\.usr-x86-64-verity-sig\.{UUID}\.raw\.zst$"),
    ]
    for pattern in patterns:
        matches = [name for name in entries if pattern.fullmatch(name)]
        if len(matches) != 1:
            fail(f"expected one artifact matching {pattern.pattern!r}, found {len(matches)}")
        selected.add(matches[0])

    published = {name for name in entries if name.startswith("ParticleOS-Host_")}
    if published != selected:
        fail(f"release artifact set differs from the exact schema: {sorted(published ^ selected)}")

    destination.mkdir(mode=0o700)
    source_fd = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in sorted(selected):
            entry = entries[name]
            if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                fail(f"{name!r} is not a regular non-symlink file")
            input_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
            try:
                before = os.fstat(input_fd)
                if not stat.S_ISREG(before.st_mode):
                    fail(f"{name!r} changed type while opening")
                output_fd = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=destination_fd,
                )
                with os.fdopen(output_fd, "wb") as output, os.fdopen(
                    os.dup(input_fd), "rb"
                ) as input_file:
                    shutil.copyfileobj(input_file, output, length=1024 * 1024)
                    output.flush()
                    os.fsync(output.fileno())
                after = os.fstat(input_fd)
                before_identity = (
                    before.st_dev,
                    before.st_ino,
                    before.st_size,
                    before.st_mtime_ns,
                    before.st_ctime_ns,
                )
                after_identity = (
                    after.st_dev,
                    after.st_ino,
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                )
                if before_identity != after_identity:
                    fail(f"{name!r} changed while being snapshotted")
            finally:
                os.close(input_fd)
        os.fsync(destination_fd)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    finally:
        os.close(destination_fd)
        os.close(source_fd)


if __name__ == "__main__":
    main()
