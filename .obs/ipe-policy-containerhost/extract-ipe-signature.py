#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Extract one OBS IPE signature from a hostile newc archive."""

from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


MAX_ARCHIVE_SIZE = 64 * 1024
MAX_SIGNATURE_SIZE = 8 * 1024
HEADER_SIZE = 110


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"unsafe IPE signer response: {message}")


def align4(value: int) -> int:
    return (value + 3) & ~3


def read_stable_archive(path: Path) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as error:
        fail(f"cannot open archive safely: {error}")
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            fail("archive is not a regular file")
        if not 1 <= before.st_size <= MAX_ARCHIVE_SIZE:
            fail("archive size is outside the accepted range")
        chunks: list[bytes] = []
        remaining = MAX_ARCHIVE_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(16 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        after = os.fstat(descriptor)
        identity = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if identity(before) != identity(after) or len(data) != before.st_size:
            fail("archive changed while being read")
        return data
    finally:
        os.close(descriptor)


def parse_newc(archive: bytes) -> bytes:
    offset = 0
    signature: bytes | None = None
    trailer = False

    while offset < len(archive):
        if archive[offset:] == b"\0" * (len(archive) - offset):
            break
        if trailer or offset + HEADER_SIZE > len(archive):
            fail("truncated data or content after trailer")

        header = archive[offset : offset + HEADER_SIZE]
        offset += HEADER_SIZE
        if header[:6] != b"070701":
            fail("only non-CRC newc archives are accepted")
        try:
            fields = [int(header[6 + index * 8 : 14 + index * 8], 16) for index in range(13)]
        except ValueError:
            fail("malformed newc header")
        mode, nlink, size, name_size = fields[1], fields[4], fields[6], fields[11]
        if not 1 <= name_size <= 64 or offset + name_size > len(archive):
            fail("invalid member name size")
        raw_name = archive[offset : offset + name_size]
        if raw_name[-1:] != b"\0" or b"\0" in raw_name[:-1]:
            fail("invalid member name")
        try:
            name = raw_name[:-1].decode("ascii")
        except UnicodeDecodeError:
            fail("non-ASCII member name")
        offset = align4(offset + name_size)
        if offset > len(archive):
            fail("truncated member-name padding")
        if offset + size > len(archive):
            fail("truncated member data")
        data = archive[offset : offset + size]
        offset = align4(offset + size)
        if offset > len(archive):
            fail("truncated member-data padding")

        if name == "TRAILER!!!":
            if size != 0:
                fail("trailer carries data")
            trailer = True
            continue

        normalized = name[2:] if name.startswith("./") else name
        if normalized != "ipe-policy.sig":
            fail(f"unexpected member {name!r}")
        if signature is not None:
            fail("duplicate signature member")
        if not stat.S_ISREG(mode) or nlink != 1:
            fail("signature member is not a single regular file")
        if mode & 0o7000:
            fail("signature member carries special mode bits")
        if not 1 <= size <= MAX_SIGNATURE_SIZE:
            fail("signature size is outside the accepted range")
        signature = data

    if not trailer or signature is None:
        fail("archive lacks its one signature or trailer")
    return signature


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(f"usage: {sys.argv[0]} ARCHIVE DESTINATION_DIRECTORY")
    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    signature = parse_newc(read_stable_archive(source))

    destination_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        output_fd = os.open(
            "ipe-policy.sig",
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_fd,
        )
        with os.fdopen(output_fd, "wb") as output:
            output.write(signature)
    finally:
        os.close(destination_fd)


if __name__ == "__main__":
    main()
