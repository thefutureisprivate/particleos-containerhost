#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

from pathlib import Path
import os
import subprocess
import tempfile
import threading
import time

HELPER = (
    Path(__file__).resolve().parents[1]
    / "mkosi.extra/usr/lib/particleos/snapshot-uki"
)


def invoke(source: Path, destination: Path, name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(HELPER), str(source), str(destination), name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="particleos-uki-snapshot-test.") as temporary:
        root = Path(temporary)
        source = root / "source.efi"
        source.write_bytes(b"reviewed-uki")
        destination = root / "snapshot"
        destination.mkdir(mode=0o700)
        result = invoke(source, destination, "0.efi")
        assert result.returncode == 0, result.stderr
        assert (destination / "0.efi").read_bytes() == b"reviewed-uki"
        assert (destination / "0.efi").stat().st_mode & 0o777 == 0o400

        symlink = root / "symlink.efi"
        symlink.symlink_to(source)
        rejected = root / "rejected"
        rejected.mkdir(mode=0o700)
        result = invoke(symlink, rejected, "0.efi")
        assert result.returncode != 0
        assert list(rejected.iterdir()) == []

        result = invoke(source, destination, "0.efi")
        assert result.returncode != 0
        result = invoke(source, destination, "../escape.efi")
        assert result.returncode != 0

        destination_symlink = root / "snapshot-link"
        destination_symlink.symlink_to(rejected, target_is_directory=True)
        result = invoke(source, destination_symlink, "0.efi")
        assert result.returncode != 0
        assert list(rejected.iterdir()) == []

        raced_source = root / "raced.efi"
        with raced_source.open("wb") as output:
            output.truncate(64 * 1024 * 1024)
        raced_destination = root / "raced-snapshot"
        raced_destination.mkdir(mode=0o700)
        stop = threading.Event()

        def mutate_source() -> None:
            value = 0
            while not stop.is_set():
                with raced_source.open("r+b", buffering=0) as file:
                    file.write(bytes((value,)))
                    os.fsync(file.fileno())
                value ^= 1

        mutator = threading.Thread(target=mutate_source)
        mutator.start()
        time.sleep(0.01)
        try:
            result = invoke(raced_source, raced_destination, "0.efi")
        finally:
            stop.set()
            mutator.join()
        assert result.returncode != 0
        assert list(raced_destination.iterdir()) == []

    print("stable UKI policy-input snapshot tests passed")


if __name__ == "__main__":
    main()
