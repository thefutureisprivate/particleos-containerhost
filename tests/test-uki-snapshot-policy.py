#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

from pathlib import Path
from importlib.machinery import SourceFileLoader
import importlib.util
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


HELPER = (
    Path(__file__).resolve().parents[1]
    / "mkosi.extra/usr/lib/particleos/snapshot-uki"
)


def invoke(source: Path, destination: Path, name: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(HELPER), str(source), str(destination), name],
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

        raced_source = root / "raced.efi"
        raced_source.write_bytes(b"reviewed-before-open")
        raced_destination = root / "raced-snapshot"
        raced_destination.mkdir(mode=0o700)
        loader = SourceFileLoader("particleos_snapshot_uki", str(HELPER))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        assert spec is not None
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        original_copy = module.shutil.copyfileobj

        def replace_path_after_open(input_file, output_file, length):
            raced_source.unlink()
            raced_source.write_bytes(b"attacker-replacement")
            original_copy(input_file, output_file, length)

        module.shutil.copyfileobj = replace_path_after_open
        saved_argv = sys.argv
        try:
            sys.argv = [str(HELPER), str(raced_source), str(raced_destination), "0.efi"]
            try:
                module.main()
            except SystemExit:
                pass
            else:
                raise AssertionError("path replacement during snapshot was accepted")
        finally:
            sys.argv = saved_argv
        assert list(raced_destination.iterdir()) == []

    print("stable UKI policy-input snapshot tests passed")


if __name__ == "__main__":
    main()
