#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

from __future__ import annotations

import copy
import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


sys.dont_write_bytecode = True

REPOSITORY = Path(__file__).resolve().parents[1]
HELPER = REPOSITORY / "mkosi.scripts" / "validate-systemd-manifest"
EXPECTED_VERSION = (REPOSITORY / "mkosi.resources" / "systemd-version").read_text().strip()
SYSTEMD_PACKAGES = {
    "systemd",
    "systemd-boot",
    "systemd-container",
    "systemd-libs",
    "systemd-networkd",
    "systemd-networkd-defaults",
    "systemd-oomd-defaults",
    "systemd-pam",
    "systemd-resolved",
    "systemd-shared",
    "systemd-standalone-sysusers",
    "systemd-udev",
}


def package(name: str, version: str = EXPECTED_VERSION) -> dict[str, str]:
    return {"type": "rpm", "name": name, "version": version, "architecture": "x86_64"}


def good_manifest() -> dict[str, object]:
    packages = [package(name) for name in sorted(SYSTEMD_PACKAGES)]
    packages.extend([package("podman", "5.8.4-1.fc44"), package("runsc", "20260810.0-1")])
    return {
        "manifest_version": 1,
        "config": {
            "name": "ParticleOS-Host",
            "distribution": "fedora",
            "architecture": "x86-64",
            "output_format": "disk",
            "version": "44.86.1",
            "release": "44",
        },
        "packages": packages,
        "extension": {},
    }


def run_case(root: Path, case: str, mutate, accepted: bool) -> None:
    source = root / f"{case}-source"
    output = root / f"{case}-output"
    (source / "mkosi.resources").mkdir(parents=True)
    output.mkdir()
    (source / "mkosi.resources" / "systemd-version").write_text(EXPECTED_VERSION + "\n")
    document = good_manifest()
    path = output / "ParticleOS-Host_44.86.1_x86-64.manifest.gz"
    mutate(document, path)
    if not path.exists() and not path.is_symlink():
        with gzip.open(path, "wt", encoding="utf-8") as stream:
            json.dump(document, stream)
    environment = os.environ.copy()
    environment.update({"SRCDIR": str(source), "OUTPUTDIR": str(output)})
    result = subprocess.run(
        [sys.executable, str(HELPER)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if (result.returncode == 0) != accepted:
        raise AssertionError(f"{case}: rc={result.returncode}: {result.stderr}")


def main() -> None:
    cases = []
    cases.append(("good", lambda document, path: None, True))

    def rollback(document, path):
        for entry in document["packages"]:
            if entry["name"] == "systemd-libs":
                entry["version"] = "260.1-1"

    cases.append(("rollback", rollback, False))
    cases.append(
        (
            "extra-systemd",
            lambda document, path: document["packages"].append(package("systemd-unreviewed")),
            False,
        )
    )
    cases.append(
        (
            "missing-systemd",
            lambda document, path: document["packages"].pop(0),
            False,
        )
    )
    cases.append(
        (
            "duplicate",
            lambda document, path: document["packages"].append(copy.deepcopy(document["packages"][0])),
            False,
        )
    )
    cases.append(
        (
            "missing-runtime",
            lambda document, path: document["packages"].pop(),
            False,
        )
    )
    cases.append(
        (
            "wrong-schema",
            lambda document, path: document.update({"unexpected": True}),
            False,
        )
    )

    def symlink(document, path):
        path.symlink_to("/etc/passwd")

    cases.append(("symlink", symlink, False))

    with tempfile.TemporaryDirectory(prefix="particleos-systemd-manifest-test.") as temporary:
        root = Path(temporary)
        for case, mutate, accepted in cases:
            run_case(root, case, mutate, accepted)

    print("exact systemd manifest policy tests passed")


if __name__ == "__main__":
    main()
