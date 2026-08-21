#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
helper=$repository/mkosi.scripts/validate-systemd-manifest
temporary=$(mktemp -d /tmp/particleos-systemd-manifest-test.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT

expected_version=$(sed -n -E 's/^EXPECTED_SYSTEMD_VERSION = "([0-9A-Za-z.+~^-]+)"$/\1/p' "$helper")
[[ -n $expected_version ]] || { echo 'cannot read the reviewed systemd version' >&2; exit 1; }
systemd_packages=(
    systemd systemd-boot systemd-container systemd-libs systemd-networkd
    systemd-networkd-defaults systemd-oomd-defaults systemd-pam
    systemd-resolved systemd-shared systemd-standalone-sysusers systemd-udev
)

jq -n --arg version "$expected_version" '
    {
        manifest_version: 1,
        config: {
            name: "ParticleOS-Host",
            distribution: "fedora",
            architecture: "x86-64",
            output_format: "disk",
            version: "44.86.1",
            release: "44"
        },
        packages: ([$ARGS.positional[] | {
            type: "rpm", name: ., version: $version, architecture: "x86_64"
        }] + [
            {type: "rpm", name: "podman", version: "5.8.4-1.fc44", architecture: "x86_64"},
            {type: "rpm", name: "runsc", version: "20260810.0-1", architecture: "x86_64"}
        ]),
        extension: {}
    }
' --args "${systemd_packages[@]}" >"$temporary/base.json"

run_case() {
    local case_name=$1 accepted=$2 filter=$3 format=${4:-compressed}
    local output=$temporary/$case_name-output path status
    mkdir "$output"
    if [[ $format == compressed ]]; then
        path=$output/ParticleOS-Host_44.86.1_x86-64.manifest.gz
        jq "$filter" "$temporary/base.json" | gzip -n >"$path"
    else
        path=$output/ParticleOS-Host_44.86.1_x86-64.manifest
        jq "$filter" "$temporary/base.json" >"$path"
    fi
    set +e
    OUTPUTDIR=$output "$helper" >"$temporary/$case_name.out" 2>"$temporary/$case_name.err"
    status=$?
    set -e
    if [[ $accepted == yes ]]; then
        ((status == 0)) || { cat "$temporary/$case_name.err" >&2; return 1; }
    else
        ((status != 0))
    fi
}

run_case good yes '.'
run_case rollback no '(.packages[] | select(.name == "systemd-libs").version) = "260.1-1"'
run_case extra-systemd no '.packages += [{type:"rpm",name:"systemd-unreviewed",version:.packages[0].version,architecture:"x86_64"}]'
run_case missing-systemd no '.packages |= .[1:]'
run_case duplicate no '.packages += [.packages[0]]'
run_case missing-runtime no 'del(.packages[-1])'
run_case wrong-schema no '.unexpected = true'
run_case post-output-raw yes '.' raw

symlink_output=$temporary/symlink-output
mkdir "$symlink_output"
ln -s /etc/passwd "$symlink_output/ParticleOS-Host_44.86.1_x86-64.manifest.gz"
if OUTPUTDIR=$symlink_output "$helper"; then
    echo 'manifest symlink was accepted' >&2
    exit 1
fi

both_output=$temporary/both-formats-output
mkdir "$both_output"
gzip -n -c "$temporary/base.json" >"$both_output/ParticleOS-Host_44.86.1_x86-64.manifest.gz"
cp "$temporary/base.json" "$both_output/ParticleOS-Host_44.86.1_x86-64.manifest"
if OUTPUTDIR=$both_output "$helper"; then
    echo 'simultaneous raw and compressed manifests were accepted' >&2
    exit 1
fi

echo 'exact systemd manifest policy tests passed'
