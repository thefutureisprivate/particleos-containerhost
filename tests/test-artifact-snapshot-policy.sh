#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
helper=$repository/scripts/snapshot-artifacts.py
prefix=ParticleOS-Host_44.85.0_x86-64
usr_uuid=0123456789abcdef0123456789abcdef
verity_uuid=123456789abcdef0123456789abcdef0
signature_uuid=23456789abcdef0123456789abcdef01
temporary=$(mktemp -d /tmp/particleos-artifact-snapshot-test.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT

names=(
    "$prefix.efi"
    "$prefix.esp.raw.zst"
    "$prefix.manifest.gz"
    "$prefix.osrelease"
    "$prefix.raw.zst"
    "$prefix.repart.tar"
    "$prefix.SHA256SUMS"
    "$prefix.SHA256SUMS.sha256"
    "$prefix.SHA256SUMS.sha256.asc"
    "$prefix.usr-x86-64.$usr_uuid.raw.zst"
    "$prefix.usr-x86-64-verity.$verity_uuid.raw.zst"
    "$prefix.usr-x86-64-verity-sig.$signature_uuid.raw.zst"
)

populate() {
    local source=$1 name
    mkdir "$source"
    for name in "${names[@]}"; do
        printf '%s\n' "$name" >"$source/$name"
    done
}

assert_case() {
    local case_name=$1 accepted=$2
    local source=$temporary/$case_name-source
    local destination=$temporary/$case_name-snapshot status actual expected
    shift 2
    populate "$source"
    "$@" "$source"
    set +e
    "$helper" "$source" "$destination" >"$temporary/$case_name.out" 2>"$temporary/$case_name.err"
    status=$?
    set -e
    if [[ $accepted == yes ]]; then
        ((status == 0)) || { cat "$temporary/$case_name.err" >&2; return 1; }
        expected=$(printf '%s\n' "${names[@]}" | sort)
        actual=$(find "$destination" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
        [[ $actual == "$expected" && $(stat -c '%a' "$destination") == 700 ]]
        while IFS= read -r name; do
            [[ $(stat -c '%a' "$destination/$name") == 600 ]]
        done <<<"$actual"
    else
        ((status != 0)) && [[ ! -e $destination ]]
    fi
}

unchanged() { :; }
add_extra() { printf x >"$1/$prefix.unexpected"; }
remove_member() { rm -- "$1/$prefix.efi"; }
make_symlink() { rm -- "$1/$prefix.efi"; ln -s /etc/passwd "$1/$prefix.efi"; }
mix_version() { mv -- "$1/$prefix.efi" "$1/ParticleOS-Host_44.84.9_x86-64.efi"; }

assert_case good yes unchanged
assert_case extra no add_extra
assert_case missing no remove_member
assert_case symlink no make_symlink
assert_case version-mix no mix_version

echo 'exact immutable artifact snapshot policy tests passed'
