#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
helper=$repository/mkosi.extra/usr/lib/particleos/snapshot-uki
temporary=$(mktemp -d /tmp/particleos-uki-snapshot-test.XXXXXXXX)
mutator_pid=

cleanup() {
    rm -f -- "$temporary/mutate"
    [[ $mutator_pid =~ ^[1-9][0-9]*$ ]] && wait "$mutator_pid" 2>/dev/null || true
    rm -rf -- "$temporary"
}
trap cleanup EXIT

source_uki=$temporary/source.efi
destination=$temporary/snapshot
printf '%s' reviewed-uki >"$source_uki"
mkdir -m 0700 "$destination"
"$helper" "$source_uki" "$destination" 0.efi
cmp -- "$source_uki" "$destination/0.efi"
[[ $(stat -c '%a' "$destination/0.efi") == 400 ]]

ln -s "$source_uki" "$temporary/symlink.efi"
mkdir -m 0700 "$temporary/rejected"
if "$helper" "$temporary/symlink.efi" "$temporary/rejected" 0.efi; then
    echo 'UKI source symlink was accepted' >&2
    exit 1
fi
[[ -z $(find "$temporary/rejected" -mindepth 1 -print -quit) ]]
if "$helper" "$source_uki" "$destination" 0.efi; then
    echo 'existing UKI snapshot was overwritten' >&2
    exit 1
fi
if "$helper" "$source_uki" "$destination" ../escape.efi; then
    echo 'unsafe UKI snapshot name was accepted' >&2
    exit 1
fi
ln -s "$temporary/rejected" "$temporary/snapshot-link"
if "$helper" "$source_uki" "$temporary/snapshot-link" 0.efi; then
    echo 'UKI snapshot destination symlink was accepted' >&2
    exit 1
fi
[[ -z $(find "$temporary/rejected" -mindepth 1 -print -quit) ]]

raced_source=$temporary/raced.efi
raced_destination=$temporary/raced-snapshot
truncate -s 64M "$raced_source"
mkdir -m 0700 "$raced_destination"
: >"$temporary/mutate"
printf '\000' >"$temporary/byte-0"
printf '\001' >"$temporary/byte-1"
(
    value=0
    while [[ -e $temporary/mutate ]]; do
        dd if="$temporary/byte-$value" of="$raced_source" bs=1 count=1 conv=notrunc status=none
        sync -d "$raced_source"
        value=$((value ^ 1))
    done
) &
mutator_pid=$!
sleep 0.02
set +e
"$helper" "$raced_source" "$raced_destination" 0.efi
status=$?
set -e
rm -f -- "$temporary/mutate"
wait "$mutator_pid" 2>/dev/null || true
mutator_pid=
((status != 0))
[[ -z $(find "$raced_destination" -mindepth 1 -print -quit) ]]

echo 'stable UKI policy-input snapshot tests passed'
