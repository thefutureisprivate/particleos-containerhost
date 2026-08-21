#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
helper=$repository/.obs/ipe-policy-containerhost/extract-ipe-signature.py
temporary=$(mktemp -d /tmp/particleos-ipe-archive-test.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT
printf '%s' signature >"$temporary/signature.payload"
printf x >"$temporary/x.payload"
dd if=/dev/zero of="$temporary/oversize.payload" bs=8193 count=1 status=none

pad4() {
    local length=$1 padding
    padding=$(((4 - length % 4) % 4))
    ((padding == 0)) || dd if=/dev/zero bs=1 count="$padding" status=none
}

member() {
    local output=$1 name=$2 data=$3 mode=$4 nlink=$5
    local name_size=$((${#name} + 1)) data_size
    data_size=$(stat -c '%s' "$data")
    {
        printf '070701%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x' \
            1 "$mode" 0 0 "$nlink" 0 "$data_size" 0 0 0 0 "$name_size" 0
        printf '%s\0' "$name"
        pad4 "$((110 + name_size))"
        cat "$data"
        pad4 "$data_size"
    } >>"$output"
}

finish_archive() {
    local output=$1
    member "$output" TRAILER!!! /dev/null 0 1
    dd if=/dev/zero bs=512 count=1 status=none >>"$output"
}

invoke() {
    local case_name=$1 accepted=$2 source=$3 status
    local destination=$temporary/$case_name
    mkdir "$destination"
    set +e
    "$helper" "$source" "$destination" >"$temporary/$case_name.out" 2>"$temporary/$case_name.err"
    status=$?
    set -e
    if [[ $accepted == yes ]]; then
        ((status == 0)) || { cat "$temporary/$case_name.err" >&2; return 1; }
        cmp -- "$temporary/signature.payload" "$destination/ipe-policy.sig"
    else
        ((status != 0))
    fi
}

regular_mode=$((8#100644))
symlink_mode=$((8#120777))
device_mode=$((8#020600))

good=$temporary/good.cpio
member "$good" ./ipe-policy.sig "$temporary/signature.payload" "$regular_mode" 1
finish_archive "$good"
invoke good yes "$good"
ln -s "$good" "$temporary/source-symlink.cpio"
invoke source-symlink no "$temporary/source-symlink.cpio"

make_case() {
    local name=$1 member_name=$2 data=$3 mode=${4:-$regular_mode} nlink=${5:-1}
    local archive=$temporary/$name.cpio
    member "$archive" "$member_name" "$data" "$mode" "$nlink"
    finish_archive "$archive"
    invoke "$name" no "$archive"
}

make_case absolute /tmp/ipe-policy.sig "$temporary/signature.payload"
make_case traversal ../ipe-policy.sig "$temporary/signature.payload"
make_case unexpected other.sig "$temporary/signature.payload"
duplicate=$temporary/duplicate.cpio
member "$duplicate" ./ipe-policy.sig "$temporary/signature.payload" "$regular_mode" 1
member "$duplicate" ./ipe-policy.sig "$temporary/signature.payload" "$regular_mode" 1
finish_archive "$duplicate"
invoke duplicate no "$duplicate"
make_case symlink ipe-policy.sig "$temporary/x.payload" "$symlink_mode"
make_case device ipe-policy.sig "$temporary/x.payload" "$device_mode"
make_case hardlink ipe-policy.sig "$temporary/x.payload" "$regular_mode" 2
make_case oversize ipe-policy.sig "$temporary/oversize.payload"
no_trailer=$temporary/no-trailer.cpio
member "$no_trailer" ./ipe-policy.sig "$temporary/signature.payload" "$regular_mode" 1
invoke no-trailer no "$no_trailer"

echo 'hostile IPE signer-response archive policy tests passed'
