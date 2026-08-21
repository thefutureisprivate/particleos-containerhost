#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

repository=$(cd "$(dirname "$0")/.." && pwd)
helper=$repository/mkosi.scripts/repart-archive
templates=$repository/mkosi.repart
temporary=$(mktemp -d /tmp/particleos-repart-test.XXXXXXXX)
trap 'rm -rf -- "$temporary"' EXIT
mapfile -t definitions < <(find "$templates" -maxdepth 1 -type f -name '*.conf' -printf '%f\n' | sort)
((${#definitions[@]} > 0))

invoke() {
    local case_name=$1 accepted=$2 source=$3 label=${4:-} status
    local target=$temporary/$case_name
    set +e
    if [[ -n $label ]]; then
        "$helper" "$source" "$target" "$label" >"$temporary/$case_name.out" 2>"$temporary/$case_name.err"
    else
        "$helper" "$source" "$target" >"$temporary/$case_name.out" 2>"$temporary/$case_name.err"
    fi
    status=$?
    set -e
    if [[ $accepted == yes ]]; then
        ((status == 0)) || { cat "$temporary/$case_name.err" >&2; return 1; }
    else
        ((status != 0))
    fi
}

good=$temporary/good.tar
tar -C "$templates" -cf "$good" -- "${definitions[@]}"
invoke good yes "$good"
ln -s "$good" "$temporary/source-symlink.tar"
invoke source-symlink no "$temporary/source-symlink.tar"

versioned_directory=$temporary/versioned-directory
mkdir "$versioned_directory"
cp "$templates"/*.conf "$versioned_directory/"
sed -i 's/Label=%M_%A_vsig/Label=ParticleOS-Host_44.85.0_vsig/g' "$versioned_directory"/*.conf
tar -C "$versioned_directory" -cf "$temporary/versioned.tar" -- "${definitions[@]}"
invoke versioned yes "$temporary/versioned.tar" ParticleOS-Host_44.85.0_vsig
invoke versioned-without-label no "$temporary/versioned.tar"
invoke unsafe-label no "$temporary/versioned.tar" ../unsafe

absolute_file=$temporary/absolute.conf
printf x >"$absolute_file"
tar --absolute-names -cf "$temporary/absolute.tar" -- "$absolute_file"
invoke absolute no "$temporary/absolute.tar"

single=$temporary/single
mkdir "$single"
printf x >"$single/40-root.conf"
tar -C "$single" --transform='s|^|../|' -cf "$temporary/traversal.tar" 40-root.conf
invoke traversal no "$temporary/traversal.tar"

mkdir -p "$temporary/nested/nested"
printf x >"$temporary/nested/nested/40-root.conf"
tar -C "$temporary/nested" -cf "$temporary/nested.tar" nested/40-root.conf
invoke nested no "$temporary/nested.tar"

printf x >"$single/40-root.txt"
tar -C "$single" -cf "$temporary/suffix.tar" 40-root.txt
invoke suffix no "$temporary/suffix.tar"

ln -s 40-root.txt "$single/symlink.conf"
tar -C "$single" -cf "$temporary/symlink.tar" symlink.conf
invoke symlink no "$temporary/symlink.tar"

mkfifo "$single/fifo.conf"
tar -C "$single" -cf "$temporary/fifo.tar" fifo.conf
invoke fifo no "$temporary/fifo.tar"

dd if=/dev/zero of="$single/oversize.conf" bs=65537 count=1 status=none
tar -C "$single" -cf "$temporary/oversize.tar" oversize.conf
invoke oversize no "$temporary/oversize.tar"

tar -C "$single" -cf "$temporary/duplicate.tar" 40-root.conf
tar -C "$single" -rf "$temporary/duplicate.tar" --transform='s|^|./|' 40-root.conf
invoke duplicate no "$temporary/duplicate.tar"

extra_directory=$temporary/extra-directory
mkdir "$extra_directory"
cp "$templates"/*.conf "$extra_directory/"
printf '[Partition]\nType=root\n' >"$extra_directory/99-extra.conf"
tar -C "$extra_directory" -cf "$temporary/extra-valid-definition.tar" -- "${definitions[@]}" 99-extra.conf
invoke extra-valid-definition no "$temporary/extra-valid-definition.tar"

changed_directory=$temporary/changed-directory
mkdir "$changed_directory"
cp "$templates"/*.conf "$changed_directory/"
sed -i 's|CopyFiles=/usr:/|CopyFiles=/etc:/|' "$changed_directory"/*.conf
tar -C "$changed_directory" -cf "$temporary/changed-directive.tar" -- "${definitions[@]}"
invoke changed-directive no "$temporary/changed-directive.tar"

missing=("${definitions[@]:0:${#definitions[@]}-1}")
tar -C "$templates" -cf "$temporary/missing-definition.tar" -- "${missing[@]}"
invoke missing-definition no "$temporary/missing-definition.tar"

echo 'hostile repart archive policy tests passed'
