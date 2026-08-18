#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

[[ $# -eq 1 ]] || { echo "usage: $0 ARTIFACT_DIRECTORY" >&2; exit 2; }
repository="$(cd "$(dirname "$0")/.." && pwd)"
directory="$(realpath "$1")"

one_artifact() {
    local pattern=$1
    mapfile -t matches < <(find "$directory" -maxdepth 1 -type f -name "$pattern")
    [[ ${#matches[@]} -eq 1 ]] || {
        echo "expected one $pattern artifact, found ${#matches[@]}" >&2
        return 1
    }
    printf '%s' "${matches[0]}"
}

disk="$(one_artifact 'ParticleOS-Host_*_x86-64.raw.zst')"
uki="$(one_artifact 'ParticleOS-Host_*.efi')"
manifest="$(one_artifact 'ParticleOS-Host_*.manifest.gz')"
os_release="$(one_artifact 'ParticleOS-Host_*.osrelease')"
repart_archive="$(one_artifact 'ParticleOS-Host_*.repart.tar')"
checksum_manifest="$(one_artifact 'ParticleOS-Host_*.SHA256SUMS')"

(
    cd "$directory"
    sha256sum -c "${checksum_manifest##*/}"
)
mapfile -t checksummed_names < <(
    sed -E 's/^[[:xdigit:]]{64} [ *]//' "$checksum_manifest" | sort
)
mapfile -t published_names < <(
    find "$directory" -maxdepth 1 -type f \
        -name 'ParticleOS-Host_*' \
        ! -name '*.SHA256SUMS' ! -name '*.sha256' ! -name '*.asc' \
        -printf '%f\n' | sort
)
[[ ${#checksummed_names[@]} -eq ${#published_names[@]} ]]
[[ $(printf '%s\n' "${checksummed_names[@]}") == $(printf '%s\n' "${published_names[@]}") ]]

sbverify --list "$uki" | grep -q 'signature certificates'
uki_details="$(ukify inspect "$uki")"
for setting in \
    'audit=1' \
    'enforcing=1' \
    'ipe.enforce=1' \
    'module.sig_enforce=1' \
    'lockdown=confidentiality' \
    'systemd.verity_usr_options=root-hash-signature=auto'; do
    grep -qF "$setting" <<<"$uki_details"
done
if grep -qE '^\.pcr(sig|pkey):' <<<"$uki_details"; then
    echo 'UKI unexpectedly contains a TPM-incompatible public-key PCR policy' >&2
    exit 1
fi
gzip -t "$manifest"
zgrep -q '"name": "runsc"' "$manifest"
zgrep -q '"name": "podman"' "$manifest"

image_id="$(sed -n 's/^IMAGE_ID=//p' "$os_release" | tr -d '"')"
image_version="$(sed -n 's/^IMAGE_VERSION=//p' "$os_release" | tr -d '"')"
[[ "$image_id" == ParticleOS-Host && "$image_version" =~ ^[0-9]+\.[0-9]+$ ]]

scratch="$(mktemp -d /tmp/particleos-artifacts.XXXXXX)"
trap 'rm -rf -- "${scratch:?}"' EXIT
tar -xf "$repart_archive" -C "$scratch"
mapfile -t build_definitions < <(find "$scratch" -maxdepth 1 -type f -name '*.conf')
[[ ${#build_definitions[@]} -eq 4 ]]
grep -RqxF 'Type=usr-verity-sig' "$scratch"
grep -RqxF "Label=${image_id}_${image_version}_vsig" "$scratch"

# The distributable image contains the signed active slot. systemd-repart adds
# the empty alternate slot and encrypted state partition on first boot. Read
# only the primary GPT header, avoiding a multi-gigabyte decompression.
zstd -q -t "$disk"
set +o pipefail
zstd -dc "$disk" | dd of="$scratch/gpt-prefix.raw" bs=128K count=1 iflag=fullblock status=none
dd_status=${PIPESTATUS[1]}
set -o pipefail
[[ $dd_status -eq 0 ]]
python3 - "$scratch/gpt-prefix.raw" "$image_id" "$image_version" <<'PY'
import struct
import sys
import uuid

data = open(sys.argv[1], 'rb').read()
image_id, version = sys.argv[2:]
header = struct.unpack_from('<8sIIIIQQQQ16sQIII', data, 512)
assert header[0] == b'EFI PART'
entries_lba, count, entry_size = header[10:13]
entries = []
for index in range(count):
    offset = entries_lba * 512 + index * entry_size
    entry = data[offset:offset + entry_size]
    if not any(entry[:16]):
        continue
    type_id = str(uuid.UUID(bytes_le=entry[:16]))
    attributes = struct.unpack_from('<Q', entry, 48)[0]
    label = entry[56:128].decode('utf-16le').rstrip('\x00')
    entries.append((type_id, attributes, label))

expected = {
    ('c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'esp'),
    ('e7bb33fb-06cf-4e81-8273-e543b413e2e2', f'{image_id}_{version}_vsig'),
    ('77ff5f63-e7b6-4633-acf4-1565b864c0e6', f'{image_id}_{version}_verity'),
    ('8484680c-9521-48c6-9c11-b0720656f69e', f'{image_id}_{version}'),
}
assert {(type_id, label) for type_id, _, label in entries} == expected, entries
assert all(attributes & (1 << 60) for _, attributes, label in entries if label != 'esp')
PY

runtime="$repository/mkosi.extra/usr/lib/repart.d"
for type in usr usr-verity usr-verity-sig; do
    [[ "$(grep -rl "^Type=${type}$" "$runtime" | wc -l)" -eq 2 ]]
done
grep -qxF 'Type=root' "$runtime/40-root.conf"
grep -qxF 'Encrypt=tpm2' "$runtime/40-root.conf"
grep -qxF 'TPM2PCRs=7' "$runtime/40-root.conf"

echo 'Checksums, signed UKI, manifest, versioned verity label, base GPT, and runtime A/B layout passed.'
