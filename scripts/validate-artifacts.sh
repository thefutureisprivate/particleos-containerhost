#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

[[ $# -eq 1 || $# -eq 2 ]] || {
    echo "usage: $0 ARTIFACT_DIRECTORY [AUTHENTICATED_SNAPSHOT]" >&2
    exit 2
}
repository="$(cd "$(dirname "$0")/.." && pwd)"
source_directory=$1
snapshot_destination=${2:-}
scratch="$(mktemp -d /tmp/particleos-artifacts.XXXXXX)"
trap 'rm -rf -- "${scratch:?}"' EXIT
directory=$scratch/release
/usr/bin/python3 "$repository/scripts/snapshot-artifacts.py" "$source_directory" "$directory"

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
one_artifact 'ParticleOS-Host_*_x86-64.esp.raw.zst' >/dev/null
one_artifact 'ParticleOS-Host_*.manifest.gz' >/dev/null
os_release="$(one_artifact 'ParticleOS-Host_*.osrelease')"
repart_archive="$(one_artifact 'ParticleOS-Host_*.repart.tar')"
checksum_manifest="$(one_artifact 'ParticleOS-Host_*.SHA256SUMS')"
checksum_digest="$(one_artifact 'ParticleOS-Host_*.SHA256SUMS.sha256')"
checksum_signature="$(one_artifact 'ParticleOS-Host_*.SHA256SUMS.sha256.asc')"

trusted_key="$repository/mkosi.resources/particleos-obs-pubkey.gpg"
expected_key_fingerprint=0B2264A151F114677B1D0AAF25688B9E8208EED3
mapfile -t primary_fingerprints < <(
    gpg --batch --show-keys --with-colons "$trusted_key" |
        awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
)
[[ ${#primary_fingerprints[@]} -eq 1 &&
   ${primary_fingerprints[0]} == "$expected_key_fingerprint" ]]
install -d -m 0700 "$scratch/gnupg"
GNUPGHOME=$scratch/gnupg gpg --batch --yes --dearmor \
    --output "$scratch/trusted-keyring.gpg" "$trusted_key"
signature_status=$(GNUPGHOME=$scratch/gnupg gpgv --homedir "$scratch/gnupg" \
    --keyring "$scratch/trusted-keyring.gpg" --status-fd=1 \
    "$checksum_signature" "$checksum_digest" 2>"$scratch/gpgv.log")
mapfile -t valid_signatures < <(
    awk '$1 == "[GNUPG:]" && $2 == "VALIDSIG" { print $3 " " $NF }' \
        <<<"$signature_status"
)
[[ ${#valid_signatures[@]} -eq 1 ]]
read -r signing_fingerprint primary_fingerprint <<<"${valid_signatures[0]}"
[[ $signing_fingerprint =~ ^[0-9A-F]{40}$ &&
   $primary_fingerprint == "$expected_key_fingerprint" ]]

checksum_basename=${checksum_manifest##*/}
[[ $(wc -l <"$checksum_digest") -eq 1 ]]
read -r signed_manifest_digest signed_manifest_name extra <"$checksum_digest"
[[ $signed_manifest_digest =~ ^[0-9a-f]{64}$ &&
   $signed_manifest_name == "$checksum_basename" &&
   -z ${extra:-} ]]
actual_manifest_digest=$(sha256sum -- "$checksum_manifest")
actual_manifest_digest=${actual_manifest_digest%% *}
[[ $actual_manifest_digest == "$signed_manifest_digest" ]]
mapfile -t checksummed_names < <(
    /usr/bin/python3 - "$checksum_manifest" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
names = []
for line_number, line in enumerate(path.read_text().splitlines(), 1):
    match = re.fullmatch(r"[0-9a-f]{64}  (ParticleOS-Host_[A-Za-z0-9_.-]+)", line)
    if match is None:
        raise SystemExit(f"unsafe checksum line {line_number}")
    name = match.group(1)
    if "/" in name or name in names:
        raise SystemExit(f"unsafe checksum member {name!r}")
    names.append(name)
for name in sorted(names):
    print(name)
PY
)
(
    cd "$directory"
    sha256sum -c "$checksum_basename"
)
mapfile -t published_names < <(
    find "$directory" -maxdepth 1 -type f \
        -name 'ParticleOS-Host_*' \
        ! -name '*.SHA256SUMS' ! -name '*.sha256' ! -name '*.asc' \
        -printf '%f\n' | sort
)
[[ ${#checksummed_names[@]} -eq ${#published_names[@]} ]]
[[ $(printf '%s\n' "${checksummed_names[@]}") == $(printf '%s\n' "${published_names[@]}") ]]

uki_details="$(ukify inspect "$uki")"
for setting in \
    'audit=1' \
    'enforcing=1' \
    'ipe.enforce=1' \
    'module.sig_enforce=1' \
    'lockdown=confidentiality' \
    'systemd.credentials_boot_policy=strict' \
    'systemd.verity_usr_options=root-hash-signature=auto'; do
    grep -qF "$setting" <<<"$uki_details"
done
if grep -qE '^\.pcr(sig|pkey):' <<<"$uki_details"; then
    echo 'UKI unexpectedly contains a TPM-incompatible public-key PCR policy' >&2
    exit 1
fi
OUTPUTDIR="$directory" "$repository/mkosi.scripts/validate-systemd-manifest"
objcopy --dump-section ".initrd=$scratch/initrd" "$uki" "$scratch/uki.copy"
lsinitrd "$scratch/initrd" >"$scratch/initrd.list"
grep -qE ' etc/ipe/ipe-policy\.p7b$' "$scratch/initrd.list"
lsinitrd --file usr/lib/verity.d/_projectcert.crt "$scratch/initrd" \
    >"$scratch/project-cert.crt"
expected_certificate_fingerprint=F18D066F4D25D63875BB0C370061D75A2AED67E81D33AF11669D79860BB9D2B7
actual_certificate_fingerprint=$(openssl x509 -in "$scratch/project-cert.crt" \
    -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g')
[[ $actual_certificate_fingerprint == "$expected_certificate_fingerprint" ]]
sbverify --cert "$scratch/project-cert.crt" "$uki"

# Authenticate the actual initial-installation boot path, not just the
# separately published UKI. The full disk's ESP copy must be byte-identical and
# independently pass PE signature verification.
compressed_size=$(stat -c %s -- "$disk")
expanded_size=$(zstd --list --verbose -- "$disk" 2>/dev/null |
    sed -n -E 's/^Decompressed Size:.*\(([0-9]+) B\)$/\1/p')
[[ $compressed_size -le $((8 * 1024 * 1024 * 1024)) &&
   $expanded_size =~ ^[0-9]+$ &&
   $expanded_size -le $((16 * 1024 * 1024 * 1024)) ]]
zstd --sparse -q -d -f -o "$scratch/disk.raw" "$disk"
esp_offset=$(systemd-repart --json=short "$scratch/disk.raw" |
    jq -r '.[] | select(.type == "esp") | .offset')
[[ $esp_offset =~ ^[0-9]+$ ]]
mcopy -i "$scratch/disk.raw@@$esp_offset" \
    "::EFI/Linux/${uki##*/}" "$scratch/embedded-uki.efi"
cmp -- "$uki" "$scratch/embedded-uki.efi"
sbverify --cert "$scratch/project-cert.crt" "$scratch/embedded-uki.efi"

image_id="$(sed -n 's/^IMAGE_ID=//p' "$os_release" | tr -d '"')"
image_version="$(sed -n 's/^IMAGE_VERSION=//p' "$os_release" | tr -d '"')"
[[ "$image_id" == ParticleOS-Host && "$image_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]

definitions="$scratch/repart"
"$repository/mkosi.scripts/repart-archive" "$repart_archive" "$definitions" \
    "${image_id}_${image_version}_vsig"
mapfile -t build_definitions < <(find "$definitions" -maxdepth 1 -type f -name '*.conf')
[[ ${#build_definitions[@]} -eq 4 ]]
grep -RqxF 'Type=usr-verity-sig' "$definitions"
grep -RqxF "Label=${image_id}_${image_version}_vsig" "$definitions"
grep -RqxF 'Label=ParticleESP' "$definitions"

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
    ('c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'ParticleESP'),
    ('e7bb33fb-06cf-4e81-8273-e543b413e2e2', f'{image_id}_{version}_vsig'),
    ('77ff5f63-e7b6-4633-acf4-1565b864c0e6', f'{image_id}_{version}_verity'),
    ('8484680c-9521-48c6-9c11-b0720656f69e', f'{image_id}_{version}'),
}
assert {(type_id, label) for type_id, _, label in entries} == expected, entries
assert all(attributes & (1 << 60) for _, attributes, label in entries if label != 'ParticleESP')
PY

runtime="$repository/mkosi.extra/usr/lib/repart.d"
for type in usr usr-verity usr-verity-sig; do
    [[ "$(grep -rl "^Type=${type}$" "$runtime" | wc -l)" -eq 2 ]]
done
grep -qxF 'Type=root' "$runtime/40-root.conf"
grep -qxF 'Encrypt=tpm2' "$runtime/40-root.conf"
grep -qxF 'TPM2PCRs=7' "$runtime/40-root.conf"

if [[ -n $snapshot_destination ]]; then
    [[ ! -e $snapshot_destination ]]
    mv -- "$directory" "$snapshot_destination"
    directory=
    printf 'Authenticated snapshot: %s\n' "$snapshot_destination"
fi

echo 'Authenticated exact release snapshot, signer and checksums, standalone and disk-embedded UKIs, manifest, versioned verity label, base GPT, and runtime A/B layout passed.'
