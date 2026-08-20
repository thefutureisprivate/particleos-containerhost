#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY OUTPUT_VARS [OVMF_VARS_TEMPLATE]" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
artifact_directory=$(realpath "$1")
output=$2
template=${3:-/usr/share/qemu/ovmf-x86_64-smm-vars.bin}
owner=5f6584aa-b7f5-4f73-a11f-174abedd65be
expected_certificate_fingerprint=F18D066F4D25D63875BB0C370061D75A2AED67E81D33AF11669D79860BB9D2B7

case $output in
    /*) ;;
    *) output=$PWD/$output ;;
esac
template=$(realpath "$template")
output_directory=${output%/*}
[[ -d $output_directory && -w $output_directory ]] || {
    echo "output directory is not writable: $output_directory" >&2
    exit 1
}
[[ ! -e $output ]] || {
    echo "refusing to overwrite existing variable store: $output" >&2
    exit 1
}
[[ -f $template ]] || { echo "missing OVMF variable-store template: $template" >&2; exit 1; }
for command in find lsinitrd objcopy openssl realpath virt-fw-vars; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done

# This authenticates the release manifest with the repository-pinned OBS key,
# checks every published digest, verifies the UKI signature with the pinned OBS
# certificate, and validates the embedded certificate before it becomes a UEFI
# trust anchor.
"$repository/scripts/validate-artifacts.sh" "$artifact_directory"
mapfile -t ukis < <(
    find "$artifact_directory" -maxdepth 1 -type f \
        -name 'ParticleOS-Host_*.efi' -print
)
[[ ${#ukis[@]} -eq 1 ]] || {
    echo "expected one authenticated UKI, found ${#ukis[@]}" >&2
    exit 1
}

scratch=$(mktemp -d "$output_directory/.particleos-ovmf-vars.XXXXXXXX")
cleanup() {
    local status=$?
    if [[ -d ${scratch:-} && ${scratch##*/} == .particleos-ovmf-vars.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

objcopy --dump-section ".initrd=$scratch/initrd" "${ukis[0]}" "$scratch/uki.copy"
lsinitrd --file usr/lib/verity.d/_projectcert.crt "$scratch/initrd" \
    >"$scratch/project-cert.crt"
actual_certificate_fingerprint=$(openssl x509 -in "$scratch/project-cert.crt" \
    -noout -fingerprint -sha256 | sed 's/^.*=//; s/://g')
[[ $actual_certificate_fingerprint == "$expected_certificate_fingerprint" ]]

# Explicit PK/KEK/db enrollment avoids the convenience profile's additional
# vendor keys. This disposable store trusts only the authenticated project
# certificate and starts with Secure Boot enabled.
virt-fw-vars -i "$template" \
    --set-pk "$owner" "$scratch/project-cert.crt" \
    --add-kek "$owner" "$scratch/project-cert.crt" \
    --add-db "$owner" "$scratch/project-cert.crt" \
    --secure-boot -o "$scratch/ovmf-vars.bin"
summary=$(virt-fw-vars -i "$scratch/ovmf-vars.bin" -p)
grep -Eq '^SecureBootEnable[[:space:]]+: bool: ON$' <<<"$summary"
for database in PK KEK db; do
    grep -Eq "^${database}[[:space:]]+: blob: [1-9][0-9]* bytes$" <<<"$summary"
done

mv -- "$scratch/ovmf-vars.bin" "$output"
chmod 0600 "$output"
printf 'Created authenticated project-only OVMF variable store: %s\n' "$output"
printf 'Enrolled certificate SHA-256: %s\n' "$actual_certificate_fingerprint"
