#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "usage: $0 OUTPUT_DISK_IMAGE" >&2
    exit 2
fi

output=$1
source_image=${VM_AUDIT_CONTAINER_SOURCE:-docker://docker.io/library/busybox@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23}
signed_identity=localhost/particleos-audit:1
fixture_mount=/run/particleos-container-fixture

case $output in
    /*) ;;
    *) output=$PWD/$output ;;
esac
output_directory=${output%/*}
[[ -d $output_directory && -w $output_directory ]] || {
    echo "output directory is not writable: $output_directory" >&2
    exit 1
}
[[ ! -e $output ]] || {
    echo "refusing to overwrite existing fixture: $output" >&2
    exit 1
}

for command in gpg mcopy mktemp mv skopeo truncate; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
if command -v mkfs.vfat >/dev/null; then
    mkfs_vfat=mkfs.vfat
elif command -v mkfs.fat >/dev/null; then
    mkfs_vfat=mkfs.fat
elif [[ -x /usr/sbin/mkfs.fat ]]; then
    mkfs_vfat=/usr/sbin/mkfs.fat
else
    echo 'missing required command: mkfs.vfat or mkfs.fat' >&2
    exit 1
fi

scratch=$(mktemp -d "$output_directory/.particleos-container-fixture.XXXXXXXX")
cleanup() {
    local status=$?
    if [[ -d ${scratch:-} &&
            ${scratch##*/} == .particleos-container-fixture.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

payload=$scratch/payload
gnupg=$scratch/gnupg
install -d -m 0700 "$gnupg"
install -d -m 0755 "$payload/image"
export GNUPGHOME=$gnupg

good_uid='ParticleOS VM Audit <audit@particleos.invalid>'
wrong_uid='ParticleOS VM Audit Wrong Key <wrong@particleos.invalid>'
gpg --batch --passphrase '' --quick-generate-key "$good_uid" ed25519 sign 0 >/dev/null
gpg --batch --passphrase '' --quick-generate-key "$wrong_uid" ed25519 sign 0 >/dev/null
good_fingerprint=$(gpg --batch --with-colons --list-secret-keys "$good_uid" |
    awk -F: '$1 == "fpr" { print $10; exit }')
wrong_fingerprint=$(gpg --batch --with-colons --list-secret-keys "$wrong_uid" |
    awk -F: '$1 == "fpr" { print $10; exit }')
[[ $good_fingerprint =~ ^[0-9A-F]{40}$ &&
   $wrong_fingerprint =~ ^[0-9A-F]{40}$ ]]
gpg --batch --export "$good_fingerprint" >"$payload/audit-key.gpg"
gpg --batch --export "$wrong_fingerprint" >"$payload/wrong-key.gpg"

skopeo copy \
    --override-os linux \
    --override-arch amd64 \
    --sign-by "$good_fingerprint" \
    --sign-identity "$signed_identity" \
    "$source_image" "dir:$payload/image"
[[ -s $payload/image/manifest.json && -s $payload/image/signature-1 ]]

write_policy() {
    local destination=$1 key_name=$2
    printf '%s\n' \
        '{' \
        '  "default": [{"type": "reject"}],' \
        '  "transports": {' \
        '    "dir": {' \
        "      \"$fixture_mount/image\": [{" \
        '        "type": "signedBy",' \
        '        "keyType": "GPGKeys",' \
        "        \"keyPath\": \"$fixture_mount/$key_name\"," \
        '        "signedIdentity": {' \
        '          "type": "exactReference",' \
        "          \"dockerReference\": \"$signed_identity\"" \
        '        }' \
        '      }]' \
        '    }' \
        '  }' \
        '}' >"$destination"
}
write_policy "$payload/policy-good.json" audit-key.gpg
write_policy "$payload/policy-wrong.json" wrong-key.gpg

host_policy=$scratch/policy-host.json
sed \
    -e "s@$fixture_mount/image@$payload/image@g" \
    -e "s@$fixture_mount/audit-key.gpg@$payload/audit-key.gpg@g" \
    "$payload/policy-good.json" >"$host_policy"
install -d -m 0755 "$scratch/verified-good" "$scratch/verified-wrong"
skopeo --policy "$host_policy" copy \
    "dir:$payload/image" "dir:$scratch/verified-good" >/dev/null
sed \
    -e "s@$fixture_mount/image@$payload/image@g" \
    -e "s@$fixture_mount/wrong-key.gpg@$payload/wrong-key.gpg@g" \
    "$payload/policy-wrong.json" >"$host_policy"
wrong_policy_log=$scratch/wrong-policy.log
if skopeo --policy "$host_policy" copy \
        "dir:$payload/image" "dir:$scratch/verified-wrong" \
        >"$wrong_policy_log" 2>&1; then
    echo 'signed fixture unexpectedly passed verification with the wrong key' >&2
    exit 1
elif ! grep -Eqi 'signature|public key|verification|not accepted|rejected' \
        "$wrong_policy_log"; then
    sed -n '1,80p' "$wrong_policy_log" >&2
    echo 'wrong-key fixture verification failed for an unexpected reason' >&2
    exit 1
fi

fixture=$scratch/particleos-container-fixture.raw
truncate -s 32M "$fixture"
"$mkfs_vfat" -n PTESTOCI "$fixture" >/dev/null
mcopy -i "$fixture" -s "$payload"/* ::/
mv -- "$fixture" "$output"
chmod 0644 "$output"

printf 'Created signed container fixture: %s\n' "$output"
printf 'Signed identity: %s\n' "$signed_identity"
printf 'Signing key fingerprint: %s\n' "$good_fingerprint"
