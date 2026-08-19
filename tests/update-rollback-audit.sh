#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -Eeuo pipefail

trap 'printf "UPDATE_ROLLBACK_AUDIT_FAIL line=%s status=%s command=%q\n" "$LINENO" "$?" "$BASH_COMMAND" >&2' ERR

read -r scenario <"$CREDENTIALS_DIRECTORY/update-audit-scenario"
read -r base_version <"$CREDENTIALS_DIRECTORY/update-audit-base-version"
read -r candidate_version <"$CREDENTIALS_DIRECTORY/update-audit-candidate-version"
# shellcheck source=/dev/null
source /usr/lib/os-release

[[ $scenario == rollback-denial || $scenario == health-fallback ]]
[[ $base_version =~ ^[0-9]+([.][0-9]+)*$ ]]
[[ $candidate_version =~ ^[0-9]+([.][0-9]+)*$ ]]
[[ ${IMAGE_VERSION:-} =~ ^[0-9]+([.][0-9]+)*$ ]]
[[ $candidate_version != "$base_version" ]]

state_directory=/var/lib/particleos/update-rollback-audit
stage_file="$state_directory/stage"
base_entry_file="$state_directory/base-entry"
boot_root=$(realpath -e -- "$(bootctl --print-boot-path)")
uki_directory="$boot_root/EFI/Linux"
component=/var/lib/pcrlock.d/650-particleos-uki.pcrlock.d
policy=/var/lib/systemd/pcrlock.json
ready=/var/lib/particleos/pcrlock-update-ready
project_certificate=/usr/lib/verity.d/_projectcert.crt

[[ -d $uki_directory && ! -L $uki_directory ]]
[[ -d $component && ! -L $component ]]
[[ -f $policy && ! -L $policy ]]

mapfile -t component_files < <(
    find "$component" -mindepth 1 -maxdepth 1 -type f -name '*.pcrlock' -print | sort
)
mapfile -t installed_ukis < <(
    find "$uki_directory" -mindepth 1 -maxdepth 1 -type f \
        -name 'ParticleOS-Host_*.efi' -print | sort
)

for uki in "${installed_ukis[@]}"; do
    sbverify --cert "$project_certificate" "$uki" >/dev/null
done

check_policy_pcrs() {
    grep -Eq '"pcr"[[:space:]]*:[[:space:]]*7([,}])' "$policy"
    grep -Eq '"pcr"[[:space:]]*:[[:space:]]*11([,}])' "$policy"
}

check_ready_marker() {
    local actual_hash extra label recorded_hash
    read -r label recorded_hash extra <"$ready"
    [[ $label == pcrlock-policy-sha256 && -z ${extra:-} ]]
    actual_hash=$(sha256sum -- "$policy")
    actual_hash=${actual_hash%% *}
    [[ $recorded_hash == "$actual_hash" ]]
}

write_state() {
    local path=$1 value=$2
    umask 077
    printf '%s\n' "$value" >"$path"
}

stage=initial
if [[ -f $stage_file ]]; then
    read -r stage <"$stage_file"
fi

case $stage in
initial)
    [[ $IMAGE_VERSION == "$base_version" ]]
    [[ ${#component_files[@]} -eq 1 ]]
    [[ ${#installed_ukis[@]} -eq 1 ]]
    [[ ! -e $ready ]]
    check_policy_pcrs

    current_stub=$(realpath -e -- "$(bootctl --print-stub-path)")
    base_entry=${current_stub##*/}
    [[ $base_entry == "ParticleOS-Host_${base_version}_x86-64.efi" ]]

    install -d -m 0700 "$state_directory"
    write_state "$base_entry_file" "$base_entry"
    available_version=$(systemd-sysupdate check-new)
    [[ $available_version == "$candidate_version" ]]
    echo "UPDATE_ROLLBACK_AUDIT_AVAILABLE version=$available_version"
    systemctl start --wait systemd-sysupdate-update.service
    journalctl --no-pager --output=short-monotonic \
        -u systemd-sysupdate-update.service >&2 || true

    mapfile -t component_files < <(
        find "$component" -mindepth 1 -maxdepth 1 -type f -name '*.pcrlock' -print | sort
    )
    mapfile -t installed_ukis < <(
        find "$uki_directory" -mindepth 1 -maxdepth 1 -type f \
            -name 'ParticleOS-Host_*.efi' -print | sort
    )
    [[ ${#component_files[@]} -eq 2 ]]
    [[ ${#installed_ukis[@]} -eq 2 ]]
    find "$uki_directory" -maxdepth 1 -type f \
        -name "ParticleOS-Host_${candidate_version}_x86-64*.efi" -print -quit |
        grep -q .
    check_policy_pcrs
    check_ready_marker
    write_state "$stage_file" staged
    sync
    echo "UPDATE_ROLLBACK_AUDIT_STAGED base=$base_version candidate=$candidate_version variants=${#component_files[@]}"
    systemctl start systemd-sysupdate-reboot.service || true
    sleep 30
    echo 'UPDATE_ROLLBACK_AUDIT_REBOOT_FAILED'
    exit 1
    ;;
staged)
    if [[ $IMAGE_VERSION == "$base_version" ]]; then
        [[ $scenario == health-fallback ]]
        [[ ${#component_files[@]} -eq 1 ]]
        [[ ${#installed_ukis[@]} -eq 2 ]]
        [[ ! -e $ready ]]
        check_policy_pcrs
        echo "UPDATE_ROLLBACK_AUDIT_FALLBACK_PASS base=$base_version candidate=$candidate_version variants=${#component_files[@]}"
        exit 0
    fi

    [[ $scenario == rollback-denial ]]
    [[ $IMAGE_VERSION == "$candidate_version" ]]
    [[ ${#component_files[@]} -eq 1 ]]
    [[ ${#installed_ukis[@]} -eq 2 ]]
    [[ ! -e $ready ]]
    check_policy_pcrs
    read -r base_entry <"$base_entry_file"
    [[ $base_entry == "ParticleOS-Host_${base_version}_x86-64.efi" ]]
    bootctl set-oneshot "$base_entry"
    write_state "$stage_file" rollback-attempt
    sync
    echo "UPDATE_ROLLBACK_AUDIT_CANDIDATE_BLESSED base=$base_version candidate=$candidate_version variants=${#component_files[@]}"
    ;;
rollback-attempt)
    echo "UPDATE_ROLLBACK_AUDIT_BYPASS version=$IMAGE_VERSION"
    exit 1
    ;;
*)
    echo "invalid update audit stage: $stage" >&2
    exit 1
    ;;
esac
