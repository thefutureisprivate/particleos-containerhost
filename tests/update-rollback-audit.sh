#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -Eeuo pipefail

trap 'printf "UPDATE_ROLLBACK_AUDIT_FAIL line=%s status=%s command=%q\n" "$LINENO" "$?" "$BASH_COMMAND" >&2' ERR

read -r scenario <"$CREDENTIALS_DIRECTORY/update-audit-scenario"
read -r base_version <"$CREDENTIALS_DIRECTORY/update-audit-base-version"
read -r candidate_version <"$CREDENTIALS_DIRECTORY/update-audit-candidate-version"
# shellcheck source=/dev/null
source /usr/lib/os-release

[[ $scenario == rollback-denial || $scenario == workload-quarantine ||
   $scenario == host-fallback ]]
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
credential_directory="$boot_root/loader/credentials"

[[ -d $uki_directory && ! -L $uki_directory ]]
[[ -d $component && ! -L $component ]]
[[ -f $policy && ! -L $policy ]]
[[ -d $credential_directory && ! -L $credential_directory ]]

mapfile -t pcrlock_credentials < <(
    find "$credential_directory" -mindepth 1 -maxdepth 1 -type f \
        -name 'pcrlock.*.cred' -printf '%f\n'
)
[[ ${#pcrlock_credentials[@]} -eq 1 &&
   ${pcrlock_credentials[0]} == "pcrlock.${IMAGE_ID}.cred" ]]

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
    local actual_hash extra policy_label recorded_hash version_label recorded_version
    local uki_label recorded_uki_hash
    read -r policy_label recorded_hash version_label recorded_version \
        uki_label recorded_uki_hash extra <"$ready"
    [[ $policy_label == pcrlock-policy-sha256 &&
       $version_label == candidate-version &&
       $recorded_version == "$candidate_version" &&
       $uki_label == candidate-uki-sha256 &&
       $recorded_uki_hash =~ ^[0-9a-f]{64}$ &&
       -z ${extra:-} ]]
    actual_hash=$(sha256sum -- "$policy")
    actual_hash=${actual_hash%% *}
    [[ $recorded_hash == "$actual_hash" ]]
    /usr/lib/particleos/pcrlock-update-ready
}

dump_blessing_state() {
    local unit
    echo 'UPDATE_ROLLBACK_AUDIT_BLESSING_DIAGNOSTIC_BEGIN' >&2
    printf '%s\n' '--- PCR-lock variants ---' >&2
    find "$component" -mindepth 1 -maxdepth 1 -printf '%f %y\n' | sort >&2 || true
    printf '%s\n' '--- readiness marker ---' >&2
    if [[ -e $ready ]]; then
        stat --format='%n mode=%a type=%F' "$ready" >&2 || true
        sed -n '1p' "$ready" >&2 || true
    else
        echo 'absent' >&2
    fi
    for unit in systemd-bless-boot.service particleos-pcrlock-prune.service \
            boot-complete.target; do
        printf '%s\n' "--- $unit ---" >&2
        systemctl show "$unit" \
            -p ActiveState -p SubState -p Result -p ConditionResult \
            -p AssertResult -p Job -p Requires -p Wants -p After >&2 || true
    done
    journalctl --no-pager --output=short-monotonic \
        -u systemd-bless-boot.service \
        -u particleos-pcrlock-prune.service >&2 || true
    echo 'UPDATE_ROLLBACK_AUDIT_BLESSING_DIAGNOSTIC_END' >&2
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
    candidate_json=$(systemd-sysupdate --json=short check-new)
    [[ $candidate_json == "{\"available\":\"${candidate_version}\"}" ]]
    echo "UPDATE_ROLLBACK_AUDIT_JSON version=$candidate_version"
    if [[ $scenario == workload-quarantine ]]; then
        systemctl enable particleos-workload-health.service
        systemctl is-enabled --quiet particleos-workload-health.service
    fi

    # Reproduce the former ESP-enumeration bypass: an offline attacker can
    # rename an older project-signed UKI to the fresh candidate's filename.
    # Embedded release matching must reject it before the PCR policy changes.
    replayed_candidate="$uki_directory/ParticleOS-Host_${candidate_version}_x86-64.efi"
    cp -- "$current_stub" "$replayed_candidate"
    if /usr/lib/particleos/pcrlock-refresh candidate "$candidate_version"; then
        echo 'UPDATE_ROLLBACK_AUDIT_OLD_UKI_BYPASS'
        exit 1
    fi
    rm -f -- "$replayed_candidate"
    [[ ! -e $ready ]]
    mapfile -t component_files < <(
        find "$component" -mindepth 1 -maxdepth 1 -type f -name '*.pcrlock' -print | sort
    )
    [[ ${#component_files[@]} -eq 1 ]]
    echo "UPDATE_ROLLBACK_AUDIT_OLD_UKI_REJECT version=$candidate_version"

    if ! systemctl start --wait systemd-sysupdate.service; then
        systemctl status --no-pager --full systemd-sysupdate.service >&2 || true
        journalctl --no-pager --output=short-monotonic \
            -u systemd-sysupdate.service >&2 || true
        exit 1
    fi
    journalctl --no-pager --output=short-monotonic \
        -u systemd-sysupdate.service >&2 || true

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
    systemctl --no-block start systemd-sysupdate-reboot.service
    exit 0
    ;;
staged)
    if [[ $IMAGE_VERSION == "$base_version" ]]; then
        [[ $scenario == host-fallback ]]
        if [[ ${#component_files[@]} -eq 2 && -e $ready ]]; then
            echo "UPDATE_ROLLBACK_AUDIT_FALLBACK_PRUNE_PENDING base=$base_version candidate=$candidate_version"
            exit 0
        fi
        [[ ${#component_files[@]} -eq 1 ]]
        [[ ${#installed_ukis[@]} -eq 2 ]]
        [[ ! -e $ready ]]
        [[ ! -e /var/lib/particleos/pcrlock-candidate-attempts ]]
        check_policy_pcrs
        [[ $(systemctl show -p ConditionResult --value \
            particleos-pcrlock-fallback-prune.service) == yes ]]
        [[ $(systemctl show -p Result --value \
            particleos-pcrlock-fallback-prune.service) == success ]]
        fallback_journal=$(journalctl --no-pager --output=cat -b \
            -u particleos-pcrlock-fallback-prune.service)
        grep -Fq "PARTICLEOS_PCRLOCK_FALLBACK_PRUNED base=$base_version candidate=$candidate_version authenticated_attempts=3" \
            <<<"$fallback_journal"
        echo "UPDATE_ROLLBACK_AUDIT_FALLBACK_PRUNE_CONFIRMED base=$base_version candidate=$candidate_version"
        echo "UPDATE_ROLLBACK_AUDIT_FALLBACK_PASS base=$base_version candidate=$candidate_version variants=${#component_files[@]} authenticated_attempts=3"
        systemctl --no-block poweroff
        exit 0
    fi

    [[ $IMAGE_VERSION == "$candidate_version" ]]
    [[ ${#installed_ukis[@]} -eq 2 ]]
    check_policy_pcrs

    if [[ $scenario == workload-quarantine && ${#component_files[@]} -eq 2 && -e $ready ]]; then
        echo "UPDATE_ROLLBACK_AUDIT_HEALTH_PENDING version=$candidate_version"
        exit 0
    fi

    if [[ ${#component_files[@]} -eq 2 && -e $ready ]]; then
        echo "UPDATE_ROLLBACK_AUDIT_BLESSING_PENDING version=$candidate_version"
        exit 0
    fi
    if [[ ${#component_files[@]} -ne 1 || -e $ready ]]; then
        dump_blessing_state
    fi
    [[ ${#component_files[@]} -eq 1 ]]
    [[ ! -e $ready ]]
    if [[ $scenario == workload-quarantine ]]; then
        workload_journal=$(journalctl --no-pager --output=cat -b \
            -u particleos-workload-health.service)
        grep -Fq "PARTICLEOS_WORKLOAD_QUARANTINED version=$candidate_version attempts=3" \
            <<<"$workload_journal"
    else
        [[ $scenario == rollback-denial ]]
    fi
    read -r base_entry <"$base_entry_file"
    [[ $base_entry == "ParticleOS-Host_${base_version}_x86-64.efi" ]]
    bootctl set-oneshot "$base_entry"
    write_state "$stage_file" rollback-attempt
    sync
    echo "UPDATE_ROLLBACK_AUDIT_CANDIDATE_BLESSED base=$base_version candidate=$candidate_version variants=${#component_files[@]}"
    systemctl --no-block poweroff
    exit 0
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
