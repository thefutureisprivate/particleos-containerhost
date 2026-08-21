#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "usage: $0 BASE_ARTIFACT_DIRECTORY CANDIDATE_ARTIFACT_DIRECTORY ENROLLED_OVMF_VARS [OVMF_CODE]" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
base_artifacts=$(realpath "$1")
candidate_artifacts=$(realpath "$2")
ovmf_vars_source=$(realpath "$3")
ovmf_code=${4:-/usr/share/qemu/ovmf-x86_64-smm-code.bin}
ovmf_code=$(realpath "$ovmf_code")
audit_timeout=${VM_UPDATE_AUDIT_TIMEOUT:-900}
denial_timeout=${VM_UPDATE_DENIAL_TIMEOUT:-80}
audit_tmpdir=${VM_UPDATE_AUDIT_TMPDIR:-$base_artifacts}
keep_failed=${VM_UPDATE_AUDIT_KEEP_FAILED:-0}
requested_scenario=${VM_UPDATE_AUDIT_SCENARIO:-all}
vm_display=${VM_UPDATE_AUDIT_DISPLAY:-none}

for value in "$audit_timeout" "$denial_timeout"; do
    [[ $value =~ ^[1-9][0-9]*$ ]] || {
        echo 'VM update audit timeouts must be positive numbers of seconds' >&2
        exit 2
    }
done
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'VM_UPDATE_AUDIT_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
[[ $requested_scenario == all || $requested_scenario == rollback-denial ||
        $requested_scenario == workload-quarantine ||
        $requested_scenario == host-fallback ]] || {
    echo 'VM_UPDATE_AUDIT_SCENARIO must be all, rollback-denial, workload-quarantine, or host-fallback' >&2
    exit 2
}
[[ $vm_display == none || $vm_display == gtk ]] || {
    echo 'VM_UPDATE_AUDIT_DISPLAY must be none or gtk' >&2
    exit 2
}
[[ -r /dev/kvm && -w /dev/kvm ]] || {
    echo '/dev/kvm is unavailable' >&2
    exit 1
}
for command in base64 cp cut find grep mktemp pgrep qemu-system-x86_64 \
        realpath sed sort swtpm tail timeout tr truncate zstd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -f $ovmf_code ]] || { echo "missing OVMF code image: $ovmf_code" >&2; exit 1; }
[[ -d $audit_tmpdir && -w $audit_tmpdir ]] || {
    echo "VM update audit temporary directory is not writable: $audit_tmpdir" >&2
    exit 1
}

snapshot_root=$(mktemp -d "$audit_tmpdir/.particleos-artifact-snapshot.XXXXXXXX")
trap 'rm -rf -- "$snapshot_root"' EXIT
"$repository/scripts/validate-artifacts.sh" "$base_artifacts" "$snapshot_root/base"
"$repository/scripts/validate-artifacts.sh" "$candidate_artifacts" "$snapshot_root/candidate"
base_artifacts=$snapshot_root/base
candidate_artifacts=$snapshot_root/candidate

find_one() {
    local directory=$1 pattern=$2 description=$3
    local -a matches=()
    mapfile -t matches < <(find "$directory" -maxdepth 1 -type f -name "$pattern" -print)
    [[ ${#matches[@]} -eq 1 ]] || {
        echo "expected one $description in $directory, found ${#matches[@]}" >&2
        return 1
    }
    printf '%s\n' "${matches[0]}"
}

read_image_version() {
    local osrelease=$1 version
    version=$(sed -n -E \
        's/^IMAGE_VERSION="?([0-9]+([.][0-9]+)*)"?$/\1/p' \
        "$osrelease")
    [[ $version =~ ^[0-9]+([.][0-9]+)*$ ]] || {
        echo "invalid IMAGE_VERSION in $osrelease" >&2
        return 1
    }
    printf '%s\n' "$version"
}

base_image=$(find_one "$base_artifacts" 'ParticleOS-Host_*_x86-64.raw.zst' 'base disk image')
candidate_image=$(find_one "$candidate_artifacts" 'ParticleOS-Host_*_x86-64.raw.zst' 'candidate disk image')
base_osrelease=$(find_one "$base_artifacts" 'ParticleOS-Host_*_x86-64.osrelease' 'base os-release')
candidate_osrelease=$(find_one "$candidate_artifacts" 'ParticleOS-Host_*_x86-64.osrelease' 'candidate os-release')
base_version=$(read_image_version "$base_osrelease")
candidate_version=$(read_image_version "$candidate_osrelease")
latest_version=$(printf '%s\n%s\n' "$base_version" "$candidate_version" | sort -V | tail -1)
[[ $candidate_version == "$latest_version" && $candidate_version != "$base_version" ]] || {
    echo "candidate version $candidate_version must be newer than base $base_version" >&2
    exit 1
}

# The candidate disk is authenticated above but updates are intentionally
# downloaded through the image's production systemd-sysupdate configuration.
# Keeping this reference makes the required local evidence explicit.
[[ -s $candidate_image ]]

audit_service=$(base64 -w0 "$repository/tests/update-rollback-audit-getty.conf")
audit_script=$(base64 -w0 "$repository/tests/update-rollback-audit.sh")
prune_audit=$(base64 -w0 "$repository/tests/update-rollback-prune-audit.conf")
audit_activate=$(base64 -w0 "$repository/tests/audit-activate.conf")
pcrlock_audit=$(base64 -w0 "$repository/tests/pcrlock-enroll-audit.conf")
boot_diagnostic_service=$(base64 -w0 "$repository/tests/boot-audit-diagnostic.conf")
boot_diagnostic_script=$(base64 -w0 "$repository/tests/boot-audit-diagnostic")
homed_firstboot_dropin=$(base64 -w0 "$repository/tests/homed-firstboot-audit.conf")
homed_firstboot_audit=$(base64 -w0 "$repository/tests/homed-firstboot-audit")
root_password=$(printf particleos | base64 -w0)
firstboot_timezone=$(printf Etc/UTC | base64 -w0)
health_dropin=$(base64 -w0 "$repository/tests/update-rollback-health.conf")
health_script=$(base64 -w0 "$repository/tests/update-rollback-health.sh")
host_failure_dropin=$(base64 -w0 "$repository/tests/update-rollback-host-failure.conf")
host_failure_script=$(base64 -w0 "$repository/tests/update-rollback-host-failure")
base_credential=$(printf '%s\n' "$base_version" | base64 -w0)
candidate_credential=$(printf '%s\n' "$candidate_version" | base64 -w0)

scratch=$(mktemp -d "$audit_tmpdir/.particleos-update-rollback.XXXXXXXX")
runtime_directory=$(mktemp -d /tmp/particleos-update-rollback.XXXXXXXX)
active_state=
qemu_active=0

stop_tpm() {
    local pid='' pidfile
    [[ -n ${active_state:-} ]] || return 0
    pidfile=$active_state/swtpm.pid
    if [[ -s $pidfile ]]; then
        read -r pid <"$pidfile" || true
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/comm &&
            -r /proc/$pid/cmdline && $(<"/proc/$pid/comm") == swtpm ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
        if [[ $command_line == *"$active_state/"* ]]; then
            kill "$pid" 2>/dev/null || true
            for _ in {1..20}; do
                [[ ! -e /proc/$pid ]] && break
                sleep 0.1
            done
            if [[ -r /proc/$pid/comm && $(<"/proc/$pid/comm") == swtpm ]]; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    fi
}

stop_qemu() {
    local command_line='' pid='' pidfile
    [[ -n ${active_state:-} ]] || return 0
    pidfile=$active_state/qemu.pid
    if [[ -s $pidfile ]]; then
        read -r pid <"$pidfile" || true
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/comm &&
            -r /proc/$pid/cmdline && $(<"/proc/$pid/comm") == qemu-system-x86 ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
        if [[ $command_line == *"$active_state/"* ]]; then
            kill -TERM "$pid" 2>/dev/null || true
            for _ in {1..30}; do
                [[ ! -e /proc/$pid ]] && break
                sleep 0.1
            done
            if [[ -r /proc/$pid/comm && $(<"/proc/$pid/comm") == qemu-system-x86 ]]; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
        fi
    fi
}

cleanup() {
    local status=$?
    if ((qemu_active)); then
        stop_qemu
    fi
    stop_tpm
    if [[ -n ${runtime_directory:-} && -d $runtime_directory &&
            $runtime_directory == /tmp/particleos-update-rollback.* ]]; then
        rm -rf -- "$runtime_directory"
    fi
    rm -rf -- "$snapshot_root"
    if ((status != 0)) && [[ $keep_failed == 1 ]]; then
        echo "Preserved failed update/rollback audit state: $scratch" >&2
    elif [[ -n ${scratch:-} && -d $scratch &&
            ${scratch##*/} == .particleos-update-rollback.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

prepare_scenario() {
    local scenario=$1
    active_state=$scratch/$scenario
    mkdir -m 0700 "$active_state" "$active_state/tpm"
    cp --reflink=auto --sparse=always "$ovmf_vars_source" "$active_state/ovmf-vars.bin"
    zstd --sparse -q -d -f -o "$active_state/particleos.raw" "$base_image"
    truncate -s 16G "$active_state/particleos.raw"
}

extract_usrhash() {
    local log=$1 evidence
    evidence=$(grep -m1 -oE \
        'UPDATE_ROLLBACK_AUDIT_USRHASH hash=[0-9a-f]{64}' "$log") || {
        echo "missing explicit usrhash evidence in $log" >&2
        return 1
    }
    printf '%s\n' "${evidence##*=}"
}

assert_counted_attempt() {
    local boot_number=$1 tries_left=$2 tries_done=$3 log actual_usrhash
    log=$active_state/boot-$boot_number.log
    actual_usrhash=$(extract_usrhash "$log") || return 1
    if ! grep -qF "ParticleOS-Host_${candidate_version}_x86-64+${tries_left}-${tries_done}.efi" "$log" ||
            [[ $actual_usrhash == "$fallback_base_usrhash" ]]; then
        tail -240 "$log" >&2 || true
        echo "candidate attempt $tries_done did not have the expected boot count and usrhash" >&2
        return 1
    fi
    echo "UPDATE_ROLLBACK_AUDIT_COUNTED_ATTEMPT attempt=$tries_done tries_left=$tries_left version=$candidate_version"
}

assert_failed_host_attempt() {
    local boot_number=$1 tries_left=$2 tries_done=$3 log
    log=$active_state/boot-$boot_number.log
    if ! grep -qF "ParticleOS-Host_${candidate_version}_x86-64+${tries_left}-${tries_done}.efi" "$log" ||
            ! grep -qF "UPDATE_ROLLBACK_AUDIT_HOST_FAILURE version=$candidate_version" "$log"; then
        tail -240 "$log" >&2 || true
        echo "failed host attempt $tries_done did not have the expected boot count and injected failure" >&2
        return 1
    fi
    echo "UPDATE_ROLLBACK_AUDIT_COUNTED_HOST_FAILURE attempt=$tries_done tries_left=$tries_left version=$candidate_version"
}

run_guest() {
    local scenario=$1 boot_number=$2 expectation=$3
    local log=$active_state/boot-$boot_number.log
    local socket=$runtime_directory/tpm.sock
    local scenario_credential status timeout_seconds
    scenario_credential=$(printf '%s\n' "$scenario" | base64 -w0)
    timeout_seconds=$audit_timeout
    [[ $expectation == denied ]] && timeout_seconds=$denial_timeout

    rm -f -- "$active_state/swtpm.pid" "$active_state/qemu.pid" "$socket"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$active_state/tpm" \
        --ctrl "type=unixio,path=$socket" \
        --pid "file=$active_state/swtpm.pid" \
        --log "file=$active_state/swtpm-$boot_number.log" \
        --daemon \
        --terminate

    qemu_active=1
    set +e
    timeout --foreground --signal=TERM --kill-after=15s "$timeout_seconds" \
        qemu-system-x86_64 \
        -name "particleos-update-rollback-audit-$$-$scenario" \
        -machine q35,smm=on,accel=kvm \
        -cpu host \
        -m 2048 \
        -smp 2 \
        -pidfile "$active_state/qemu.pid" \
        -global driver=cfi.pflash01,property=secure,value=on \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,unit=1,file=$active_state/ovmf-vars.bin" \
        -drive "if=virtio,format=raw,file=$active_state/particleos.raw" \
        -chardev "socket,id=chrtpm,path=$socket" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0 \
        -display "$vm_display" \
        -serial "file:$log" \
        -monitor none \
        -no-reboot \
        -smbios type=11,value='io.systemd.stub.kernel-cmdline-extra=systemd.mask=serial-getty@ttyS0.service systemd.mask=systemd-sysupdate.timer systemd.mask=systemd-sysupdate-reboot.timer' \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.getty@tty1.service~90-particleos-update-audit=$audit_service" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit=$audit_activate" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit=$pcrlock_audit" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-prune.service~90-particleos-audit=$prune_audit" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-prune.service~80-particleos-host-failure=$host_failure_dropin" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit=$boot_diagnostic_service" \
        -smbios "type=11,value=io.systemd.credential.binary:boot-audit-diagnostic=$boot_diagnostic_script" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-audit=$homed_firstboot_dropin" \
        -smbios "type=11,value=io.systemd.credential.binary:homed-firstboot-audit=$homed_firstboot_audit" \
        -smbios "type=11,value=io.systemd.credential.binary:passwd.plaintext-password.root=$root_password" \
        -smbios "type=11,value=io.systemd.credential.binary:firstboot.timezone=$firstboot_timezone" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-workload-health.service~90-particleos-update-audit=$health_dropin" \
        -smbios "type=11,value=io.systemd.credential.binary:update-rollback-audit=$audit_script" \
        -smbios "type=11,value=io.systemd.credential.binary:update-rollback-health=$health_script" \
        -smbios "type=11,value=io.systemd.credential.binary:update-rollback-host-failure=$host_failure_script" \
        -smbios "type=11,value=io.systemd.credential.binary:update-audit-scenario=$scenario_credential" \
        -smbios "type=11,value=io.systemd.credential.binary:update-audit-base-version=$base_credential" \
        -smbios "type=11,value=io.systemd.credential.binary:update-audit-candidate-version=$candidate_credential"
    status=$?
    set -e
    qemu_active=0
    stop_tpm

    if [[ $expectation == clean || $expectation == enrollment ]]; then
        if ((status != 0)); then
            tail -240 "$log" >&2 || true
            echo "$scenario boot $boot_number did not power off or reboot cleanly" >&2
            return 1
        fi
        if grep -q 'UPDATE_ROLLBACK_AUDIT_FAIL ' "$log"; then
            tail -240 "$log" >&2 || true
            echo "$scenario boot $boot_number failed a guest-side audit assertion" >&2
            return 1
        fi
        if [[ $expectation == enrollment ]]; then
            grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_STAGED ' "$log" || {
                tail -240 "$log" >&2 || true
                echo "$scenario bootstrap-enrollment boot did not stage the retained PCR 7 token" >&2
                return 1
            }
            grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED ' "$log" || {
                tail -240 "$log" >&2 || true
                echo "$scenario bootstrap-enrollment boot did not queue its proof reboot" >&2
                return 1
            }
        fi
    else
        if ((status != 124)); then
            tail -240 "$log" >&2 || true
            echo "superseded UKI unexpectedly completed boot with status $status" >&2
            return 1
        fi
        if grep -q 'UPDATE_ROLLBACK_AUDIT_BYPASS ' "$log"; then
            tail -240 "$log" >&2 || true
            echo 'superseded UKI bypassed the TPM rollback boundary' >&2
            return 1
        fi
        grep -q 'unit=emergency ' "$log" || {
            tail -240 "$log" >&2 || true
            echo 'superseded UKI did not produce the expected initrd emergency evidence' >&2
            return 1
        }
    fi
}

if [[ $requested_scenario == all || $requested_scenario == rollback-denial ]]; then
echo "Testing blessed-candidate revocation: $base_version -> $candidate_version"
prepare_scenario rollback-denial
run_guest rollback-denial 0 enrollment
run_guest rollback-denial 1 clean
grep 'UPDATE_ROLLBACK_AUDIT_STAGED ' "$active_state/boot-1.log"
denial_base_usrhash=$(extract_usrhash "$active_state/boot-1.log")
run_guest rollback-denial 2 clean
grep 'UPDATE_ROLLBACK_AUDIT_CANDIDATE_BLESSED ' "$active_state/boot-2.log"
grep -F "UPDATE_ROLLBACK_AUDIT_OLD_UKI_ONESHOT entry=ParticleOS-Host_${base_version}_x86-64.efi" \
    "$active_state/boot-2.log"
denial_candidate_usrhash=$(extract_usrhash "$active_state/boot-2.log")
[[ $denial_candidate_usrhash != "$denial_base_usrhash" ]]
run_guest rollback-denial 3 denied
echo 'UPDATE_ROLLBACK_AUDIT_DENIAL_PASS superseded signed UKI could not unlock persistent state'
fi

if [[ $requested_scenario == all || $requested_scenario == workload-quarantine ]]; then
echo "Testing bounded opt-in workload health: $base_version -> $candidate_version"
prepare_scenario workload-quarantine
run_guest workload-quarantine 0 enrollment
run_guest workload-quarantine 1 clean
grep 'UPDATE_ROLLBACK_AUDIT_STAGED ' "$active_state/boot-1.log"
fallback_base_usrhash=$(extract_usrhash "$active_state/boot-1.log")
run_guest workload-quarantine 2 clean
assert_counted_attempt 2 2 1
grep -F "PARTICLEOS_WORKLOAD_CANDIDATE_FAILED version=$candidate_version attempts=1" \
    "$active_state/boot-2.log"
run_guest workload-quarantine 3 clean
assert_counted_attempt 3 1 2
grep -F "PARTICLEOS_WORKLOAD_CANDIDATE_FAILED version=$candidate_version attempts=2" \
    "$active_state/boot-3.log"
run_guest workload-quarantine 4 clean
assert_counted_attempt 4 0 3
grep -F "PARTICLEOS_WORKLOAD_QUARANTINED version=$candidate_version attempts=3 status=1" \
    "$active_state/boot-4.log"
grep 'UPDATE_ROLLBACK_AUDIT_CANDIDATE_BLESSED ' "$active_state/boot-4.log"
run_guest workload-quarantine 5 denied
echo 'UPDATE_ROLLBACK_AUDIT_WORKLOAD_BOUND_PASS unhealthy workload quarantined and candidate adopted on attempt three'
fi

if [[ $requested_scenario == all || $requested_scenario == host-fallback ]]; then
echo "Testing authenticated three-attempt host fallback: $candidate_version -> $base_version"
prepare_scenario host-fallback
run_guest host-fallback 0 enrollment
run_guest host-fallback 1 clean
grep 'UPDATE_ROLLBACK_AUDIT_STAGED ' "$active_state/boot-1.log"
fallback_base_usrhash=$(extract_usrhash "$active_state/boot-1.log")
for boot_number in 2 3 4; do
    run_guest host-fallback "$boot_number" clean
    tries_done=$((boot_number - 1))
    tries_left=$((3 - tries_done))
    assert_failed_host_attempt "$boot_number" "$tries_left" "$tries_done"
done
run_guest host-fallback 5 clean
grep 'UPDATE_ROLLBACK_AUDIT_FALLBACK_PASS ' "$active_state/boot-5.log"
grep 'UPDATE_ROLLBACK_AUDIT_FALLBACK_PRUNE_CONFIRMED ' "$active_state/boot-5.log"
[[ $(extract_usrhash "$active_state/boot-5.log") == "$fallback_base_usrhash" ]]
fi

echo 'ParticleOS A/B update, bounded workload health, authenticated three-attempt host fallback, and signed-UKI rollback-protection audit passed; all guests and TPM emulators are stopped.'
