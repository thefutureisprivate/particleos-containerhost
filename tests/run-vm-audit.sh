#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -lt 3 || $# -gt 4 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY ENROLLED_OVMF_VARS CONTAINER_FIXTURE [OVMF_CODE]" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
artifact_directory=$(realpath "$1")
ovmf_vars_source=$(realpath "$2")
container_fixture=$(realpath "$3")
ovmf_code=${4:-/usr/share/qemu/ovmf-x86_64-smm-code.bin}
ovmf_code=$(realpath "$ovmf_code")
audit_timeout=${VM_AUDIT_TIMEOUT:-900}
denial_timeout=${VM_AUDIT_DENIAL_TIMEOUT:-80}
audit_tmpdir=${VM_AUDIT_TMPDIR:-$artifact_directory}
keep_failed=${VM_AUDIT_KEEP_FAILED:-0}
vm_display=${VM_AUDIT_DISPLAY:-none}

[[ $audit_timeout =~ ^[1-9][0-9]*$ && $denial_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'VM_AUDIT_TIMEOUT and VM_AUDIT_DENIAL_TIMEOUT must be positive seconds' >&2
    exit 2
}
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'VM_AUDIT_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
[[ $vm_display == none || $vm_display == gtk ]] || {
    echo 'VM_AUDIT_DISPLAY must be none or gtk' >&2
    exit 2
}
[[ -r /dev/kvm && -w /dev/kvm ]] || {
    echo '/dev/kvm is unavailable' >&2
    exit 1
}
for command in base64 cp dd find grep jq mcopy mktemp pgrep pkill qemu-system-x86_64 \
        realpath swtpm systemd-repart tail timeout tr truncate zstd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -f $container_fixture ]] || { echo "missing signed container fixture: $container_fixture" >&2; exit 1; }
[[ -f $ovmf_code ]] || { echo "missing OVMF code image: $ovmf_code" >&2; exit 1; }
[[ -d $audit_tmpdir && -w $audit_tmpdir ]] || {
    echo "VM audit temporary directory is not writable: $audit_tmpdir" >&2
    exit 1
}

snapshot_root=$(mktemp -d "$audit_tmpdir/.particleos-artifact-snapshot.XXXXXXXX")
trap 'rm -rf -- "$snapshot_root"' EXIT
authenticated_artifacts=$snapshot_root/release
"$repository/scripts/validate-artifacts.sh" "$artifact_directory" "$authenticated_artifacts"
artifact_directory=$authenticated_artifacts
mapfile -t compressed_images < <(
    find "$artifact_directory" -maxdepth 1 -type f \
        -name 'ParticleOS-Host_*_x86-64.raw.zst' -print
)
[[ ${#compressed_images[@]} -eq 1 ]] || {
    echo "expected one compressed disk image, found ${#compressed_images[@]}" >&2
    exit 1
}

scratch=$(mktemp -d "$audit_tmpdir/.particleos-vm-audit.XXXXXXXX")
qemu_active=0
swtpm_pid_file=$scratch/swtpm.pid

stop_tpm() {
    local command_line='' pid=''
    if [[ -s $swtpm_pid_file ]]; then
        read -r pid <"$swtpm_pid_file" || true
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/comm &&
            -r /proc/$pid/cmdline ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    fi
    if [[ $command_line == *"$scratch/"* ]] &&
            [[ $(<"/proc/$pid/comm") == swtpm ]]; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            [[ ! -e /proc/$pid ]] && break
            sleep 0.1
        done
        if [[ -r /proc/$pid/comm ]] && [[ $(<"/proc/$pid/comm") == swtpm ]]; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
}

stop_qemu() {
    local pattern="name particleos-containerhost-audit-$$"
    pkill -TERM -f "$pattern" 2>/dev/null || true
    for _ in {1..30}; do
        pgrep -f "$pattern" >/dev/null || return 0
        sleep 0.1
    done
    pkill -KILL -f "$pattern" 2>/dev/null || true
}

cleanup() {
    local status=$?
    if ((qemu_active)); then
        stop_qemu
    fi
    stop_tpm
    rm -rf -- "$snapshot_root"
    if ((status != 0)) && [[ $keep_failed == 1 ]]; then
        echo "Preserved failed VM audit state: $scratch" >&2
    elif [[ -n ${scratch:-} && -d $scratch &&
            ${scratch##*/} == .particleos-vm-audit.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

disk=$scratch/particleos.raw
ovmf_vars=$scratch/ovmf-vars.bin
tpm_state=$scratch/tpm
mkdir -m 0700 "$tpm_state"
cp --reflink=auto --sparse=always "$ovmf_vars_source" "$ovmf_vars"
zstd --sparse -q -d -f -o "$disk" "${compressed_images[0]}"
truncate -s 16G "$disk"

audit_service=$(base64 -w0 "$repository/tests/vm-audit-getty.conf")
audit_script=$(base64 -w0 "$repository/tests/vm-audit.sh")
audit_activate=$(base64 -w0 "$repository/tests/audit-activate.conf")
pcrlock_audit=$(base64 -w0 "$repository/tests/pcrlock-enroll-audit.conf")
pcrlock_header_backup_dropin=$(base64 -w0 "$repository/tests/pcrlock-header-backup.conf")
pcrlock_header_backup=$(base64 -w0 "$repository/tests/pcrlock-header-backup")
boot_diagnostic_service=$(base64 -w0 "$repository/tests/boot-audit-diagnostic.conf")
boot_diagnostic_script=$(base64 -w0 "$repository/tests/boot-audit-diagnostic")
homed_firstboot_dropin=$(base64 -w0 "$repository/tests/homed-firstboot-audit.conf")
homed_firstboot_audit=$(base64 -w0 "$repository/tests/homed-firstboot-audit")
root_password=$(printf particleos | base64 -w0)
firstboot_timezone=$(printf Etc/UTC | base64 -w0)
nftables_failure=$(base64 -w0 "$repository/tests/nftables-failure.conf")

run_boot() {
    local boot_number=$1
    local expectation=$2
    local boot_disk=${3:-$disk}
    local log=$scratch/boot-$boot_number.log
    local socket=$scratch/tpm-$boot_number.sock
    local timeout_seconds=$audit_timeout status
    local -a fault_credentials=()
    [[ $expectation == denied ]] && timeout_seconds=$denial_timeout
    if [[ $expectation == security-fault ]]; then
        timeout_seconds=$denial_timeout
        fault_credentials=(
            -smbios
            "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.nftables.service~90-particleos-failure=$nftables_failure"
        )
    fi

    rm -f -- "$swtpm_pid_file"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$tpm_state" \
        --ctrl "type=unixio,path=$socket" \
        --pid "file=$swtpm_pid_file" \
        --log "file=$scratch/swtpm-$boot_number.log" \
        --daemon \
        --terminate

    qemu_active=1
    set +e
    timeout --foreground --signal=TERM --kill-after=15s "$timeout_seconds" \
            qemu-system-x86_64 \
            -name "particleos-containerhost-audit-$$" \
            -machine q35,smm=on,accel=kvm \
            -cpu host \
            -m 2048 \
            -smp 2 \
            -global driver=cfi.pflash01,property=secure,value=on \
            -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
            -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars" \
            -drive "if=virtio,format=raw,file=$boot_disk" \
            -drive "if=virtio,format=raw,readonly=on,file=$container_fixture" \
            -chardev "socket,id=chrtpm,path=$socket" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-tis,tpmdev=tpm0 \
            -netdev user,id=net0,guestfwd=tcp:10.0.2.100:18443-cmd:/bin/cat \
            -device virtio-net-pci,netdev=net0 \
            -display "$vm_display" \
            -serial "file:$log" \
            -monitor none \
            -no-reboot \
            -smbios type=11,value='io.systemd.stub.kernel-cmdline-extra=systemd.mask=serial-getty@ttyS0.service' \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.getty@tty1.service~90-particleos-vm-audit=$audit_service" \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit=$audit_activate" \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit=$pcrlock_audit" \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-enroll.service~80-particleos-header-backup=$pcrlock_header_backup_dropin" \
            -smbios "type=11,value=io.systemd.credential.binary:pcrlock-header-backup=$pcrlock_header_backup" \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit=$boot_diagnostic_service" \
            -smbios "type=11,value=io.systemd.credential.binary:boot-audit-diagnostic=$boot_diagnostic_script" \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-audit=$homed_firstboot_dropin" \
            -smbios "type=11,value=io.systemd.credential.binary:homed-firstboot-audit=$homed_firstboot_audit" \
            -smbios "type=11,value=io.systemd.credential.binary:passwd.plaintext-password.root=$root_password" \
            -smbios "type=11,value=io.systemd.credential.binary:firstboot.timezone=$firstboot_timezone" \
            -smbios "type=11,value=io.systemd.credential.binary:vm-audit=$audit_script" \
            "${fault_credentials[@]}"
    status=$?
    set -e
    qemu_active=0
    stop_tpm

    if [[ $expectation == denied ]]; then
        if ((status == 124)) &&
                grep -Eq 'ParticleOS-Host-root|systemd-cryptsetup@root|Failed to mount|emergency' "$log" &&
                ! grep -q '^PARTICLEOS_VM_AUDIT_PASS ' "$log"; then
            echo 'PARTICLEOS_LUKS_HEADER_REPLAY_DENIED'
            return 0
        fi
    elif [[ $expectation == security-fault ]]; then
        if ((status == 124)) &&
                grep -Eq 'Failed to start.*nftables|nftables[.]service.*failed|Emergency Mode' "$log" &&
                ! grep -Eq 'Started.*systemd-networkd|PARTICLEOS_VM_AUDIT_PASS' "$log"; then
            echo 'PARTICLEOS_NETWORK_SECURITY_FAIL_CLOSED'
            return 0
        fi
    elif ((status != 0)); then
        :
    elif [[ $expectation == enrollment ]]; then
        if grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_STAGED ' "$log" &&
                grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED ' "$log" &&
                ! grep -q '^PARTICLEOS_VM_AUDIT_FAIL ' "$log"; then
            grep 'PARTICLEOS_PCRLOCK_BOOTSTRAP_STAGED ' "$log" | tail -n1
            grep 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED ' "$log" | tail -n1
            return 0
        fi
    elif grep -q '^PARTICLEOS_VM_AUDIT_PASS ' "$log" &&
            ! grep -q '^PARTICLEOS_VM_AUDIT_FAIL ' "$log"; then
        grep '^PARTICLEOS_VM_AUDIT_PASS ' "$log"
        return 0
    fi
    tail -240 "$log" >&2 || true
    echo "VM audit boot $boot_number failed" >&2
    return 1
}

echo 'Staging PCR 7+11 enrollment while retaining the PCR 7 bootstrap token...'
run_boot 1 enrollment
echo 'Proving the PCR 7+11 token on a later boot before retiring bootstrap...'
run_boot 2 audit
echo 'Running persistent TPM-unlock and signed-container audit with the same state...'
run_boot 3 audit

echo 'Restoring the bootstrap-era LUKS2 header to prove its volume key is obsolete...'
esp_offset=$(systemd-repart --json=short "$disk" |
    jq -r '.[] | select(.type == "esp") | .offset')
state_offset=$(systemd-repart --json=short "$disk" |
    jq -r '.[] | select(.label == "ParticleOS-Host-root") | .offset')
[[ $esp_offset =~ ^[0-9]+$ && $state_offset =~ ^[0-9]+$ && $((state_offset % 4096)) -eq 0 ]]
mcopy -i "$disk@@$esp_offset" ::pcr7-bootstrap-header "$scratch/pcr7-bootstrap-header"
[[ -s $scratch/pcr7-bootstrap-header ]]
header_replay_disk=$scratch/header-replay.raw
cp --reflink=auto --sparse=always "$disk" "$header_replay_disk"
dd if="$scratch/pcr7-bootstrap-header" of="$header_replay_disk" bs=4096 \
    seek=$((state_offset / 4096)) conv=notrunc status=none
run_boot 4 denied "$header_replay_disk"

echo 'Injecting an nftables startup failure to prove network activation fails closed...'
run_boot 5 security-fault

echo 'ParticleOS VM audit passed, including LUKS2 header-replay denial and fail-closed network startup; all guests and TPM emulators are stopped.'
