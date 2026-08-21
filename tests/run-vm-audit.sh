#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY ENROLLED_OVMF_VARS CONTAINER_FIXTURE" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tests/lib/mkosi-vm.sh
source "$repository/tests/lib/mkosi-vm.sh"
artifact_directory=$(realpath "$1")
ovmf_vars_source=$(realpath "$2")
container_fixture=$(realpath "$3")
audit_timeout=${VM_AUDIT_TIMEOUT:-900}
denial_timeout=${VM_AUDIT_DENIAL_TIMEOUT:-80}
audit_tmpdir=${VM_AUDIT_TMPDIR:-$artifact_directory}
keep_failed=${VM_AUDIT_KEEP_FAILED:-0}
only_network_fault=${VM_AUDIT_ONLY_NETWORK_FAULT:-0}
vm_display=${VM_AUDIT_DISPLAY:-none}

[[ $audit_timeout =~ ^[1-9][0-9]*$ && $denial_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'VM_AUDIT_TIMEOUT and VM_AUDIT_DENIAL_TIMEOUT must be positive seconds' >&2
    exit 2
}
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'VM_AUDIT_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
[[ $only_network_fault == 0 || $only_network_fault == 1 ]] || {
    echo 'VM_AUDIT_ONLY_NETWORK_FAULT must be 0 or 1' >&2
    exit 2
}
vm_console=$(mkosi_vm_console "$vm_display")
mkosi_vm_require
for command in cp dd find grep install jq mcopy mktemp realpath systemd-repart \
        tail timeout truncate zstd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -f $container_fixture ]] || { echo "missing signed container fixture: $container_fixture" >&2; exit 1; }
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
vm_active=0
active_machine=
swtpm_pid_file=$scratch/swtpm.pid

cleanup() {
    local status=$?
    if ((vm_active)) && [[ -n $active_machine ]]; then
        mkosi_vm_stop 0 "$scratch" "$active_machine"
    fi
    mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"
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

install_credential() {
    local source=$1 directory=$2 name=$3
    install -m 0600 "$source" "$directory/$name"
}

write_credential() {
    local value=$1 directory=$2 name=$3
    printf '%s' "$value" >"$directory/$name"
    chmod 0600 "$directory/$name"
}

run_boot() {
    local boot_number=$1 expectation=$2 boot_disk=${3:-$disk}
    local log=$scratch/boot-$boot_number.log
    local socket=$scratch/tpm-$boot_number.sock
    local credentials=$scratch/credentials-$boot_number
    local timeout_seconds=$audit_timeout status
    local kernel_command_line_extra='systemd.mask=serial-getty@ttyS0.service'
    local -a qemu_arguments=(
        -netdev 'user,id=net0,guestfwd=tcp:10.0.2.100:18443-cmd:/bin/cat'
        -device 'virtio-net-pci,netdev=net0'
        -no-reboot
    )

    mkdir -m 0700 "$credentials"
    if [[ $expectation == denied ]]; then
        timeout_seconds=$denial_timeout
    elif [[ $expectation == security-fault ]]; then
        timeout_seconds=$denial_timeout
        # Do not let a resumable provisioning prompt consume the bounded
        # firewall-failure window before network-pre.target is reached.
        kernel_command_line_extra+=' systemd.mask=systemd-firstboot.service systemd.mask=systemd-homed-firstboot.service'
        install_credential "$repository/tests/nftables-failure.conf" "$credentials" \
            'systemd.unit-dropin.nftables.service~90-particleos-failure'
        install_credential "$repository/tests/boot-audit-diagnostic.conf" "$credentials" \
            'systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit'
        install_credential "$repository/tests/boot-audit-diagnostic" "$credentials" \
            boot-audit-diagnostic
        install_credential "$repository/tests/audit-activate.conf" "$credentials" \
            'systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit'
        install_credential "$repository/tests/network-failure-audit.conf" "$credentials" \
            'systemd.unit-dropin.getty@tty1.service~90-particleos-network-failure'
    else
        install_credential "$repository/tests/vm-audit-getty.conf" "$credentials" \
            'systemd.unit-dropin.getty@tty1.service~90-particleos-vm-audit'
        install_credential "$repository/tests/audit-activate.conf" "$credentials" \
            'systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit'
        install_credential "$repository/tests/pcrlock-enroll-audit.conf" "$credentials" \
            'systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit'
        install_credential "$repository/tests/pcrlock-header-backup.conf" "$credentials" \
            'systemd.unit-dropin.particleos-pcrlock-enroll.service~80-particleos-header-backup'
        install_credential "$repository/tests/pcrlock-header-backup" "$credentials" \
            pcrlock-header-backup
        install_credential "$repository/tests/boot-audit-diagnostic.conf" "$credentials" \
            'systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit'
        install_credential "$repository/tests/boot-audit-diagnostic" "$credentials" \
            boot-audit-diagnostic
        install_credential "$repository/tests/homed-firstboot-audit.conf" "$credentials" \
            'systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-audit'
        install_credential "$repository/tests/homed-firstboot-audit" "$credentials" \
            homed-firstboot-audit
        install_credential "$repository/tests/vm-audit.sh" "$credentials" vm-audit
        write_credential particleos "$credentials" passwd.plaintext-password.root
        write_credential Etc/UTC "$credentials" firstboot.timezone
        qemu_arguments=(
            -drive "if=virtio,format=raw,readonly=on,file=$container_fixture"
            "${qemu_arguments[@]}"
        )
    fi

    mkosi_vm_start_tpm "$tpm_state" "$socket" "$swtpm_pid_file" \
        "$scratch/swtpm-$boot_number.log"
    active_machine="particleos-audit-$$-$boot_number"
    mkosi_vm_build_command "$repository" "$boot_disk" "$ovmf_vars" \
        "$active_machine" "$vm_console" "$credentials" \
        "$kernel_command_line_extra" "$socket" "file:$log" \
        "${qemu_arguments[@]}"

    vm_active=1
    set +e
    timeout --foreground --signal=TERM --kill-after=15s "$timeout_seconds" \
        "${MKOSI_VM_COMMAND[@]}"
    status=$?
    set -e
    mkosi_vm_stop 0 "$scratch" "$active_machine"
    vm_active=0
    mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"

    if [[ $expectation == denied ]]; then
        if ((status == 124)) &&
                grep -Eq 'ParticleOS-Host-root|systemd-cryptsetup@root|Failed to mount|emergency' "$log" &&
                ! grep -q '^PARTICLEOS_VM_AUDIT_PASS ' "$log"; then
            echo 'PARTICLEOS_LUKS_HEADER_REPLAY_DENIED'
            return 0
        fi
    elif [[ $expectation == security-fault ]]; then
        if ((status == 0)) &&
                ! grep -Eq 'Started.*systemd-networkd|PARTICLEOS_VM_AUDIT_PASS|PARTICLEOS_NETWORK_SECURITY_FAIL_OPEN' "$log"; then
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
    echo "VM audit boot $boot_number failed (mkosi status $status)" >&2
    return 1
}

if [[ $only_network_fault == 1 ]]; then
    echo 'Injecting an nftables startup failure on a fresh authenticated image...'
    run_boot 1 security-fault
    echo 'ParticleOS fail-closed network startup audit passed; mkosi VM and TPM emulator are stopped.'
    exit 0
fi

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

echo 'ParticleOS mkosi VM audit passed, including LUKS2 header-replay denial and fail-closed network startup; all guests and TPM emulators are stopped.'
