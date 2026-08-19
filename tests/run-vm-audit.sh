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
audit_timeout=${VM_AUDIT_TIMEOUT:-300}
audit_tmpdir=${VM_AUDIT_TMPDIR:-$artifact_directory}

[[ $audit_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'VM_AUDIT_TIMEOUT must be a positive number of seconds' >&2
    exit 2
}
[[ -r /dev/kvm && -w /dev/kvm ]] || {
    echo '/dev/kvm is unavailable' >&2
    exit 1
}
for command in base64 cp find grep mktemp pgrep pkill qemu-system-x86_64 realpath \
        swtpm tail timeout tr truncate zstd; do
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

"$repository/scripts/validate-artifacts.sh" "$artifact_directory"
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
    if [[ -n ${scratch:-} && -d $scratch &&
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

audit_service=$(base64 -w0 "$repository/tests/vm-audit.service")
audit_script=$(base64 -w0 "$repository/tests/vm-audit.sh")

run_boot() {
    local boot_number=$1
    local log=$scratch/boot-$boot_number.log
    local socket=$scratch/tpm-$boot_number.sock

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
    if ! timeout --foreground --signal=TERM --kill-after=15s "$audit_timeout" \
            qemu-system-x86_64 \
            -name "particleos-containerhost-audit-$$" \
            -machine q35,smm=on,accel=kvm \
            -cpu host \
            -m 2048 \
            -smp 2 \
            -global driver=cfi.pflash01,property=secure,value=on \
            -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
            -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars" \
            -drive "if=virtio,format=raw,file=$disk" \
            -drive "if=virtio,format=raw,readonly=on,file=$container_fixture" \
            -chardev "socket,id=chrtpm,path=$socket" \
            -tpmdev emulator,id=tpm0,chardev=chrtpm \
            -device tpm-tis,tpmdev=tpm0 \
            -netdev user,id=net0 \
            -device virtio-net-pci,netdev=net0 \
            -display none \
            -serial "file:$log" \
            -monitor none \
            -no-reboot \
            -smbios type=11,value=io.systemd.stub.kernel-cmdline-extra=systemd.wants=vm-audit.service \
            -smbios "type=11,value=io.systemd.credential.binary:systemd.extra-unit.vm-audit.service=$audit_service" \
            -smbios "type=11,value=io.systemd.credential.binary:vm-audit=$audit_script"; then
        qemu_active=0
        stop_tpm
        tail -200 "$log" >&2 || true
        echo "VM audit boot $boot_number did not power off cleanly" >&2
        return 1
    fi
    qemu_active=0
    stop_tpm

    if ! grep -q '^PARTICLEOS_VM_AUDIT_PASS ' "$log" ||
            grep -q '^PARTICLEOS_VM_AUDIT_FAIL ' "$log"; then
        tail -240 "$log" >&2 || true
        echo "VM audit boot $boot_number failed" >&2
        return 1
    fi
    grep '^PARTICLEOS_VM_AUDIT_PASS ' "$log"
}

echo 'Running fresh-state Secure Boot, TPM enrollment, and signed-container audit...'
run_boot 1
echo 'Running persistent TPM-unlock and signed-container audit with the same state...'
run_boot 2
echo 'ParticleOS two-boot VM audit passed; both guests and TPM emulators are stopped.'
