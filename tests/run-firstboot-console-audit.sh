#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY ENROLLED_OVMF_VARS [OVMF_CODE]" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
artifact_directory=$(realpath "$1")
ovmf_vars_source=$(realpath "$2")
ovmf_code=${3:-/usr/share/qemu/ovmf-x86_64-smm-code.bin}
ovmf_code=$(realpath "$ovmf_code")
audit_tmpdir=${FIRSTBOOT_VM_TMPDIR:-$artifact_directory}
keep_failed=${FIRSTBOOT_VM_KEEP_FAILED:-0}
vm_display=${FIRSTBOOT_VM_DISPLAY:-gtk}

[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'FIRSTBOOT_VM_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
[[ $vm_display == none || $vm_display == gtk ]] || {
    echo 'FIRSTBOOT_VM_DISPLAY must be none or gtk' >&2
    exit 2
}
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo '/dev/kvm is unavailable' >&2; exit 1; }
for command in base64 cp find mktemp pgrep pkill python3 qemu-system-x86_64 \
        realpath swtpm tail tr truncate zstd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -f $ovmf_code ]] || { echo "missing OVMF code image: $ovmf_code" >&2; exit 1; }
[[ -d $audit_tmpdir && -w $audit_tmpdir ]] || {
    echo "first-boot audit directory is not writable: $audit_tmpdir" >&2
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

scratch=$(mktemp -d "$audit_tmpdir/.particleos-firstboot-audit.XXXXXXXX")
swtpm_pid_file=$scratch/swtpm.pid
qemu_active=0

stop_tpm() {
    local command_line='' pid=''
    if [[ -s $swtpm_pid_file ]]; then
        read -r pid <"$swtpm_pid_file" || true
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/comm && -r /proc/$pid/cmdline ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    fi
    if [[ $command_line == *"$scratch/"* && $(<"/proc/$pid/comm") == swtpm ]]; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            [[ ! -e /proc/$pid ]] && break
            sleep 0.1
        done
        if [[ -r /proc/$pid/comm && $(<"/proc/$pid/comm") == swtpm ]]; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
}

stop_qemu() {
    local pattern="name particleos-firstboot-console-audit-$$"
    pkill -TERM -f "$pattern" 2>/dev/null || true
    for _ in {1..30}; do
        pgrep -f "$pattern" >/dev/null || return 0
        sleep 0.1
    done
    pkill -KILL -f "$pattern" 2>/dev/null || true
}

cleanup() {
    local status=$?
    ((qemu_active)) && stop_qemu
    stop_tpm
    if ((status != 0)) && [[ $keep_failed == 1 ]]; then
        echo "Preserved failed first-boot audit state: $scratch" >&2
    elif [[ -n ${scratch:-} && -d $scratch &&
            ${scratch##*/} == .particleos-firstboot-audit.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

disk=$scratch/particleos.raw
ovmf_vars=$scratch/ovmf-vars.bin
tpm_state=$scratch/tpm
tpm_socket=$scratch/tpm.sock
log=$scratch/firstboot.log
mkdir -m 0700 "$tpm_state"
cp --reflink=auto --sparse=always "$ovmf_vars_source" "$ovmf_vars"
zstd --sparse -q -d -f -o "$disk" "${compressed_images[0]}"
truncate -s 16G "$disk"

firstboot_serial=$(base64 -w0 "$repository/tests/firstboot-serial.conf")
audit_service=$(base64 -w0 "$repository/tests/firstboot-console-audit.conf")
audit_script=$(base64 -w0 "$repository/tests/firstboot-console-audit")
audit_activate=$(base64 -w0 "$repository/tests/audit-activate.conf")

swtpm socket \
    --tpm2 \
    --tpmstate "dir=$tpm_state" \
    --ctrl "type=unixio,path=$tpm_socket" \
    --pid "file=$swtpm_pid_file" \
    --log "file=$scratch/swtpm.log" \
    --daemon \
    --terminate

qemu_active=1
if ! "$repository/tests/firstboot-console-expect.py" "$log" -- \
        qemu-system-x86_64 \
        -name "particleos-firstboot-console-audit-$$" \
        -machine q35,smm=on,accel=kvm \
        -cpu host \
        -m 2048 \
        -smp 2 \
        -global driver=cfi.pflash01,property=secure,value=on \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars" \
        -drive "if=virtio,format=raw,file=$disk" \
        -chardev "socket,id=chrtpm,path=$tpm_socket" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -device tpm-tis,tpmdev=tpm0 \
        -netdev user,id=net0 \
        -device virtio-net-pci,netdev=net0 \
        -display "$vm_display" \
        -serial stdio \
        -monitor none \
        -smbios type=11,value='io.systemd.stub.kernel-cmdline-extra=systemd.mask=serial-getty@ttyS0.service systemd.mask=systemd-sysupdate.timer systemd.mask=systemd-sysupdate-reboot.timer' \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-firstboot.service~90-particleos-serial=$firstboot_serial" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-serial=$firstboot_serial" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.getty@tty1.service~90-particleos-firstboot-audit=$audit_service" \
        -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit=$audit_activate" \
        -smbios "type=11,value=io.systemd.credential.binary:firstboot-console-audit=$audit_script"; then
    qemu_active=0
    stop_tpm
    tail -240 "$log" >&2 || true
    echo 'native first-boot console audit failed' >&2
    exit 1
fi
qemu_active=0
stop_tpm

grep 'PARTICLEOS_FIRSTBOOT_CONSOLE_PASS ' "$log"
echo 'ParticleOS native root/timezone/homed provisioning and authenticated run0 audit passed; guest and TPM emulator are stopped.'
