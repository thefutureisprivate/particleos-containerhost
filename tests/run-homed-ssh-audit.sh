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
audit_timeout=${HOMED_SSH_VM_TIMEOUT:-300}
audit_tmpdir=${HOMED_SSH_VM_TMPDIR:-$artifact_directory}
keep_failed=${HOMED_SSH_VM_KEEP_FAILED:-0}
vm_display=${HOMED_SSH_VM_DISPLAY:-gtk}

[[ $audit_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'HOMED_SSH_VM_TIMEOUT must be a positive number of seconds' >&2
    exit 2
}
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'HOMED_SSH_VM_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
[[ $vm_display == none || $vm_display == gtk ]] || {
    echo 'HOMED_SSH_VM_DISPLAY must be none or gtk' >&2
    exit 2
}
[[ -r /dev/kvm && -w /dev/kvm ]] || { echo '/dev/kvm is unavailable' >&2; exit 1; }
for command in awk base64 cp find grep mktemp python3 qemu-system-x86_64 \
        realpath seq ssh ssh-keygen swtpm tail timeout tr truncate zstd; do
    command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

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

scratch=$(mktemp -d "$audit_tmpdir/.particleos-homed-ssh-audit.XXXXXXXX")
qemu_pid=
swtpm_pid_file=$scratch/swtpm.pid

stop_qemu() {
    local command_line=
    local process_state=
    [[ $qemu_pid =~ ^[1-9][0-9]*$ && -r /proc/$qemu_pid/cmdline ]] || return 0
    command_line=$(tr '\0' ' ' <"/proc/$qemu_pid/cmdline")
    [[ $command_line == *"$scratch/"* ]] || return 0
    kill "$qemu_pid" 2>/dev/null || true
    for _ in {1..30}; do
        [[ ! -e /proc/$qemu_pid ]] && return 0
        process_state=$(awk '$1 == "State:" { print $2 }' "/proc/$qemu_pid/status") || return 0
        [[ $process_state == Z ]] && return 0
        sleep 0.1
    done
    kill -KILL "$qemu_pid" 2>/dev/null || true
}

reap_qemu() {
    [[ $qemu_pid =~ ^[1-9][0-9]*$ ]] || return 0
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=
}

stop_tpm() {
    local command_line=
    local pid=
    if [[ -s $swtpm_pid_file ]]; then
        read -r pid <"$swtpm_pid_file" || true
    fi
    [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/cmdline ]] || return 0
    command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    [[ $command_line == *"$scratch/"* ]] || return 0
    kill "$pid" 2>/dev/null || true
    for _ in {1..20}; do
        [[ ! -e /proc/$pid ]] && return 0
        sleep 0.1
    done
    if [[ -r /proc/$pid/comm && $(<"/proc/$pid/comm") == swtpm ]]; then
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    stop_qemu
    reap_qemu
    stop_tpm
    rm -rf -- "$snapshot_root"
    if ((status != 0)) && [[ $keep_failed == 1 ]]; then
        echo "Preserved failed homed SSH audit state: $scratch" >&2
    elif [[ -n ${scratch:-} && -d $scratch &&
            ${scratch##*/} == .particleos-homed-ssh-audit.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

disk=$scratch/particleos.raw
ovmf_vars=$scratch/ovmf-vars.bin
tpm_state=$scratch/tpm
log=$scratch/boot.log
mkdir -m 0700 "$tpm_state"
cp --reflink=auto --sparse=always "$ovmf_vars_source" "$ovmf_vars"
zstd --sparse -q -d -f -o "$disk" "${compressed_images[0]}"
truncate -s 16G "$disk"
ssh-keygen -q -t ed25519 -N '' -f "$scratch/id_ed25519"

homed_dropin=$(base64 -w0 "$repository/tests/homed-ssh-firstboot-audit.conf")
homed_audit=$(base64 -w0 "$repository/tests/homed-ssh-firstboot-audit")
authorized_key=$(base64 -w0 "$scratch/id_ed25519.pub")
pcrlock_audit=$(base64 -w0 "$repository/tests/pcrlock-enroll-audit.conf")
root_password=$(printf particleos | base64 -w0)
firstboot_timezone=$(printf Etc/UTC | base64 -w0)
ssh_port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')

start_tpm() {
    local socket=$1
    rm -f -- "$swtpm_pid_file"
    swtpm socket --tpm2 --tpmstate "dir=$tpm_state" \
        --ctrl "type=unixio,path=$socket" --pid "file=$swtpm_pid_file" \
        --log "file=$scratch/swtpm.log" --daemon --terminate
}

qemu_arguments=(
    -name "particleos-homed-ssh-audit-$$"
    -machine 'q35,smm=on,accel=kvm'
    -cpu host
    -m 2048
    -smp 2
    -global 'driver=cfi.pflash01,property=secure,value=on'
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code"
    -drive "if=pflash,format=raw,unit=1,file=$ovmf_vars"
    -drive "if=virtio,format=raw,file=$disk"
    -device 'tpm-tis,tpmdev=tpm0'
    -device 'virtio-net-pci,netdev=net0'
    -display "$vm_display"
    -serial "file:$log"
    -monitor none
    -smbios 'type=11,value=io.systemd.stub.kernel-cmdline-extra=systemd.mask=serial-getty@ttyS0.service'
    -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-audit=$homed_dropin"
    -smbios "type=11,value=io.systemd.credential.binary:homed-ssh-firstboot-audit=$homed_audit"
    -smbios "type=11,value=io.systemd.credential.binary:homed-ssh-authorized-key=$authorized_key"
    -smbios "type=11,value=io.systemd.credential.binary:systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit=$pcrlock_audit"
    -smbios "type=11,value=io.systemd.credential.binary:passwd.plaintext-password.root=$root_password"
    -smbios "type=11,value=io.systemd.credential.binary:firstboot.timezone=$firstboot_timezone"
)

echo 'Staging the PCR 7+11 policy before provisioning the homed account...'
tpm_socket=$scratch/tpm-enroll.sock
start_tpm "$tpm_socket"
if ! timeout --foreground --signal=TERM --kill-after=15s "$audit_timeout" \
        qemu-system-x86_64 "${qemu_arguments[@]}" \
        -chardev "socket,id=chrtpm,path=$tpm_socket" \
        -tpmdev emulator,id=tpm0,chardev=chrtpm \
        -netdev user,id=net0 -no-reboot; then
    tail -200 "$log" >&2 || true
    echo 'homed SSH enrollment boot did not stop cleanly' >&2
    exit 1
fi
stop_tpm
grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_STAGED ' "$log" || {
    tail -200 "$log" >&2
    echo 'PCR policy enrollment did not stage' >&2
    exit 1
}

echo 'Booting with an inactive homed account and key-only SSH enabled...'
: >"$log"
tpm_socket=$scratch/tpm-ssh.sock
start_tpm "$tpm_socket"
qemu-system-x86_64 "${qemu_arguments[@]}" \
    -chardev "socket,id=chrtpm,path=$tpm_socket" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" &
qemu_pid=$!

for _ in $(seq 1 "$audit_timeout"); do
    grep -q '^PARTICLEOS_HOMED_SSH_READY user=particleadmin state=inactive' "$log" 2>/dev/null && break
    [[ -e /proc/$qemu_pid ]] || break
    sleep 1
done
grep -q '^PARTICLEOS_HOMED_SSH_READY user=particleadmin state=inactive' "$log" || {
    tail -240 "$log" >&2 || true
    echo 'guest did not expose an inactive homed account over SSH' >&2
    exit 1
}

"$repository/tests/homed-ssh-expect.py" "$ssh_port" "$scratch/id_ed25519" \
    'ParticleOS-Test-SSH-261!'

stop_qemu
reap_qemu
stop_tpm
echo 'ParticleOS homed SSH unlock audit passed; the guest and TPM emulator are stopped.'
