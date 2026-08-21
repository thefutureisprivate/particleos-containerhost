#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 ARTIFACT_DIRECTORY ENROLLED_OVMF_VARS" >&2
    exit 2
fi

repository=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=tests/lib/mkosi-vm.sh
source "$repository/tests/lib/mkosi-vm.sh"
artifact_directory=$(realpath "$1")
ovmf_vars_source=$(realpath "$2")
audit_timeout=${HOMED_SSH_VM_TIMEOUT:-300}
audit_tmpdir=${HOMED_SSH_VM_TMPDIR:-$artifact_directory}
keep_failed=${HOMED_SSH_VM_KEEP_FAILED:-0}
vm_display=${HOMED_SSH_VM_DISPLAY:-gui}

[[ $audit_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'HOMED_SSH_VM_TIMEOUT must be a positive number of seconds' >&2
    exit 2
}
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'HOMED_SSH_VM_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
vm_console=$(mkosi_vm_console "$vm_display")
mkosi_vm_require
for command in cp find grep install mktemp realpath ss ssh ssh-keygen tail \
        timeout truncate zstd; do
    command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -d $audit_tmpdir && -w $audit_tmpdir ]] || {
    echo "homed SSH audit directory is not writable: $audit_tmpdir" >&2
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

scratch=$(mktemp -d "$audit_tmpdir/.particleos-homed-ssh-audit.XXXXXXXX")
socket_directory=$(mktemp -d /tmp/phs.XXXXXXXX)
mkosi_pid=
swtpm_pid_file=$scratch/swtpm.pid
active_machine=

cleanup() {
    local status=$?
    mkosi_vm_stop "${mkosi_pid:-0}" "$scratch" "${active_machine:-particleos-homed-ssh-audit}"
    [[ -z ${mkosi_pid:-} ]] || wait "$mkosi_pid" 2>/dev/null || true
    mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"
    rm -rf -- "$snapshot_root"
    if [[ -n ${socket_directory:-} && -d $socket_directory &&
            ${socket_directory##*/} == phs.* ]]; then
        rm -rf -- "$socket_directory"
    fi
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
credentials=$scratch/credentials
mkdir -m 0700 "$tpm_state" "$credentials"
cp --reflink=auto --sparse=always "$ovmf_vars_source" "$ovmf_vars"
zstd --sparse -q -d -f -o "$disk" "${compressed_images[0]}"
truncate -s 16G "$disk"
ssh-keygen -q -t ed25519 -N '' -f "$scratch/id_ed25519"
install -m 0600 "$repository/tests/homed-ssh-firstboot-audit.conf" "$credentials/systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-audit"
install -m 0600 "$repository/tests/homed-ssh-firstboot-audit" "$credentials/homed-ssh-firstboot-audit"
install -m 0600 "$scratch/id_ed25519.pub" "$credentials/homed-ssh-authorized-key"
install -m 0600 "$repository/tests/pcrlock-enroll-audit.conf" "$credentials/systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit"
printf '%s' particleos >"$credentials/passwd.plaintext-password.root"
printf '%s' Etc/UTC >"$credentials/firstboot.timezone"
chmod 0600 "$credentials/passwd.plaintext-password.root" "$credentials/firstboot.timezone"

pick_tcp_port() {
    local candidate
    for _ in {1..200}; do
        candidate=$((20000 + RANDOM % 30000))
        if ! ss -H -ltn "sport = :$candidate" | grep -q .; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    echo 'could not select an unused local SSH port' >&2
    return 1
}

start_guest() {
    local boot=$1 socket=$2 serial=$3
    shift 3
    active_machine="particleos-homed-ssh-audit-$$-$boot"
    mkosi_vm_start_tpm "$tpm_state" "$socket" "$swtpm_pid_file" "$scratch/swtpm-$boot.log"
    mkosi_vm_build_command "$repository" "$disk" "$ovmf_vars" "$active_machine" \
        "$vm_console" "$credentials" 'systemd.mask=serial-getty@ttyS0.service' \
        "$socket" "$serial" "$@"
}

ssh_port=$(pick_tcp_port)
echo 'Staging the PCR 7+11 policy before provisioning the homed account...'
tpm_socket=$socket_directory/enroll.sock
start_guest enroll "$tpm_socket" "file:$log" \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -no-reboot
set +e
timeout --foreground --signal=TERM --kill-after=15s "$audit_timeout" \
    "${MKOSI_VM_COMMAND[@]}"
status=$?
set -e
mkosi_vm_stop 0 "$scratch" "$active_machine"
mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"
if ((status != 0)); then
    tail -200 "$log" >&2 || true
    echo 'homed SSH enrollment mkosi VM did not stop cleanly' >&2
    exit 1
fi
grep -q 'PARTICLEOS_PCRLOCK_BOOTSTRAP_STAGED ' "$log" || {
    tail -200 "$log" >&2
    echo 'PCR policy enrollment did not stage' >&2
    exit 1
}

echo 'Booting with an inactive homed account and key-only SSH enabled...'
: >"$log"
tpm_socket=$socket_directory/ssh.sock
start_guest ssh "$tpm_socket" "file:$log" \
    -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$ssh_port-:22" \
    -device virtio-net-pci,netdev=net0
"${MKOSI_VM_COMMAND[@]}" >"$scratch/mkosi-ssh.log" 2>&1 &
mkosi_pid=$!

for ((attempt = 0; attempt < audit_timeout; attempt++)); do
    grep -q '^PARTICLEOS_HOMED_SSH_READY user=particleadmin state=inactive' "$log" 2>/dev/null && break
    [[ -e /proc/$mkosi_pid ]] || break
    sleep 1
done
grep -q '^PARTICLEOS_HOMED_SSH_READY user=particleadmin state=inactive' "$log" || {
    tail -240 "$log" >&2 || true
    tail -120 "$scratch/mkosi-ssh.log" >&2 || true
    echo 'guest did not expose an inactive homed account over SSH' >&2
    exit 1
}

"$repository/tests/homed-ssh-expect.sh" "$ssh_port" "$scratch/id_ed25519" \
    'ParticleOS-Test-SSH-261!'

mkosi_vm_stop "$mkosi_pid" "$scratch" "$active_machine"
wait "$mkosi_pid" 2>/dev/null || true
mkosi_pid=
mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"
echo 'ParticleOS homed SSH unlock audit passed via mkosi VM; the guest and TPM emulator are stopped.'
