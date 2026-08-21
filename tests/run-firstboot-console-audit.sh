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
audit_timeout=${FIRSTBOOT_VM_TIMEOUT:-420}
audit_tmpdir=${FIRSTBOOT_VM_TMPDIR:-$artifact_directory}
keep_failed=${FIRSTBOOT_VM_KEEP_FAILED:-0}

[[ $audit_timeout =~ ^[1-9][0-9]*$ ]] || {
    echo 'FIRSTBOOT_VM_TIMEOUT must be a positive number of seconds' >&2
    exit 2
}
[[ $keep_failed == 0 || $keep_failed == 1 ]] || {
    echo 'FIRSTBOOT_VM_KEEP_FAILED must be 0 or 1' >&2
    exit 2
}
mkosi_vm_require
for command in cp find grep install jq mkfifo mktemp realpath socat tail tesseract \
        truncate zstd; do
    command -v "$command" >/dev/null || {
        echo "missing required command: $command" >&2
        exit 1
    }
done
[[ -f $ovmf_vars_source ]] || { echo "missing OVMF variable store: $ovmf_vars_source" >&2; exit 1; }
[[ -d $audit_tmpdir && -w $audit_tmpdir ]] || {
    echo "first-boot audit directory is not writable: $audit_tmpdir" >&2
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

scratch=$(mktemp -d "$audit_tmpdir/.particleos-firstboot-audit.XXXXXXXX")
swtpm_pid_file=$scratch/swtpm.pid
mkosi_pid=
qmp_pid=
qmp_input_fd=
qmp_output_fd=
serial_input_fd=
machine="particleos-firstboot-audit-$$"

cleanup() {
    local status=$?
    if [[ $qmp_pid =~ ^[1-9][0-9]*$ ]]; then
        kill "$qmp_pid" 2>/dev/null || true
        wait "$qmp_pid" 2>/dev/null || true
    fi
    [[ -z $serial_input_fd ]] || exec {serial_input_fd}>&-
    mkosi_vm_stop "${mkosi_pid:-0}" "$scratch" "$machine"
    [[ -z ${mkosi_pid:-} ]] || wait "$mkosi_pid" 2>/dev/null || true
    mkosi_vm_stop_tpm "$swtpm_pid_file" "$scratch"
    rm -rf -- "$snapshot_root"
    if ((status != 0)) && [[ $keep_failed == 1 ]]; then
        echo "Preserved failed first-boot audit state: $scratch" >&2
    elif [[ -n ${scratch:-} && -d $scratch &&
            ${scratch##*/} == .particleos-firstboot-audit.* ]]; then
        rm -rf -- "$scratch"
    fi
    exit "$status"
}
trap cleanup EXIT

fail() {
    tail -240 "$log" >&2 2>/dev/null || true
    printf 'native first-boot console audit failed: %s\n' "$*" >&2
    exit 1
}

disk=$scratch/particleos.raw
ovmf_vars=$scratch/ovmf-vars.bin
tpm_state=$scratch/tpm
tpm_socket=$scratch/tpm.sock
log=$scratch/firstboot.log
qmp_socket=$scratch/qmp.sock
vga_screenshot=$scratch/firstboot-vga.ppm
serial_input=$scratch/serial.input
credentials=$scratch/credentials
mkdir -m 0700 "$tpm_state" "$credentials"
cp --reflink=auto --sparse=always "$ovmf_vars_source" "$ovmf_vars"
zstd --sparse -q -d -f -o "$disk" "${compressed_images[0]}"
truncate -s 16G "$disk"
install -m 0600 "$repository/tests/firstboot-console-audit.conf" "$credentials/systemd.unit-dropin.getty@tty1.service~90-particleos-firstboot-audit"
install -m 0600 "$repository/tests/audit-activate.conf" "$credentials/systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit"
install -m 0600 "$repository/tests/pcrlock-enroll-audit.conf" "$credentials/systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit"
install -m 0600 "$repository/tests/firstboot-console-audit" "$credentials/firstboot-console-audit"

qmp_read_response() {
    local response
    while IFS= read -r -t 8 -u "$qmp_output_fd" response; do
        jq -e 'has("event")' <<<"$response" >/dev/null 2>&1 && continue
        jq -e 'has("error") | not' <<<"$response" >/dev/null || {
            printf 'QMP request failed: %s\n' "$response" >&2
            return 1
        }
        return 0
    done
    echo 'QMP response timed out' >&2
    return 1
}

qmp_execute() {
    printf '%s\n' "$1" >&"$qmp_input_fd"
    qmp_read_response
}

qmp_connect() {
    local greeting request
    while [[ ! -S $qmp_socket ]]; do
        process_running "$mkosi_pid" || fail 'mkosi VM exited before QMP became available'
        ((SECONDS < deadline)) || fail 'QMP socket did not appear'
        sleep 0.05
    done
    coproc QMP_CLIENT { socat - UNIX-CONNECT:"$qmp_socket"; }
    qmp_output_fd=${QMP_CLIENT[0]}
    qmp_input_fd=${QMP_CLIENT[1]}
    qmp_pid=$QMP_CLIENT_PID
    IFS= read -r -t 8 -u "$qmp_output_fd" greeting || fail 'QMP greeting timed out'
    jq -e 'has("QMP")' <<<"$greeting" >/dev/null || fail 'invalid QMP greeting'
    request='{"execute":"qmp_capabilities"}'
    qmp_execute "$request" || fail 'QMP capability negotiation failed'
}

qmp_key() {
    local code=$1 shifted=${2:-0} request
    if [[ $shifted == 1 ]]; then
        request=$(jq -cn --arg code "$code" '{execute:"input-send-event",arguments:{events:[
            {type:"key",data:{down:true,key:{type:"qcode",data:"shift"}}},
            {type:"key",data:{down:true,key:{type:"qcode",data:$code}}},
            {type:"key",data:{down:false,key:{type:"qcode",data:$code}}},
            {type:"key",data:{down:false,key:{type:"qcode",data:"shift"}}}
        ]}}')
    else
        request=$(jq -cn --arg code "$code" '{execute:"input-send-event",arguments:{events:[
            {type:"key",data:{down:true,key:{type:"qcode",data:$code}}},
            {type:"key",data:{down:false,key:{type:"qcode",data:$code}}}
        ]}}')
    fi
    qmp_execute "$request"
    sleep 0.015
}

qmp_type_line() {
    local value=$1 character code shifted index
    for ((index = 0; index < ${#value}; index++)); do
        character=${value:index:1}
        shifted=0
        case $character in
            [a-z]) code=$character ;;
            [A-Z]) code=${character,,}; shifted=1 ;;
            [0-9]) code=$character ;;
            /) code=slash ;;
            -) code=minus ;;
            *) fail "unsupported VGA input character: $character" ;;
        esac
        qmp_key "$code" "$shifted" || fail "could not type VGA character: $character"
    done
    qmp_key ret || fail 'could not submit VGA response'
}

screenshot_text() {
    local request
    request=$(jq -cn --arg file "$vga_screenshot" \
        '{execute:"screendump",arguments:{filename:$file}}')
    qmp_execute "$request" || return 1
    tesseract "$vga_screenshot" stdout --psm 6 2>/dev/null |
        tr '[:upper:]' '[:lower:]' |
        tr '\n' ' ' |
        sed -E 's/[[:space:]]+/ /g; s/passuord/password/g; s/neu /new /g'
}

process_running() {
    local pid=$1 state
    [[ -r /proc/$pid/status ]] || return 1
    state=$(awk '$1 == "State:" { print $2 }' "/proc/$pid/status") || return 1
    [[ $state != Z ]]
}

wait_log_count() {
    local needle=$1 expected=$2 count
    while ((SECONDS < deadline)); do
        count=$({ grep -aoF -- "$needle" "$log" 2>/dev/null || true; } | wc -l)
        ((count >= expected)) && return 0
        process_running "$mkosi_pid" || return 1
        sleep 0.1
    done
    return 1
}

mkosi_vm_start_tpm "$tpm_state" "$tpm_socket" "$swtpm_pid_file" "$scratch/swtpm.log"
mkosi_vm_build_command "$repository" "$disk" "$ovmf_vars" "$machine" gui \
    "$credentials" \
    'systemd.mask=serial-getty@ttyS0.service systemd.mask=systemd-sysupdate.timer systemd.mask=systemd-sysupdate-reboot.timer' \
    "$tpm_socket" stdio \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -qmp "unix:$qmp_socket,server=on,wait=off" \
    -monitor none

mkfifo -m 0600 "$serial_input"
exec {serial_input_fd}<>"$serial_input"
"${MKOSI_VM_COMMAND[@]}" <"$serial_input" >"$log" 2>&1 &
mkosi_pid=$!
deadline=$((SECONDS + audit_timeout))
qmp_connect

firmware_entry_visible=0
answers=('VgaSetup261Secure' 'VgaSetup261Secure' 'Etc/UTC' particleadmin 'VgaAdmin261Secure' 'VgaAdmin261Secure')
for index in {0..5}; do
    observed=0
    while ((SECONDS < deadline)); do
        process_running "$mkosi_pid" || fail "mkosi VM exited before VGA prompt $((index + 1))"
        screen=$(screenshot_text || true)
        if ((firmware_entry_visible == 0)) &&
                [[ $screen == *'reboot into'* && $screen == *'firmware interface'* ]]; then
            firmware_entry_visible=1
            echo 'SYSTEMD_BOOT_FIRMWARE_ENTRY_VISIBLE'
        fi
        case $index in
            0)
                if [[ $screen == *'enter the new root password'* && $screen == *'empty to skip'* ]]; then
                    observed=1
                fi
                ;;
            1)
                if [[ $screen == *'enter the new root password again'* ]]; then
                    observed=1
                fi
                ;;
            2)
                if [[ $screen == *'enter the new timezone'* && $screen == *'name or number'* ]]; then
                    observed=1
                fi
                ;;
            3)
                if [[ $screen == *'enter user name'* && $screen == *'create'* ]]; then
                    observed=1
                fi
                ;;
            4)
                if [[ $screen == *'enter new password'* && $screen == *'particleadmin'* && $screen != *'repeat'* ]]; then
                    observed=1
                fi
                ;;
            5)
                if [[ $screen == *'enter new password'* && $screen == *'particleadmin'* && $screen == *'repeat'* ]]; then
                    observed=1
                fi
                ;;
        esac
        if ((observed)); then
            printf 'FIRSTBOOT_VGA_PROMPT_VISIBLE index=%d\n' "$((index + 1))"
            qmp_type_line "${answers[index]}"
            break
        fi
        sleep 0.5
    done
    ((observed)) || fail "VGA first-boot prompt $((index + 1)) was not observed"
done
((firmware_entry_visible)) || fail 'reboot-into-firmware entry was not visible on VGA'

wait_log_count 'login:' 1 || fail 'serial login prompt was not observed'
printf 'particleadmin\n' >&"$serial_input_fd"
wait_log_count 'Password:' 1 || fail 'serial login password prompt was not observed'
printf 'VgaAdmin261Secure\n' >&"$serial_input_fd"
wait_log_count 'PARTICLEOS_ADMIN_SHELL_READY' 1 || fail 'administrator shell did not become ready'
printf '%s\n' \
    'run0 --no-ask-password --pipe /usr/bin/true && exit 97 || echo PARTICLEOS_RUN0_NOAUTH_DENIED; run0 --pipe /usr/bin/bash /run/particleos-firstboot-run0-audit || { echo PARTICLEOS_RUN0_AUTH_FAILED; systemctl --no-pager --full status polkit.service systemd-homed.service systemd-logind.service; journalctl --boot --no-pager --output=short-monotonic -u polkit.service -u systemd-homed.service -u systemd-logind.service; journalctl --boot --no-pager --output=cat _TRANSPORT=audit | grep -Ei "(avc:.*denied|polkit-agent-helper|unit=run-p|acct=.?particleadmin)"; }; exit' \
    >&"$serial_input_fd"
wait_log_count 'Password:' 2 || fail 'run0 authentication prompt was not observed'
printf 'VgaAdmin261Secure\n' >&"$serial_input_fd"
wait_log_count 'PARTICLEOS_FIRSTBOOT_CONSOLE_PASS ' 1 || fail 'guest audit did not report success'

while process_running "$mkosi_pid" && ((SECONDS < deadline)); do sleep 0.1; done
process_running "$mkosi_pid" && fail 'mkosi VM did not power off after the console audit'
set +e
wait "$mkosi_pid"
status=$?
set -e
mkosi_pid=
((status == 0)) || fail "mkosi VM exited with status $status"

grep -q 'PARTICLEOS_RUN0_NOAUTH_DENIED' "$log" || fail 'run0 did not report its unauthenticated denial'
grep -q '==== AUTHENTICATION COMPLETE ====' "$log" || fail 'run0 did not complete interactive authentication'
! grep -q 'PARTICLEOS_FIRSTBOOT_CONSOLE_FAIL ' "$log" || fail 'guest audit reported failure'
grep 'PARTICLEOS_FIRSTBOOT_CONSOLE_PASS ' "$log"
echo 'ParticleOS systemd-boot firmware entry, native VGA provisioning, and authenticated run0 mkosi VM audit passed; guest and TPM emulator are stopped.'
