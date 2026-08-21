#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 SSH_PORT PRIVATE_KEY PASSWORD" >&2
    exit 2
fi

port=$1
private_key=$2
password=$3
timeout_seconds=${HOMED_SSH_EXPECT_TIMEOUT:-90}
transcript=$(mktemp /tmp/particleos-homed-ssh-expect.XXXXXXXX)
ssh_pid=
ssh_input_fd=
ssh_output_fd=

# shellcheck disable=SC2329 # Invoked through the EXIT trap.
cleanup() {
    local status=$?
    if [[ $ssh_pid =~ ^[1-9][0-9]*$ ]] && process_running "$ssh_pid"; then
        kill -TERM "$ssh_pid" 2>/dev/null || true
        wait "$ssh_pid" 2>/dev/null || true
    fi
    [[ -z $ssh_input_fd ]] || exec {ssh_input_fd}>&-
    [[ -z $ssh_output_fd ]] || exec {ssh_output_fd}<&-
    rm -f -- "$transcript"
    exit "$status"
}
trap cleanup EXIT

fail() {
    cat "$transcript" >&2
    printf 'homed SSH audit failed: %s\n' "$*" >&2
    exit 1
}

process_running() {
    local pid=$1 state
    [[ -r /proc/$pid/status ]] || return 1
    state=$(awk '$1 == "State:" { print $2 }' "/proc/$pid/status" 2>/dev/null) || return 1
    [[ $state != Z ]]
}

coproc HOMED_SSH {
    ssh -tt \
        -p "$port" \
        -i "$private_key" \
        -o BatchMode=no \
        -o IdentitiesOnly=yes \
        -o PasswordAuthentication=no \
        -o KbdInteractiveAuthentication=no \
        -o PreferredAuthentications=publickey \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o GlobalKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        particleadmin@127.0.0.1 2>&1
}
# Bash closes the descriptors stored in the special coproc array as soon as
# the child exits. Own duplicates so the final SSH response can still be
# drained before its exit status is evaluated.
exec {ssh_output_fd}<&"${HOMED_SSH[0]}"
exec {ssh_input_fd}>&"${HOMED_SSH[1]}"
ssh_pid=$HOMED_SSH_PID
deadline=$((SECONDS + timeout_seconds))
buffer=
password_sent=0
command_sent=0
success_seen=0

while ((SECONDS < deadline)); do
    if IFS= read -r -t 0.5 -N 1 -u "$ssh_output_fd" character; then
        printf '%s' "$character" >>"$transcript"
        buffer+=$character
        ((${#buffer} <= 131072)) || buffer=${buffer: -65536}
        lower=${buffer,,}
        if ((password_sent == 0)) &&
                [[ $lower == *'please enter password for user particleadmin'* ]]; then
            printf '%s\n' "$password" >&"$ssh_input_fd"
            password_sent=1
        fi
        if ((password_sent == 1 && command_sent == 0)) &&
                [[ $buffer == *'$ ' || $buffer == *'# ' ]]; then
            printf '%s\n' \
                "printf 'PARTICLEOS_HOMED_SSH_UNLOCK_PASS uid=%s home=%s\\n' \"\$(id -u)\" \"\$HOME\"; journalctl --boot --no-pager --output=cat _TRANSPORT=audit | grep -Eiq 'avc:.*denied.*(sshd|homed|homework|userdb|fallback)' && printf 'PARTICLEOS_HOMED_SSH_AVC_FAIL\\n' || printf 'PARTICLEOS_HOMED_SSH_AVC_PASS\\n'; exit" \
                >&"$ssh_input_fd"
            command_sent=1
        fi
        if [[ $buffer =~ PARTICLEOS_HOMED_SSH_UNLOCK_PASS[[:space:]]uid=[0-9]+[[:space:]]home=/home/particleadmin ]] &&
                [[ $buffer == *'PARTICLEOS_HOMED_SSH_AVC_PASS'* ]]; then
            success_seen=1
        fi
        [[ $buffer != *'PARTICLEOS_HOMED_SSH_AVC_FAIL'* ]] ||
            fail 'SELinux denied the SSH/homed login path'
    fi

    if ! process_running "$ssh_pid"; then
        # A short final response can remain readable after ssh has already
        # become a zombie or exited. Drain it before judging the transcript.
        while IFS= read -r -t 0.1 -N 1 -u "$ssh_output_fd" character; do
            printf '%s' "$character" >>"$transcript"
            buffer+=$character
            ((${#buffer} <= 131072)) || buffer=${buffer: -65536}
        done
        if [[ $buffer =~ PARTICLEOS_HOMED_SSH_UNLOCK_PASS[[:space:]]uid=[0-9]+[[:space:]]home=/home/particleadmin ]] &&
                [[ $buffer == *'PARTICLEOS_HOMED_SSH_AVC_PASS'* ]]; then
            success_seen=1
        fi
        [[ $buffer != *'PARTICLEOS_HOMED_SSH_AVC_FAIL'* ]] ||
            fail 'SELinux denied the SSH/homed login path'
        set +e
        wait "$ssh_pid"
        status=$?
        set -e
        ssh_pid=
        if ((success_seen == 1 && status == 0)); then
            cat "$transcript"
            exit 0
        fi
        fail "SSH exited before proving unlock (status $status)"
    fi
done

fail 'timed out waiting for the homed unlock'
