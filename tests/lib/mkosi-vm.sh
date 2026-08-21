#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# Shared mkosi VM launcher for the local integration tests. Callers own their
# disk copy, enrolled firmware-variable source, persistent swtpm state, and
# cleanup trap. mkosi owns the VM process, firmware selection, primary disk,
# credentials, resources, and display.

declare -ag MKOSI_VM_COMMAND=()

mkosi_vm_require() {
    local command
    for command in mkosi swtpm; do
        command -v "$command" >/dev/null || {
            printf 'missing required VM command: %s\n' "$command" >&2
            return 1
        }
    done
    [[ -r /dev/kvm && -w /dev/kvm ]] || {
        echo '/dev/kvm is unavailable' >&2
        return 1
    }
    [[ $(mkosi --version) == 'mkosi 26' ]] || {
        echo 'local VM tests require mkosi 26' >&2
        return 1
    }
}

mkosi_vm_console() {
    case $1 in
        none) printf '%s\n' native ;;
        gui) printf '%s\n' gui ;;
        *)
            echo 'VM display mode must be none or gui' >&2
            return 2
            ;;
    esac
}

mkosi_vm_start_tpm() {
    local state_directory=$1 socket=$2 pid_file=$3 log=$4

    mkdir -p "$state_directory"
    chmod 0700 "$state_directory"
    rm -f -- "$socket" "$pid_file"
    swtpm socket \
        --tpm2 \
        --tpmstate "dir=$state_directory" \
        --ctrl "type=unixio,path=$socket" \
        --pid "file=$pid_file" \
        --log "file=$log" \
        --daemon \
        --terminate
}

mkosi_vm_stop_tpm() {
    local pid_file=$1 scope=$2 command_line='' pid=''

    if [[ -s $pid_file ]]; then
        read -r pid <"$pid_file" || true
    fi
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/comm &&
            -r /proc/$pid/cmdline ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$pid/cmdline")
    fi
    if [[ $command_line == *"$scope/"* && $(<"/proc/$pid/comm") == swtpm ]]; then
        kill "$pid" 2>/dev/null || true
        for _ in {1..20}; do
            [[ ! -e /proc/$pid ]] && return 0
            sleep 0.1
        done
        if [[ -r /proc/$pid/comm && $(<"/proc/$pid/comm") == swtpm ]]; then
            kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
}

mkosi_vm_stop() {
    local wrapper_pid=$1 scope=$2 machine=$3
    local command_line='' comm='' process process_pid

    if [[ $wrapper_pid =~ ^[1-9][0-9]*$ && -r /proc/$wrapper_pid/cmdline ]]; then
        command_line=$(tr '\0' ' ' <"/proc/$wrapper_pid/cmdline")
        if [[ $command_line == *'mkosi'* && $command_line == *"$scope/"* ]]; then
            kill -TERM "$wrapper_pid" 2>/dev/null || true
            for _ in {1..30}; do
                [[ ! -e /proc/$wrapper_pid ]] && break
                sleep 0.1
            done
            [[ ! -e /proc/$wrapper_pid ]] || kill -KILL "$wrapper_pid" 2>/dev/null || true
        fi
    fi

    # mkosi normally tears down QEMU with its transient scope. This bounded,
    # identity-checked sweep is a final guard for an interrupted wrapper.
    for process in /proc/[1-9]*; do
        [[ -r $process/comm && -r $process/cmdline ]] || continue
        read -r comm <"$process/comm" || continue
        [[ $comm == qemu-system-x86 ]] || continue
        command_line=$(tr '\0' ' ' <"$process/cmdline")
        [[ $command_line == *"$scope/"* && $command_line == *"$machine"* ]] || continue
        process_pid=${process##*/}
        kill -TERM "$process_pid" 2>/dev/null || true
    done
    for _ in {1..30}; do
        local found=0
        for process in /proc/[1-9]*; do
            [[ -r $process/comm && -r $process/cmdline ]] || continue
            read -r comm <"$process/comm" || continue
            [[ $comm == qemu-system-x86 ]] || continue
            command_line=$(tr '\0' ' ' <"$process/cmdline")
            [[ $command_line == *"$scope/"* && $command_line == *"$machine"* ]] || continue
            found=1
            break
        done
        ((found == 0)) && return 0
        sleep 0.1
    done
    for process in /proc/[1-9]*; do
        [[ -r $process/comm && -r $process/cmdline ]] || continue
        read -r comm <"$process/comm" || continue
        [[ $comm == qemu-system-x86 ]] || continue
        command_line=$(tr '\0' ' ' <"$process/cmdline")
        [[ $command_line == *"$scope/"* && $command_line == *"$machine"* ]] || continue
        kill -KILL "${process##*/}" 2>/dev/null || true
    done
}

mkosi_vm_build_command() {
    if (($# < 9)); then
        echo 'mkosi_vm_build_command requires repository, disk, firmware variables, machine, console, credentials, kernel command line, TPM socket, and serial target' >&2
        return 2
    fi

    local repository=$1 disk=$2 firmware_variables=$3 machine=$4 console=$5
    local credentials=$6 kernel_command_line=$7 tpm_socket=$8 serial_target=$9
    local output_alias output_alias_path output_directory output_name
    shift 9

    output_directory=$(dirname "$disk")
    output_name=$(basename "$disk")
    [[ $output_name == *.raw ]] || {
        echo "mkosi VM disk must use a .raw suffix: $disk" >&2
        return 2
    }
    output_alias=${output_name%.raw}
    output_alias_path=$output_directory/$output_alias
    [[ -f $disk && -f $firmware_variables && -S $tpm_socket ]] || {
        echo 'mkosi VM disk, firmware variables, or TPM socket is unavailable' >&2
        return 1
    }
    [[ -z $credentials || -d $credentials ]] || {
        echo "mkosi VM credential directory is unavailable: $credentials" >&2
        return 1
    }
    [[ -x $repository/tests/libexec/mkosi-vm/qemu-system-x86_64 ]] || {
        echo 'mkosi VM QEMU display wrapper is unavailable' >&2
        return 1
    }
    [[ " $kernel_command_line " != *' console='* ]] || {
        echo 'mkosi VM callers must not override the test console' >&2
        return 2
    }
    kernel_command_line="${kernel_command_line:+$kernel_command_line }console=ttyS0,115200"

    # mkosi builds a stable Output= symlink next to its format-suffixed disk.
    # Its VM verb requires both names even though QEMU opens the .raw target.
    # Recreate that native output layout for an authenticated prebuilt disk.
    if [[ -L $output_alias_path ]]; then
        [[ $(readlink -- "$output_alias_path") == "$output_name" ]] || {
            echo "mkosi VM output alias has an unexpected target: $output_alias_path" >&2
            return 1
        }
    elif [[ -e $output_alias_path ]]; then
        echo "mkosi VM output alias already exists and is not a symlink: $output_alias_path" >&2
        return 1
    else
        ln -s -- "$output_name" "$output_alias_path"
    fi

    MKOSI_VM_COMMAND=(
        mkosi
        --directory "$repository"
        --dependency=
        --tools-tree=
        --sandbox-tree=
        --extra-search-path "$repository/tests/libexec/mkosi-vm"
        --repository-key-check=no
        --secure-boot=no
        --bootable=no
        --format disk
        --output "$output_alias"
        --output-directory "$output_directory"
        --compress-output=no
        --image-version=0
        --ephemeral=no
        --runtime-size=16G
        --runtime-network=none
        --runtime-build-sources=no
        --bind-user=no
        --vmm=qemu
        --machine "$machine"
        --register=no
        --console "$console"
        --cpus=2
        --ram=2G
        --kvm=yes
        --vsock=no
        --tpm=no
        --firmware=uefi-secure-boot
        --firmware-variables "$firmware_variables"
        --credential=
        --kernel-command-line-extra=
    )
    [[ -z $credentials ]] || MKOSI_VM_COMMAND+=(--credential "$credentials")
    [[ -z $kernel_command_line ]] ||
        MKOSI_VM_COMMAND+=(--kernel-command-line-extra "$kernel_command_line")
    MKOSI_VM_COMMAND+=(
        vm --
        -name "$machine"
        # mkosi 26 otherwise copies this store for each invocation, discarding
        # A/B boot counts and LoaderEntryOneShot between lifecycle-test boots.
        # The QEMU wrapper consumes this test-only marker and substitutes only
        # mkosi's temporary pflash variable drive with the caller-owned copy.
        -particleos-test-firmware-variables "$firmware_variables"
        -chardev "socket,id=particleos-tpm,path=$tpm_socket"
        -tpmdev 'emulator,id=particleos-tpm0,chardev=particleos-tpm'
        -device 'tpm-tis,tpmdev=particleos-tpm0'
        -serial "$serial_target"
        "$@"
    )
}
