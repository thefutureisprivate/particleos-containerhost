#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -uo pipefail

checks=0
failures=0

pass() {
    checks=$((checks + 1))
    printf 'ok %d - %s\n' "$checks" "$1"
}

fail() {
    checks=$((checks + 1))
    failures=$((failures + 1))
    printf 'not ok %d - %s\n' "$checks" "$1"
}

check() {
    local description=$1
    shift
    if "$@"; then pass "$description"; else fail "$description"; fi
}

check_grep() {
    local description=$1 pattern=$2 file=$3
    if grep -qE -- "$pattern" "$file"; then pass "$description"; else fail "$description"; fi
}

printf 'PARTICLEOS_VM_AUDIT_BEGIN\n'

if bootctl status 2>/dev/null | grep -qF 'Secure Boot: enabled'; then
    pass 'UEFI Secure Boot is enabled'
else
    fail 'UEFI Secure Boot is enabled'
fi
check_grep 'kernel lockdown is in confidentiality mode' '\[confidentiality\]' /sys/kernel/security/lockdown
check_grep 'IPE enforcement is requested by the signed UKI' '(^| )ipe\.enforce=1( |$)' /proc/cmdline
check_grep 'null-key boot credentials are rejected by the signed UKI' '(^| )systemd\.credentials_boot_policy=strict( |$)' /proc/cmdline
ipe_policy=
for active in /sys/kernel/security/ipe/policies/*/active; do
    if [[ -f $active && $(<"$active") == 1 ]]; then
        ipe_policy=${active%/active}/policy
        break
    fi
done
if [[ -n $ipe_policy ]]; then
    pass 'an IPE policy is active'
else
    fail 'an IPE policy is active'
fi
if [[ -n $ipe_policy ]] &&
        grep -qxF 'DEFAULT action=DENY' "$ipe_policy" &&
        grep -qxF 'DEFAULT op=EXECUTE action=ALLOW' "$ipe_policy" &&
        grep -qxF 'op=KMODULE dmverity_signature=TRUE action=ALLOW' "$ipe_policy" &&
        grep -qxF 'op=FIRMWARE dmverity_signature=TRUE action=ALLOW' "$ipe_policy"; then
    pass 'IPE defaults deny for kernel-fed objects while supporting systrap execution'
else
    fail 'IPE defaults deny for kernel-fed objects while supporting systrap execution'
fi
if [[ $(getenforce) == Enforcing ]]; then pass 'SELinux is enforcing'; else fail 'SELinux is enforcing'; fi
selinux_policy=/usr/lib/particleos/selinux/particleos-containerhost.cil
if grep -qxF '(type gvisor_t)' "$selinux_policy" &&
        grep -qxF '  (typeattributeset anonymous_exec_privileged_domain (.gvisor_t))' "$selinux_policy" &&
        grep -qxF '  (deny anonymous_exec_restricted_domain self (process (execmem execstack)))' "$selinux_policy" &&
        grep -qxF '  (deny anonymous_exec_restricted_domain .container_runtime_tmpfs_t' "$selinux_policy" &&
        grep -qxF '  (allow .gvisor_t self (process (ptrace)))' "$selinux_policy"; then
    pass 'SELinux reserves executable anonymous memory for the dedicated gVisor domain'
else
    fail 'SELinux reserves executable anonymous memory for the dedicated gVisor domain'
fi
if [[ $(sysctl -n kernel.yama.ptrace_scope) == 2 ]]; then
    pass 'Yama restricts ptrace to CAP_SYS_PTRACE'
else
    fail 'Yama restricts ptrace to CAP_SYS_PTRACE'
fi
if getsebool deny_ptrace 2>/dev/null | grep -q -- '--> on'; then
    pass 'SELinux globally denies ptrace outside explicit policy'
else
    fail 'SELinux globally denies ptrace outside explicit policy'
fi

usr_type=$(findmnt -n -o FSTYPE /usr 2>/dev/null || true)
usr_options=$(findmnt -n -o OPTIONS /usr 2>/dev/null || true)
if [[ $usr_type == erofs ]]; then pass '/usr uses EROFS'; else fail '/usr uses EROFS'; fi
for option in ro nodev nosuid; do
    if [[ ,$usr_options, == *,$option,* ]]; then
        pass "/usr is mounted $option"
    else
        fail "/usr is mounted $option"
    fi
done
if findmnt -n -o SOURCE / | grep -q '^/dev/mapper/root'; then
    pass 'persistent root is mounted from the encrypted mapper device'
else
    fail 'persistent root is mounted from the encrypted mapper device'
fi
root_options=$(findmnt -n -o OPTIONS / 2>/dev/null || true)
if [[ ,$root_options, == *,noexec,* ]]; then
    pass 'persistent root is mounted noexec'
else
    fail 'persistent root is mounted noexec'
fi

state=/dev/disk/by-partlabel/ParticleOS-Host-root
if [[ -b $state ]]; then pass 'persistent state partition exists'; else fail 'persistent state partition exists'; fi
luks_metadata=$(cryptsetup luksDump --dump-json-metadata "$state" 2>/dev/null || true)
luks_metadata_compact=$(tr -d '[:space:]' <<<"$luks_metadata")
if grep -qF '"tpm2_pcrlock":true' <<<"$luks_metadata_compact" &&
        ! grep -qF '"tpm2-pcrs":[7]' <<<"$luks_metadata_compact" &&
        [[ ! -e /var/lib/particleos/pcrlock-enrollment-pending ]]; then
    pass 'a later boot proved PCR7+11 before the PCR7 bootstrap token was retired'
else
    fail 'a later boot proved PCR7+11 before the PCR7 bootstrap token was retired'
fi
if grep -Eq '"pcr"[[:space:]]*:[[:space:]]*7([,}])' /var/lib/systemd/pcrlock.json &&
        grep -Eq '"pcr"[[:space:]]*:[[:space:]]*11([,}])' /var/lib/systemd/pcrlock.json &&
        [[ -f /var/lib/particleos/pcrlock-enrolled ]]; then
    pass 'the TPM NV policy strictly covers Secure Boot and the booted UKI'
else
    fail 'the TPM NV policy strictly covers Secure Boot and the booted UKI'
fi
unit=systemd-cryptsetup@root.service
if [[ $(systemctl show --property=Result --value "$unit" 2>/dev/null) == success ]]; then
    pass "$unit completed successfully"
else
    fail "$unit completed successfully"
fi

partition_types=$(lsblk -nr -o PARTTYPE)
for specification in \
    '8484680c-9521-48c6-9c11-b0720656f69e:2:/usr slots' \
    '77ff5f63-e7b6-4633-acf4-1565b864c0e6:2:verity slots' \
    'e7bb33fb-06cf-4e81-8273-e543b413e2e2:2:verity signature slots'; do
    IFS=: read -r type expected description <<<"$specification"
    count=$(grep -icx "$type" <<<"$partition_types")
    if [[ $count -eq $expected ]]; then pass "two A/B $description exist"; else fail "two A/B $description exist"; fi
done
check 'systemd-sysupdate can enumerate the A/B deployment' systemd-sysupdate list
if [[ $(stat -c '%C' /usr/lib/systemd/import-pubring.pgp 2>/dev/null) == \
        system_u:object_r:particleos_import_key_t:s0 ]]; then
    pass 'the immutable update trust key has an importd-readable label'
else
    fail 'the immutable update trust key has an importd-readable label'
fi
if [[ $(systemctl is-enabled systemd-sysupdate-reboot.timer 2>/dev/null) == enabled ]]; then
    pass 'staged updates have an automatic reboot timer'
else
    fail 'staged updates have an automatic reboot timer'
fi
if [[ $(systemctl is-enabled particleos-workload-health.service 2>/dev/null) == disabled ]] &&
        ! systemctl show -p Requires --value systemd-bless-boot.service |
            grep -qw particleos-workload-health.service &&
        systemctl cat particleos-workload-health.service |
            grep -qF 'ConditionPathExists=/sys/firmware/efi/efivars/LoaderBootCountPath-'; then
    pass 'workload health is opt-in and can reject only counted candidates'
else
    fail 'workload health is opt-in and can reject only counted candidates'
fi

if [[ -z $(systemctl --failed --no-legend --plain) ]]; then
    pass 'systemd has no failed units'
else
    systemctl --failed --no-pager || true
    fail 'systemd has no failed units'
fi
if [[ -L /run/udev/control ]]; then
    pass 'the udev compatibility control link is available'
else
    fail 'the udev compatibility control link is available'
fi
for unit in \
    authselect-apply-changes.service \
    systemd-homed.service \
    systemd-homed-firstboot.service \
    systemd-tpm2-setup-early.service \
    systemd-pcrlogin@.service \
    systemd-pcrnvdone.service \
    systemd-pcrproduct.service \
    systemd-pcrlock.socket \
    systemd-sysupdate-notify-pcrlock.socket; do
    if [[ $(systemctl is-enabled "$unit" 2>/dev/null) == masked ]]; then
        pass "$unit is masked"
    else
        fail "$unit is masked"
    fi
done
if [[ $(systemctl is-enabled systemd-tpm2-setup.service 2>/dev/null) != masked ]]; then
    pass 'systemd-tpm2-setup.service is available for the machine-local PCR policy'
else
    fail 'systemd-tpm2-setup.service is available for the machine-local PCR policy'
fi

check 'host nftables service is active' systemctl is-active --quiet nftables.service
for chain in input forward output; do
    if nft list chain inet particleos_filter "$chain" | grep -q 'policy drop;'; then
        pass "nftables $chain chain is default deny"
    else
        fail "nftables $chain chain is default deny"
    fi
done
forward_policy=$(nft list chain inet particleos_filter forward)
if ! grep -qF 'iifname "podman*" accept' <<<"$forward_policy" &&
        ! grep -qF 'oifname "podman*" ct status dnat accept' <<<"$forward_policy"; then
    pass 'workload forwarding has no blanket Podman accept rule'
else
    fail 'workload forwarding has no blanket Podman accept rule'
fi
if nft list set inet particleos_filter workload_egress_tcp4 |
        grep -qF 'type ifname . ipv4_addr . inet_service' &&
        grep -qF 'iifname . ip daddr . tcp dport @workload_egress_tcp4' \
            <<<"$forward_policy"; then
    pass 'workload egress authority is scoped to an exact Podman bridge'
else
    fail 'workload egress authority is scoped to an exact Podman bridge'
fi
if grep -qF 'iifname "podman*" udp dport 53' <<<"$forward_policy" &&
        grep -qF 'iifname "podman*" tcp dport 53' <<<"$forward_policy" &&
        ! grep -qE 'dport 53.*accept' <<<"$forward_policy"; then
    pass 'workload DNS is explicitly blocked before egress allowlists'
else
    fail 'workload DNS is explicitly blocked before egress allowlists'
fi
for set in \
    workload_egress_tcp4 workload_egress_udp4 \
    workload_egress_tcp6 workload_egress_udp6 \
    workload_ingress_tcp4 workload_ingress_udp4 \
    workload_ingress_tcp6 workload_ingress_udp6; do
    if nft list set inet particleos_filter "$set" | grep -q 'elements ='; then
        fail "$set is empty by default"
    else
        pass "$set is empty by default"
    fi
done
for module in nft_hash nft_limit; do
    if [[ -d /sys/module/$module ]]; then pass "$module loaded before lockdown"; else fail "$module loaded before lockdown"; fi
done
udev_trigger_after=$(systemctl show systemd-udev-trigger.service --property=After --value)
if grep -qw systemd-modules-load.service <<<"$udev_trigger_after"; then
    pass 'image module preload completes before udev coldplug'
else
    fail 'image module preload completes before udev coldplug'
fi
if [[ $(sysctl -n kernel.modules_disabled) == 1 ]]; then
    pass 'kernel module loading is irreversibly disabled'
else
    fail 'kernel module loading is irreversibly disabled'
fi

if [[ $(podman info --format '{{.Host.OCIRuntime.Name}}' 2>/dev/null) == runsc ]]; then
    pass 'Podman selects runsc by default'
else
    fail 'Podman selects runsc by default'
fi
if [[ $(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null) == false ]]; then
    pass 'Podman is rootful'
else
    fail 'Podman is rootful'
fi
if grep -qxF 'keyring = true' /etc/containers/containers.conf.d/10-particleos.conf; then
    pass 'containers receive a fresh session keyring'
else
    fail 'containers receive a fresh session keyring'
fi
runsc=/usr/libexec/gvisor/runsc
if "$runsc" --version | grep -qF 'release-20260810.0'; then pass 'the pinned gVisor release is installed'; else fail 'the pinned gVisor release is installed'; fi
mapfile -t public_gvisor_binaries < <(
    find /usr/libexec/gvisor -type f -perm /0007 -print
)
if [[ $(stat -c '%a:%U:%G' /usr/bin/podman) == 750:root:root &&
        $(stat -c '%a:%U:%G' "$runsc") == 750:root:root &&
        ${#public_gvisor_binaries[@]} -eq 0 ]]; then
    pass 'Podman, runsc, and every gVisor sidecar are administrative-only'
else
    printf '%s\n' "${public_gvisor_binaries[@]}"
    fail 'Podman, runsc, and every gVisor sidecar are administrative-only'
fi
if ! systemd-run --quiet --wait --collect --pipe \
        --unit=particleos-runsc-unprivileged-audit.service \
        --property=Type=exec \
        --property=User=nobody \
        --property=Group=nobody \
        --property=NoNewPrivileges=yes \
        --property=CapabilityBoundingSet= \
        --property=AmbientCapabilities= \
        "$runsc" --version >/dev/null 2>&1; then
    pass 'an unprivileged account cannot execute runsc directly'
else
    stat -c 'runsc mode=%a owner=%U group=%G' "$runsc" 2>/dev/null || true
    fail 'an unprivileged account cannot execute runsc directly'
fi

if [[ ! -e /usr/bin/newuidmap && ! -e /usr/bin/newgidmap &&
      ! -e /usr/bin/pasta && ! -e /usr/bin/slirp4netns ]]; then
    pass 'rootless container helpers are absent'
else
    fail 'rootless container helpers are absent'
fi
userns_clone=/proc/sys/kernel/unprivileged_userns_clone
if { [[ ! -e $userns_clone ]] || [[ $(<"$userns_clone") == 0 ]]; } &&
        ! setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
            --reuid=nobody --regid=nobody --clear-groups \
            unshare --user true 2>/dev/null; then
    pass 'unprivileged user namespaces are disabled'
else
    fail 'unprivileged user namespaces are disabled'
fi

oci_policy=$(tr -d '[:space:]' </etc/containers/policy.json)
if [[ $oci_policy == '{"default":[{"type":"reject"}],"transports":{}}' ]]; then
    pass 'OCI image policy is exact default deny'
else
    fail 'OCI image policy is exact default deny'
fi
pull_log=/run/particleos-podman-deny.log
if timeout 30 podman pull docker.io/library/alpine:latest >"$pull_log" 2>&1; then
    fail 'an unsigned OCI pull is rejected'
elif grep -Eqi 'rejected by policy|source image rejected|signature policy' "$pull_log"; then
    pass 'an unsigned OCI pull is rejected by image policy'
else
    sed -n '1,20p' "$pull_log"
    fail 'an unsigned OCI pull is rejected by image policy'
fi

fixture_mount=/run/particleos-container-fixture
fixture_device=$(findfs LABEL=PTESTOCI 2>/dev/null || true)
install -d -m 0700 "$fixture_mount"
if [[ -b $fixture_device ]] &&
        mount -o ro,nosuid,nodev,noexec "$fixture_device" "$fixture_mount"; then
    pass 'the signed-container fixture is mounted read-only'
else
    fail 'the signed-container fixture is mounted read-only'
fi

image_id=
wrong_policy_log=/run/particleos-podman-wrong-policy.log
good_policy_log=/run/particleos-podman-good-policy.log
container_log=/run/particleos-podman-container.log
if mountpoint -q "$fixture_mount"; then
    if timeout 60 podman pull \
            --signature-policy "$fixture_mount/policy-wrong.json" \
            "dir:$fixture_mount/image" >"$wrong_policy_log" 2>&1; then
        fail 'the signed OCI image is rejected under an unrelated trust root'
    elif grep -Eqi 'signature|public key|verification|not accepted|rejected' \
            "$wrong_policy_log"; then
        pass 'the signed OCI image is rejected under an unrelated trust root'
    else
        sed -n '1,40p' "$wrong_policy_log"
        fail 'the signed OCI image is rejected under an unrelated trust root'
    fi

    if timeout 60 podman pull \
            --signature-policy "$fixture_mount/policy-good.json" \
            "dir:$fixture_mount/image" >"$good_policy_log" 2>&1; then
        image_id=$(podman images --no-trunc --format '{{.ID}}' | head -n1)
        if [[ $image_id =~ ^sha256:[0-9a-f]{64}$ ]]; then
            pass 'the signed OCI image is accepted by its narrow trust policy'
        else
            sed -n '1,80p' "$good_policy_log"
            fail 'the signed OCI image is accepted by its narrow trust policy'
            image_id=
        fi
    else
        sed -n '1,80p' "$good_policy_log"
        fail 'the signed OCI image is accepted by its narrow trust policy'
    fi
else
    fail 'the signed OCI image is rejected under an unrelated trust root'
    fail 'the signed OCI image is accepted by its narrow trust policy'
fi

if [[ -n $image_id ]] && timeout 90 podman run \
        --detach \
        --name particleos-podman-audit \
        --pull=never \
        "$image_id" /bin/sh -c 'printf PARTICLEOS_PODMAN_RUNSC_OK' \
        >/dev/null 2>&1 &&
        [[ $(timeout 30 podman wait particleos-podman-audit 2>/dev/null) == 0 ]] &&
        podman logs particleos-podman-audit >"$container_log" 2>&1; then
    if grep -qxF 'PARTICLEOS_PODMAN_RUNSC_OK' "$container_log"; then
        pass 'Podman executes the trusted OCI image with default runsc/systrap'
    else
        sed -n '1,100p' "$container_log"
        fail 'Podman executes the trusted OCI image with default runsc/systrap'
    fi
    if [[ $(podman inspect --format '{{.HostConfig.ReadonlyRootfs}}' \
            particleos-podman-audit 2>/dev/null) == true ]]; then
        pass 'the Podman container root filesystem is read-only by default'
    else
        fail 'the Podman container root filesystem is read-only by default'
    fi
else
    sed -n '1,120p' "$container_log" 2>/dev/null || true
    journalctl --boot --no-pager 2>/dev/null |
        grep -Ei 'avc:|denied|ipe|podman|runsc|systrap' | tail -200 || true
    fail 'Podman executes the trusted OCI image with default runsc/systrap'
    fail 'the Podman container root filesystem is read-only by default'
fi
podman rm --force particleos-podman-audit >/dev/null 2>&1 || true

health_quadlet=/run/containers/systemd/vm-health.container
health_log=/run/particleos-podman-health.log
health_container=
if [[ -n $image_id ]]; then
    install -d -m 0700 /run/containers/systemd
    cat >"$health_quadlet" <<EOF
[Unit]
Description=Disposable ParticleOS workload-health audit

[Container]
Image=$image_id
Pull=never
Exec=/bin/sleep 90
HealthCmd=/bin/true
HealthInterval=1s
HealthRetries=3
Notify=healthy
ReadOnly=true
NoNewPrivileges=true
DropCapability=all

[Service]
SuccessExitStatus=143
EOF
    systemctl daemon-reload
    if timeout 45 systemctl start vm-health.service >"$health_log" 2>&1 &&
            /usr/lib/particleos/check-workload-health >>"$health_log" 2>&1; then
        pass 'a healthy rootful Quadlet satisfies the boot health gate'
    else
        systemctl status --no-pager vm-health.service >>"$health_log" 2>&1 || true
        sed -n '1,160p' "$health_log"
        fail 'a healthy rootful Quadlet satisfies the boot health gate'
    fi

    mapfile -t health_containers < <(
        podman ps --filter 'label=PODMAN_SYSTEMD_UNIT=vm-health.service' --format '{{.ID}}'
    )
    if [[ ${#health_containers[@]} -eq 1 ]]; then
        health_container=${health_containers[0]}
    fi
    # SELinux context inspection is not available through pgrep.
    # shellcheck disable=SC2009
    gvisor_processes=$(ps -eZ 2>/dev/null |
        grep -E '[[:space:]]+(runsc|exe|gvisor_sentry)$' || true)
    if [[ -n $health_container && -n $gvisor_processes ]] &&
            ! grep -qvE '^system_u:system_r:gvisor_t:s0[[:space:]]+' \
                <<<"$gvisor_processes"; then
        pass 'live gVisor sandbox processes run in gvisor_t'
    else
        printf '%s\n' "$gvisor_processes"
        fail 'live gVisor sandbox processes run in gvisor_t'
    fi
    if [[ -n $health_container ]] &&
            podman exec "$health_container" /bin/sh -c 'command -v nc' >/dev/null 2>&1 &&
            ! timeout 8 podman exec "$health_container" \
                /bin/nc -z -w 3 1.1.1.1 443 >/dev/null 2>&1; then
        pass 'an unlisted workload destination is denied by default'
    else
        fail 'an unlisted workload destination is denied by default'
    fi

    default_bridge=$(podman network inspect podman \
        --format '{{.NetworkInterface}}' 2>/dev/null || true)
    isolated_network=particleos-audit-isolated
    isolated_container=particleos-network-isolation-audit
    isolated_bridge=
    network_isolation_ready=0
    if [[ $default_bridge =~ ^podman[0-9]+$ ]] &&
            podman network create --disable-dns "$isolated_network" >/dev/null 2>&1; then
        isolated_bridge=$(podman network inspect "$isolated_network" \
            --format '{{.NetworkInterface}}' 2>/dev/null || true)
        if [[ $isolated_bridge =~ ^podman[0-9]+$ && $isolated_bridge != "$default_bridge" ]] &&
                timeout 45 podman run --detach --name "$isolated_container" \
                    --network "$isolated_network" --pull=never "$image_id" \
                    /bin/sleep 90 >/dev/null 2>&1; then
            network_isolation_ready=1
        fi
    fi

    nft add element inet particleos_filter workload_egress_tcp4 \
        "{ \"$default_bridge\" . 1.1.1.1 . 443 }" 2>/dev/null || true
    if ((network_isolation_ready)) &&
            timeout 8 podman exec "$health_container" \
                /bin/nc -z -w 5 1.1.1.1 443 >/dev/null 2>&1 &&
            ! timeout 8 podman exec "$isolated_container" \
                /bin/nc -z -w 3 1.1.1.1 443 >/dev/null 2>&1; then
        pass 'an egress tuple for one Podman bridge grants no authority to another'
    else
        fail 'an egress tuple for one Podman bridge grants no authority to another'
    fi

    nft add element inet particleos_filter workload_egress_tcp4 \
        "{ \"$default_bridge\" . 1.1.1.1 . 53 }" 2>/dev/null || true
    if [[ -n $health_container ]] &&
            ! timeout 8 podman exec "$health_container" \
                /bin/nc -z -w 3 1.1.1.1 53 >/dev/null 2>&1; then
        pass 'a forwarding tuple cannot reopen the blocked workload DNS channel'
    else
        fail 'a forwarding tuple cannot reopen the blocked workload DNS channel'
    fi
    nft delete element inet particleos_filter workload_egress_tcp4 \
        "{ \"$default_bridge\" . 1.1.1.1 . 443, \"$default_bridge\" . 1.1.1.1 . 53 }" \
        >/dev/null 2>&1 || true
    podman rm --force "$isolated_container" >/dev/null 2>&1 || true
    podman network rm "$isolated_network" >/dev/null 2>&1 || true

    sed -i 's/^Notify=healthy$/Notify=false/' "$health_quadlet"
    if ! /usr/lib/particleos/check-workload-health >/dev/null 2>&1; then
        pass 'a workload without health-gated readiness blocks blessing'
    else
        fail 'a workload without health-gated readiness blocks blessing'
    fi
    sed -i 's/^Notify=false$/Notify=healthy/' "$health_quadlet"
else
    fail 'a healthy rootful Quadlet satisfies the boot health gate'
    fail 'live gVisor sandbox processes run in gvisor_t'
    fail 'an unlisted workload destination is denied by default'
    fail 'an egress tuple for one Podman bridge grants no authority to another'
    fail 'a forwarding tuple cannot reopen the blocked workload DNS channel'
    fail 'a workload without health-gated readiness blocks blessing'
fi
if [[ -n $image_id ]] && systemctl stop vm-health.service >/dev/null 2>&1 &&
        [[ $(systemctl is-failed vm-health.service 2>/dev/null || true) != failed ]]; then
    pass 'the disposable health workload stops without a failed unit'
elif [[ -n $image_id ]]; then
    systemctl status --no-pager vm-health.service 2>/dev/null || true
    fail 'the disposable health workload stops without a failed unit'
fi
rm -f -- "$health_quadlet"
systemctl daemon-reload

if [[ -n $image_id ]]; then
    podman rmi --force "$image_id" >/dev/null 2>&1 || true
fi
if mountpoint -q "$fixture_mount"; then
    umount "$fixture_mount" || fail 'the signed-container fixture is unmounted cleanly'
fi

mapfile -t setid_files < <(find /usr -xdev -type f -perm /6000 -perm /0111 -print)
if [[ ${#setid_files[@]} -eq 1 && ${setid_files[0]} == /usr/bin/unix_chkpwd ]]; then
    pass 'unix_chkpwd is the only set-ID executable'
else
    printf '%s\n' "${setid_files[@]}"
    fail 'unix_chkpwd is the only set-ID executable'
fi
if [[ $(systemctl is-enabled sshd.socket 2>/dev/null) == disabled ]]; then pass 'SSH remains disabled'; else fail 'SSH remains disabled'; fi
check_grep 'SSH root login is prohibited' '^PermitRootLogin no$' /etc/ssh/sshd_config.d/40-particleos-hardening.conf
dns_policy=/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf
check_grep 'strict DNS-over-TLS is configured' '^DNSOverTLS=yes$' "$dns_policy"
check_grep 'DNSSEC validation is configured' '^DNSSEC=yes$' "$dns_policy"

if ((failures == 0)); then
    printf 'PARTICLEOS_VM_AUDIT_PASS checks=%d\n' "$checks"
    exit 0
fi

printf 'PARTICLEOS_VM_AUDIT_FAIL checks=%d failures=%d\n' "$checks" "$failures"
exit 1
