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
if grep -Rqx '1' /sys/kernel/security/ipe/policies/*/active 2>/dev/null; then
    pass 'an IPE policy is active'
else
    fail 'an IPE policy is active'
fi
if [[ $(getenforce) == Enforcing ]]; then pass 'SELinux is enforcing'; else fail 'SELinux is enforcing'; fi

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

state=/dev/disk/by-partlabel/ParticleOS-Host-root
if [[ -b $state ]]; then pass 'persistent state partition exists'; else fail 'persistent state partition exists'; fi
luks_metadata=$(cryptsetup luksDump --dump-json-metadata "$state" 2>/dev/null || true)
if grep -qE '"tpm2-pcrs"[[:space:]]*:[[:space:]]*\[[[:space:]]*7[[:space:]]*\]' <<<"$luks_metadata"; then
    pass 'state TPM token is bound to PCR 7'
else
    fail 'state TPM token is bound to PCR 7'
fi
if ! grep -q '"tpm2-pubkey-pcrs"' <<<"$luks_metadata"; then
    pass 'state token has no public-key PCR11 dependency'
else
    fail 'state token has no public-key PCR11 dependency'
fi
for unit in systemd-tpm2-setup-early.service systemd-cryptsetup@root.service; do
    if [[ $(systemctl show --property=Result --value "$unit" 2>/dev/null) == success ]]; then
        pass "$unit completed successfully"
    else
        fail "$unit completed successfully"
    fi
done

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

if [[ -z $(systemctl --failed --no-legend --plain) ]]; then
    pass 'systemd has no failed units'
else
    systemctl --failed --no-pager || true
    fail 'systemd has no failed units'
fi
for unit in \
    authselect-apply-changes.service \
    systemd-homed.service \
    systemd-homed-firstboot.service \
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

check 'host nftables service is active' systemctl is-active --quiet nftables.service
for chain in input forward output; do
    if nft list chain inet particleos_filter "$chain" | grep -q 'policy drop;'; then
        pass "nftables $chain chain is default deny"
    else
        fail "nftables $chain chain is default deny"
    fi
done
for module in nft_hash nft_limit; do
    if [[ -d /sys/module/$module ]]; then pass "$module loaded before lockdown"; else fail "$module loaded before lockdown"; fi
done
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
if runsc --version | grep -qF 'release-20260810.0'; then pass 'the pinned gVisor release is installed'; else fail 'the pinned gVisor release is installed'; fi

install -d -m 0700 /run/particleos-runsc-audit/root /run/particleos-runsc-audit/bundle
ln -sfn /usr /run/particleos-runsc-audit/bundle/rootfs
cat >/run/particleos-runsc-audit/bundle/config.json <<'JSON'
{
  "ociVersion": "1.0.2",
  "process": {
    "terminal": false,
    "user": {"uid": 0, "gid": 0},
    "args": ["/bin/true"],
    "env": ["PATH=/bin:/usr/bin"],
    "cwd": "/",
    "noNewPrivileges": true
  },
  "root": {"path": "rootfs", "readonly": true},
  "hostname": "particleos-audit",
  "mounts": [
    {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]}
  ],
  "linux": {
    "namespaces": [
      {"type": "pid"},
      {"type": "network"},
      {"type": "ipc"},
      {"type": "uts"},
      {"type": "mount"}
    ]
  }
}
JSON
if runsc --platform=systrap --root=/run/particleos-runsc-audit/root run \
        --bundle=/run/particleos-runsc-audit/bundle particleos-audit; then
    pass 'runsc executes an OCI bundle with systrap'
else
    runsc --root=/run/particleos-runsc-audit/root delete --force particleos-audit 2>/dev/null || true
    fail 'runsc executes an OCI bundle with systrap'
fi

if [[ ! -e /usr/bin/newuidmap && ! -e /usr/bin/newgidmap &&
      ! -e /usr/bin/pasta && ! -e /usr/bin/slirp4netns ]]; then
    pass 'rootless container helpers are absent'
else
    fail 'rootless container helpers are absent'
fi
if [[ $(sysctl -n kernel.unprivileged_userns_clone) == 0 ]]; then
    pass 'unprivileged user namespaces are disabled'
else
    fail 'unprivileged user namespaces are disabled'
fi

if python3 - <<'PY'
import json
with open('/etc/containers/policy.json', encoding='utf-8') as policy_file:
    policy = json.load(policy_file)
assert policy == {'default': [{'type': 'reject'}], 'transports': {}}
PY
then
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

mapfile -t setid_files < <(find /usr -xdev -type f -perm /6000 -perm /0111 -print)
if [[ ${#setid_files[@]} -eq 1 && ${setid_files[0]} == /usr/bin/unix_chkpwd ]]; then
    pass 'unix_chkpwd is the only set-ID executable'
else
    printf '%s\n' "${setid_files[@]}"
    fail 'unix_chkpwd is the only set-ID executable'
fi
if [[ $(systemctl is-enabled sshd.socket 2>/dev/null) == disabled ]]; then pass 'SSH remains disabled'; else fail 'SSH remains disabled'; fi
check_grep 'SSH root login is prohibited' '^PermitRootLogin no$' /etc/ssh/sshd_config.d/40-particleos-hardening.conf
check_grep 'strict DNS-over-TLS is configured' '^DNSOverTLS=yes$' /etc/systemd/resolved.conf.d/40-particleos-dns.conf
check_grep 'DNSSEC validation is configured' '^DNSSEC=yes$' /etc/systemd/resolved.conf.d/40-particleos-dns.conf

if ((failures == 0)); then
    printf 'PARTICLEOS_VM_AUDIT_PASS checks=%d\n' "$checks"
    exit 0
fi

printf 'PARTICLEOS_VM_AUDIT_FAIL checks=%d failures=%d\n' "$checks" "$failures"
exit 1
