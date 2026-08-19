#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

cd "$(dirname "$0")/.."
failures=0

pass() { printf 'ok - %s\n' "$1"; }
fail() { printf 'not ok - %s\n' "$1" >&2; failures=$((failures + 1)); }

require_fixed() {
    local needle=$1 file=$2 description=$3
    if grep -qF -- "$needle" "$file"; then pass "$description"; else fail "$description"; fi
}

reject_fixed() {
    local needle=$1 file=$2 description=$3
    if grep -qF -- "$needle" "$file"; then fail "$description"; else pass "$description"; fi
}

require_fixed 'Distribution=fedora' mkosi.conf 'Fedora is the sole distribution'
require_fixed 'Release=44' mkosi.conf 'Fedora release is pinned'
require_fixed 'Architecture=x86-64' mkosi.conf 'architecture is pinned'
require_fixed 'ImageId=ParticleOS-Host' mkosi.conf 'generic image identity is fixed'
require_fixed 'SecureBoot=yes' mkosi.conf 'Secure Boot signing is mandatory'
require_fixed 'systemd.verity_usr_options=root-hash-signature=auto' mkosi.conf 'signed verity root hash is mandatory'
require_fixed 'ipe.enforce=1' mkosi.conf 'IPE enforcement is on the signed command line'
require_fixed 'enforcing=1' mkosi.conf 'SELinux enforcement is on the signed command line'
require_fixed 'lockdown=confidentiality' mkosi.conf 'kernel lockdown is enforced'
require_fixed 'module.sig_enforce=1' mkosi.conf 'kernel module signatures are enforced'
require_fixed 'rootflags=nosuid,nodev,noexec' mkosi.conf 'persistent state is mounted noexec'
require_fixed 'systemd.firstboot=headless' mkosi.conf 'first boot is unattended without disabling noninteractive provisioning'
require_fixed 'rd.systemd.mask=systemd-tpm2-setup-early.service' mkosi.conf 'the unused initrd NvPCR setup path is suppressed'
require_fixed 'Include=mkosi-obs' mkosi.obs.conf 'upstream OBS signer is included'
require_fixed 'SplitArtifacts=uki,partitions,roothash,os-release,repart-definitions' mkosi.obs.conf 'OBS suppresses incompatible expected-PCR artifacts'
reject_fixed 'SplitArtifacts=pcrs' mkosi.obs.conf 'OBS does not request a PCR11 public-key policy'
require_fixed '/usr/lib/nvpcr' mkosi.conf 'unused NvPCR definitions are removed'
require_fixed 'needssslcertforbuild' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS project certificate is requested'
require_fixed '[Content]' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS image closure uses the mkosi Content section'
require_fixed '        basesystem' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS stages the implicit Fedora base package'

for type in usr usr-verity usr-verity-sig; do
    count="$(grep -rl "^Type=${type}$" mkosi.extra/usr/lib/repart.d | wc -l)"
    if [[ "$count" -eq 2 ]]; then pass "two ${type} A/B slots exist"; else fail "two ${type} A/B slots exist"; fi
done
require_fixed 'Encrypt=tpm2' mkosi.extra/usr/lib/repart.d/40-root.conf 'persistent state is TPM2 encrypted'
require_fixed 'TPM2PCRs=7' mkosi.extra/usr/lib/repart.d/40-root.conf 'state is bound to Secure Boot policy'
require_fixed 'ipe-policy-containerhost' mkosi.conf 'the systrap-compatible signed IPE policy is selected'
require_fixed 'ipe-policy-containerhost' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS stages the systrap-compatible IPE policy'
if grep -qxF '        ipe-policy' mkosi.conf; then
    fail 'the incompatible generic IPE package is not selected'
else
    pass 'the incompatible generic IPE package is not selected'
fi
if grep -qxF '        ipe-policy' .obs/particleos-containerhost/x86-64/mkosi.conf; then
    fail 'OBS does not stage the incompatible generic IPE package'
else
    pass 'OBS does not stage the incompatible generic IPE package'
fi
ipe_policy=.obs/ipe-policy-containerhost/ipe-policy
require_fixed 'DEFAULT action=DENY' "$ipe_policy" 'IPE denies unmatched kernel-fed objects'
require_fixed 'DEFAULT op=EXECUTE action=ALLOW' "$ipe_policy" 'IPE permits systrap anonymous execution explicitly'
for operation in FIRMWARE KMODULE KEXEC_IMAGE KEXEC_INITRAMFS POLICY X509_CERT; do
    require_fixed "op=$operation dmverity_signature=TRUE action=ALLOW" "$ipe_policy" "IPE trusts signed dm-verity for $operation"
done
require_fixed '# needssslcertforbuild' .obs/ipe-policy-containerhost/ipe-policy-containerhost.spec 'the container-host IPE policy requires OBS signing'
require_fixed 'systemd-keyutil' .obs/ipe-policy-containerhost/ipe-policy-containerhost.spec 'the IPE policy is packaged as signed PKCS#7'
selinux_policy=mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil
require_fixed '(typeattributeset anonymous_exec_privileged_domain (.container_runtime_t))' "$selinux_policy" 'SELinux reserves anonymous execution for the gVisor runtime'
require_fixed '(deny anonymous_exec_restricted_domain self (process (execmem execstack)))' "$selinux_policy" 'SELinux denies executable anonymous memory outside the runtime'
require_fixed '(deny anonymous_exec_restricted_domain .container_runtime_tmpfs_t' "$selinux_policy" 'SELinux denies systrap-style tmpfs entrypoints outside the runtime'
if ! grep -RqsE '^Type=(home|swap)$' mkosi.extra/usr/lib/repart.d; then
    pass 'no unencrypted home or swap partition exists'
else
    fail 'no unencrypted home or swap partition exists'
fi

containers=mkosi.extra/etc/containers/containers.conf.d/10-particleos.conf
require_fixed 'runtime = "runsc"' "$containers" 'runsc is the Podman default runtime'
require_fixed 'runsc = ["/usr/libexec/gvisor/runsc"]' "$containers" 'Podman uses the packaged runtime path'
require_fixed 'runsc = ["platform=systrap"]' "$containers" 'systrap is explicit'
require_fixed 'userns = "host"' "$containers" 'Podman does not create rootless ID mappings'
require_fixed 'label = false' "$containers" 'unsupported gVisor container labeling is disabled'
require_fixed 'read_only = true' "$containers" 'containers are read-only by default'
require_fixed 'pull_policy = "always"' "$containers" 'pulls always re-evaluate image trust'
require_fixed 'short-name-mode = "enforcing"' mkosi.extra/etc/containers/registries.conf 'short-name enforcement is active'
require_fixed 'unqualified-search-registries = []' mkosi.extra/etc/containers/registries.conf 'unqualified registry search is disabled'
require_fixed 'use-sigstore-attachments: true' mkosi.extra/etc/containers/registries.d/00-particleos.yaml 'sigstore attachment discovery is enabled'

python3 - <<'PY' || failures=$((failures + 1))
import json
from pathlib import Path
p = json.loads(Path('mkosi.extra/etc/containers/policy.json').read_text())
assert p == {'default': [{'type': 'reject'}], 'transports': {}}
print('ok - OCI image policy is an exact default deny')
PY
if ! grep -Rqs 'insecureAcceptAnything' mkosi.extra/etc/containers; then
    pass 'no insecure OCI image-policy exception exists'
else
    fail 'no insecure OCI image-policy exception exists'
fi

for helper in newuidmap newgidmap pasta passt slirp4netns; do
    require_fixed "/usr/bin/$helper" mkosi.conf "$helper is removed from the image"
done
require_fixed '/usr/lib/systemd/user/podman.service' mkosi.conf 'rootless Podman service is removed'
require_fixed '/usr/lib/systemd/user/podman.socket' mkosi.conf 'rootless Podman socket is removed'
require_fixed 'kernel.unprivileged_userns_clone = 0' mkosi.extra/usr/lib/sysctl.d/70-particleos-hardening.conf 'unprivileged user namespaces are disabled'
require_fixed '(deny userns_restricted_domain self (user_namespace (create)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'SELinux denies user namespaces by default'
require_fixed '.container_runtime_t' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'gVisor runtime domain has the narrow namespace exception'
require_fixed '(allow .initrc_t .container_runtime_t (process2 (nosuid_transition)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'system services may enter the confined runtime from authenticated /usr'
require_fixed 'SELINUX=enforcing' mkosi.extra/etc/selinux/config 'SELinux is enforcing in userspace'
require_fixed 'authselect select local --force' mkosi.postinst.chroot 'Fedora local authentication profile is explicit'
for unit in \
    authselect-apply-changes.service \
    systemd-homed.service \
    systemd-homed-firstboot.service \
    systemd-tpm2-setup-early.service \
    systemd-tpm2-setup.service \
    systemd-pcrlogin@.service \
    systemd-pcrnvdone.service \
    systemd-pcrproduct.service \
    systemd-pcrlock.socket \
    systemd-sysupdate-notify-pcrlock.socket; do
    require_fixed "$unit" mkosi.finalize "$unit is immutably masked"
done

# Literal implementation strings, not expressions for this validator.
# shellcheck disable=SC2016
require_fixed 'find "$image_tree" -xdev -type f -perm /6000 -perm /0111' mkosi.finalize 'all executable set-ID bits are stripped'
# shellcheck disable=SC2016
require_fixed 'chmod 4755 "$pam_shadow_helper"' mkosi.finalize 'only unix_chkpwd setuid is restored'
# shellcheck disable=SC2016
require_fixed 'chmod 0750 "$BUILDROOT/usr/bin/podman"' mkosi.finalize 'Podman execution is restricted'
require_fixed 'PasswordAuthentication no' mkosi.extra/etc/ssh/sshd_config.d/40-particleos-hardening.conf 'SSH password authentication is disabled'
require_fixed 'PermitRootLogin no' mkosi.extra/etc/ssh/sshd_config.d/40-particleos-hardening.conf 'SSH root login is disabled'
require_fixed 'DNSOverTLS=yes' mkosi.extra/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf 'strict DNS-over-TLS is enabled'
require_fixed 'DNSSEC=yes' mkosi.extra/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf 'DNSSEC is enabled'

firewall=mkosi.extra/usr/lib/particleos/nftables.conf
require_fixed 'destroy table inet particleos_filter' "$firewall" 'host firewall reload is atomic and idempotent'
require_fixed 'chain input {' "$firewall" 'host input firewall exists'
require_fixed 'type filter hook input priority filter; policy drop;' "$firewall" 'input is default deny'
require_fixed 'type filter hook forward priority filter; policy drop;' "$firewall" 'forwarding is default deny'
require_fixed 'type filter hook output priority filter; policy drop;' "$firewall" 'output is default deny'
require_fixed 'iifname "podman*" accept' "$firewall" 'rootful Podman outbound forwarding is allowed'
require_fixed 'oifname "podman*" ct status dnat accept' "$firewall" 'only DNATed Podman ingress is forwarded'
reject_fixed 'flush ruleset' "$firewall" 'host policy does not erase Netavark rules'
require_fixed 'nft_hash' mkosi.extra/usr/lib/modules-load.d/particleos.conf 'nftables meter support loads before module lockdown'
require_fixed 'nft_limit' mkosi.extra/usr/lib/modules-load.d/particleos.conf 'nftables rate limiting loads before module lockdown'
reject_fixed 'nft delete table inet particleos_filter' mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf 'firewall startup has no expected deletion error'
require_fixed 'LoadCredential=vm-audit' tests/vm-audit.service 'VM audit is injected without modifying the image'
# Literal implementation string, not an expression for this validator.
# shellcheck disable=SC2016
require_fixed '"$runsc" --platform=systrap' tests/vm-audit.sh 'VM audit executes the packaged runtime with a real systrap sandbox'
require_fixed 'PARTICLEOS_VM_AUDIT_PASS' tests/vm-audit.sh 'VM audit has an unambiguous success marker'

service=.obs/runsc/_service
require_fixed 'release/20260810.0/x86_64/gvisor.tar.bz2' "$service" 'gVisor release archive is pinned'
require_fixed '3eca0158249c6b9b1f0d96c8f429c2aec6a4bcabd1a549bf25b15e48ca6d1d0c' "$service" 'gVisor archive SHA-256 is pinned'
require_fixed '0fbab5c58efbdf6d31e8085214f2dd821659c03d73cff3ed2b08e98826ea1cd9' "$service" 'gVisor license SHA-256 is pinned'
require_fixed 'release-20260810.0' .obs/runsc/runsc.spec 'RPM verifies the installed runsc version'
# Literal implementation string, not an expression for this validator.
# shellcheck disable=SC2016
require_fixed '[[ ${#roothashes[@]} -eq 1 ]]' mkosi.scripts/obs-build 'OBS wrapper requires the signed verity input'
reject_fixed 'PCR policy signing requires' mkosi.scripts/obs-build 'obsolete PCR signing round is absent'
# Literal implementation strings, not expressions for this validator.
# shellcheck disable=SC2016
require_fixed 'sha256sum -- "${artifact_names[@]}"' mkosi.scripts/obs-build 'checksums are regenerated after final signed artifacts are staged'
# shellcheck disable=SC2016
require_fixed 'sha256sum -c "${checksum_manifest##*/}"' scripts/validate-artifacts.sh 'artifact validation verifies the published checksum manifest'

python3 - <<'PY' || failures=$((failures + 1))
import xml.etree.ElementTree as ET
for p in ('.obs/runsc/_service', '.obs/runsc/package-meta.xml',
          '.obs/ipe-policy-containerhost/package-meta.xml',
          '.obs/particleos-containerhost/_service.example',
          '.obs/particleos-containerhost/package-meta.xml'):
    ET.parse(p)
print('ok - OBS service and package XML is well formed')
PY

if find mkosi.images mkosi.uki-profiles -mindepth 1 -print -quit 2>/dev/null | grep -q .; then
    fail 'no role images or alternate UKI profiles remain'
else
    pass 'no role images or alternate UKI profiles remain'
fi

package_lines="$(sed -n '/^Packages=/,/^$/p' mkosi.conf)"
for forbidden in nginx postgresql stalwart unbound mariadb redis; do
    if grep -qiE "^[[:space:]]*${forbidden}([[:space:]-]|$)" <<<"$package_lines"; then
        fail "application package ${forbidden} is absent"
    else
        pass "application package ${forbidden} is absent"
    fi
done

if command -v shellcheck >/dev/null; then
    mapfile -t shell_files < <(find . -type f \( -name '*.sh' -o -name 'mkosi.*' -o -path './mkosi.scripts/*' \) \
        -not -path './.git/*' -exec awk 'FNR == 1 && /^#!.*(ba)?sh/ {print FILENAME}' {} \;)
    shellcheck "${shell_files[@]}" && pass 'shell scripts pass shellcheck' || failures=$((failures + 1))
fi

if ((failures > 0)); then
    printf '%d validation check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'All container-host validation checks passed.\n'
