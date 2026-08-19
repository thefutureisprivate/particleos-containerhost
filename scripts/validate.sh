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
require_fixed 'systemd.credentials_boot_policy=strict' mkosi.conf 'null-key boot credentials are rejected by the signed UKI'
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
require_fixed 'TPM2PCRs=7' mkosi.extra/usr/lib/repart.d/40-root.conf 'state has a first-boot PCR7 bootstrap token'
require_fixed '--pcr=7 --pcr=11 --strict=yes --force' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime state policy strictly covers PCR7 and PCR11'
require_fixed 'lock-secureboot-policy' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'PCR7 policy is derived from live Secure Boot variables'
require_fixed '--wipe-slot=tpm2' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'the bootstrap TPM enrollment is replaced atomically'
require_fixed '"tpm2_pcrlock":true' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'enrollment verifies the systemd 261 pcrlock token field'
require_fixed 'ExecStartPost=/usr/lib/particleos/pcrlock-refresh all' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate-update.service.d/40-particleos-egress.conf 'updates authorize both A/B UKIs before reboot'
require_fixed 'ExecCondition=/usr/lib/particleos/pcrlock-update-ready' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate-reboot.service.d/40-particleos-pcrlock.conf 'reboot refuses an update without a committed PCR policy'
require_fixed 'enable systemd-sysupdate-reboot.timer' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'staged updates receive an automatic reboot window'
require_fixed 'enable systemd-bless-boot.service' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'boot completion and health-gated blessing are activated'
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
require_fixed '(type gvisor_t)' "$selinux_policy" 'SELinux defines a dedicated gVisor process domain'
require_fixed '(typeattributeset .container_runtime_domain (.gvisor_t))' "$selinux_policy" 'gVisor inherits only the common runtime baseline'
require_fixed '(typetransition gvisor_launcher_domain .gvisor_exec_t process .gvisor_t)' "$selinux_policy" 'gVisor binaries transition out of the Podman domain'
require_fixed '(typeattributeset anonymous_exec_privileged_domain (.gvisor_t))' "$selinux_policy" 'SELinux reserves anonymous execution for gVisor alone'
require_fixed '(deny anonymous_exec_restricted_domain self (process (execmem execstack)))' "$selinux_policy" 'SELinux denies executable anonymous memory outside the runtime'
require_fixed '(deny anonymous_exec_restricted_domain .container_runtime_tmpfs_t' "$selinux_policy" 'SELinux denies systrap-style tmpfs entrypoints outside the runtime'
require_fixed '(allow .gvisor_t self (process (ptrace)))' "$selinux_policy" 'SELinux permits only gVisor self-ptrace needed by systrap'
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
require_fixed 'keyring = true' "$containers" 'containers do not inherit the host caller keyring'
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
require_fixed 'kernel.yama.ptrace_scope = 2' mkosi.extra/usr/lib/sysctl.d/70-particleos-hardening.conf 'Yama requires CAP_SYS_PTRACE for systrap initialization'
require_fixed 'setsebool -P deny_ptrace=on' mkosi.postinst.chroot 'SELinux denies ptrace globally outside explicit policy'
require_fixed '(deny userns_restricted_domain self (user_namespace (create)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'SELinux denies user namespaces by default'
require_fixed '.container_runtime_t .gvisor_t' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'only the administrative runtime and trusted system helpers have the namespace exception'
require_fixed '(allow .gvisor_t self (user_namespace (create)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the dedicated runtime receives its required namespace permission explicitly'
require_fixed '(allow .gvisor_t .null_device_t (chr_file (setattr)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'gVisor may normalize only inherited null-device stdio'
require_fixed '(allow .gvisor_t .container_runtime_t (fifo_file (setattr)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'gVisor may normalize only conmon runtime FIFOs'
require_fixed '(allow .gvisor_t .proc_t (file (getattr open read)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'gVisor may read host proc data without mutating it'
require_fixed '(allow .init_t .udev_var_run_t (lnk_file (create)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'PID 1 may create only the typed udev compatibility link'
require_fixed '(type particleos_import_key_t)' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the update key has a dedicated SELinux type'
require_fixed '(allow .systemd_importd_t .particleos_import_key_t' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'only importd receives read access to the update key'
require_fixed '(allow .initrc_t .container_runtime_t (process2 (nosuid_transition)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'system services may enter the confined runtime from authenticated /usr'
require_fixed '/usr/lib/systemd/import-pubring\.pgp -- system_u:object_r:particleos_import_key_t:s0' mkosi.postinst.chroot 'the immutable update key receives only its dedicated label'
require_fixed 'SELINUX=enforcing' mkosi.extra/etc/selinux/config 'SELinux is enforcing in userspace'
require_fixed 'authselect select local --force' mkosi.postinst.chroot 'Fedora local authentication profile is explicit'
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
    require_fixed "$unit" mkosi.finalize "$unit is immutably masked"
done
if rg -Fq 'systemd-tpm2-setup.service' mkosi.finalize; then
    fail 'systemd-tpm2-setup.service remains available for the machine-local PCR policy'
else
    pass 'systemd-tpm2-setup.service remains available for the machine-local PCR policy'
fi

# Literal implementation strings, not expressions for this validator.
# shellcheck disable=SC2016
require_fixed 'find "$image_tree" -xdev -type f -perm /6000 -perm /0111' mkosi.finalize 'all executable set-ID bits are stripped'
# shellcheck disable=SC2016
require_fixed 'chmod 4755 "$pam_shadow_helper"' mkosi.finalize 'only unix_chkpwd setuid is restored'
# shellcheck disable=SC2016
require_fixed 'chmod 0750 "$BUILDROOT/usr/bin/podman"' mkosi.finalize 'Podman execution is restricted'
require_fixed 'chmod 0750 "$BUILDROOT/usr/libexec/gvisor/runsc"' mkosi.finalize 'direct runsc execution is restricted'
require_fixed 'gvisor_exec_t' mkosi.postinst.chroot 'gVisor executables receive the dedicated transition type'
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
require_fixed 'workload_egress_tcp4' "$firewall" 'workload TCP egress requires an exact destination set'
require_fixed 'workload_egress_udp6' "$firewall" 'workload UDP egress requires an exact destination set'
require_fixed 'workload_ingress_tcp4' "$firewall" 'DNAT TCP ingress requires an exact workload destination set'
require_fixed 'workload_ingress_udp6' "$firewall" 'DNAT UDP ingress requires an exact workload destination set'
reject_fixed 'iifname "podman*" accept' "$firewall" 'no unrestricted workload forwarding remains'
reject_fixed 'oifname "podman*" ct status dnat accept' "$firewall" 'no unrestricted DNAT forwarding remains'
require_fixed 'include "/etc/particleos/nftables.d/*.nft"' "$firewall" 'root-owned exact forwarding policy persists across boot'
reject_fixed 'flush ruleset' "$firewall" 'host policy does not erase Netavark rules'
require_fixed 'nft_hash' mkosi.extra/usr/lib/modules-load.d/particleos.conf 'nftables meter support loads before module lockdown'
require_fixed 'nft_limit' mkosi.extra/usr/lib/modules-load.d/particleos.conf 'nftables rate limiting loads before module lockdown'
reject_fixed 'nft delete table inet particleos_filter' mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf 'firewall startup has no expected deletion error'
require_fixed 'LoadCredential=vm-audit' tests/vm-audit.service 'VM audit is injected without modifying the image'
require_fixed 'SuccessAction=poweroff' tests/vm-audit.service 'successful VM audits power off the guest'
require_fixed 'FailureAction=poweroff' tests/vm-audit.service 'failed VM audits power off the guest'
require_fixed '--sign-identity "$signed_identity"' tests/prepare-signed-container-fixture.sh 'VM fixture signs an exact OCI identity'
require_fixed 'busybox@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23' tests/prepare-signed-container-fixture.sh 'VM fixture source is immutable by default'
require_fixed 'policy-wrong.json' tests/prepare-signed-container-fixture.sh 'VM fixture carries an unrelated negative-test trust root'
require_fixed 'skopeo --policy "$host_policy" copy' tests/prepare-signed-container-fixture.sh 'VM fixture verifies its signature before packaging'
require_fixed '--signature-policy "$fixture_mount/policy-wrong.json"' tests/vm-audit.sh 'VM audit proves the wrong OCI trust root is rejected'
require_fixed '--signature-policy "$fixture_mount/policy-good.json"' tests/vm-audit.sh 'VM audit imports through a narrow valid OCI trust policy'
require_fixed 'podman run' tests/vm-audit.sh 'VM audit executes a trusted image through Podman'
require_fixed 'PARTICLEOS_VM_AUDIT_PASS' tests/vm-audit.sh 'VM audit has an unambiguous success marker'
require_fixed 'kernel.yama.ptrace_scope' tests/vm-audit.sh 'VM audit verifies the systrap-compatible Yama boundary'
require_fixed 'getsebool deny_ptrace' tests/vm-audit.sh 'VM audit verifies the global SELinux ptrace restriction'
require_fixed 'the immutable update trust key has an importd-readable label' tests/vm-audit.sh 'VM audit verifies update-key SELinux access'
require_fixed 'the udev compatibility control link is available' tests/vm-audit.sh 'VM audit verifies the udev control path'
require_fixed 'io.systemd.stub.kernel-cmdline-extra=systemd.wants=vm-audit.service' tests/run-vm-audit.sh 'VM runner requests the injected audit unit'
require_fixed 'systemd.mask=serial-getty@ttyS0.service' tests/run-vm-audit.sh 'VM runner reserves the serial console for complete audit output'
require_fixed 'readonly=on,file=$container_fixture' tests/run-vm-audit.sh 'VM runner attaches the signed-container fixture read-only'
require_fixed 'run_boot 1' tests/run-vm-audit.sh 'VM runner audits fresh TPM enrollment'
require_fixed 'run_boot 2' tests/run-vm-audit.sh 'VM runner audits persistent TPM unlock'
require_fixed 'stop_tpm' tests/run-vm-audit.sh 'VM runner stops its TPM emulator after every boot'
require_fixed 'zstd --sparse' tests/run-vm-audit.sh 'VM runner preserves sparse disk allocation'
require_fixed 'VM_AUDIT_KEEP_FAILED' tests/run-vm-audit.sh 'VM runner can preserve failed diagnostics without leaving processes running'
require_fixed 'SuccessExitStatus=143' tests/vm-audit.sh 'VM health fixture treats its normal SIGTERM shutdown as successful'
require_fixed 'Wants=boot-complete.target' tests/vm-audit.service 'VM audit waits for rollback and health gates to complete'
require_fixed 'Requires=particleos-pcrlock-enroll.service particleos-workload-health.service' mkosi.extra/usr/lib/systemd/system/boot-complete.target.d/40-particleos-security-gates.conf 'first boot includes rollback and workload-health gates in its initial transaction'
require_fixed 'particleos-workload-health.service' mkosi.extra/usr/lib/systemd/system/systemd-bless-boot.service.d/40-particleos-rollback.conf 'boot blessing depends on workload health'
require_fixed 'Wants=particleos-pcrlock-prune.service' mkosi.extra/usr/lib/systemd/system/systemd-bless-boot.service.d/40-particleos-rollback.conf 'superseded UKIs are revoked only after blessing'
require_fixed 'Notify=healthy' mkosi.extra/usr/lib/particleos/check-workload-health 'Quadlet health must gate systemd readiness'

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
require_fixed 'gpgv --keyring' scripts/validate-artifacts.sh 'artifact validation authenticates the checksum digest with the pinned OBS key'
require_fixed 'sbverify --cert' scripts/validate-artifacts.sh 'artifact validation cryptographically verifies the UKI PE signature'
require_fixed 'etc/ipe/ipe-policy\.p7b' scripts/validate-artifacts.sh 'artifact validation inspects the signed UKI for the IPE policy'
require_fixed 'particleos-containerhost-repart-archive' mkosi.scripts/obs-build 'the OBS signing stage uses the hostile-input archive policy'
require_fixed 'BuildScripts=/usr/src/packages/SOURCES/particleos-containerhost-repart-archive' mkosi.scripts/obs-postoutput 'the hostile archive validator is in the OBS signing source closure'
python3 tests/test-repart-archive-policy.py && pass 'hostile repart archive cases are rejected' || failures=$((failures + 1))

for section in \
    '## Architecture' \
    '## Security and Hardening' \
    '## Hardening Review' \
    '## Installation and Provisioning' \
    '## Diagnostics and Tests' \
    '## Residual Risks'; do
    require_fixed "$section" README.md "README contains ${section#\#\# }"
done
if [[ -e TODO ]] || find docs -type f -print -quit 2>/dev/null | grep -q .; then
    fail 'README is the sole project documentation file'
else
    pass 'README is the sole project documentation file'
fi

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
