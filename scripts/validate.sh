#!/usr/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -euo pipefail

cd "$(dirname "$0")/.."
failures=0

for command in find grep python3 rg sed shellcheck; do
    command -v "$command" >/dev/null || {
        printf 'missing required validation command: %s\n' "$command" >&2
        exit 2
    }
done

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
reject_fixed 'systemd.firstboot=headless' mkosi.conf 'the signed command line permits the native console provisioning flow'
require_fixed 'auto-firmware yes' mkosi.extra/boot/loader/loader.conf 'systemd-boot explicitly enables its reboot-into-firmware menu entry'
require_fixed 'systemd.credentials_boot_policy=strict' mkosi.conf 'null-key boot credentials are rejected by the signed UKI'
require_fixed 'rd.systemd.mask=systemd-tpm2-setup-early.service' mkosi.conf 'the unused initrd NvPCR setup path is suppressed'
require_fixed 'Include=mkosi-obs' mkosi.obs.conf 'upstream OBS signer is included'
require_fixed 'SplitArtifacts=uki,partitions,roothash,os-release,repart-definitions' mkosi.obs.conf 'OBS suppresses incompatible expected-PCR artifacts'
reject_fixed 'SplitArtifacts=pcrs' mkosi.obs.conf 'OBS does not request a PCR11 public-key policy'
require_fixed '/usr/lib/nvpcr' mkosi.conf 'unused NvPCR definitions are removed'
require_fixed 'needssslcertforbuild' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS project certificate is requested'
require_fixed '[Content]' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS image closure uses the mkosi Content section'
require_fixed '        basesystem' .obs/particleos-containerhost/x86-64/mkosi.conf 'OBS stages the implicit Fedora base package'
fedora_release=$(sed -n 's/^Release=//p' mkosi.conf)
[[ $fedora_release =~ ^[0-9]+$ ]] || {
    fail 'Fedora release is a numeric version'
    fedora_release=invalid
}
require_fixed "%if \"%_repository\" == \"fedora_${fedora_release}_images\"" .obs/project-config 'OBS image repository follows the Fedora release'
require_fixed "Release: ${fedora_release}.<CI_CNT>.<B_CNT>" .obs/project-config 'OBS image version prefixes the unique build revision with the Fedora release'

for type in usr usr-verity usr-verity-sig; do
    count="$(grep -rl "^Type=${type}$" mkosi.extra/usr/lib/repart.d | wc -l)"
    if [[ "$count" -eq 2 ]]; then pass "two ${type} A/B slots exist"; else fail "two ${type} A/B slots exist"; fi
done
require_fixed 'Encrypt=tpm2' mkosi.extra/usr/lib/repart.d/40-root.conf 'persistent state is TPM2 encrypted'
require_fixed 'TPM2PCRs=7' mkosi.extra/usr/lib/repart.d/40-root.conf 'state has a first-boot PCR7 bootstrap token'
require_fixed 'systemd-pcrlock predict' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime policy preflights the stable systemd prediction before mutating TPM NV'
require_fixed '--pcr=7 --pcr=11 --json=short' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'prediction preflight requests exactly PCR7 and PCR11'
require_fixed '"pcr":7([,}])' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'prediction preflight requires PCR7 to remain safe'
require_fixed '"pcr":11([,}])' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'prediction preflight requires PCR11 to remain safe'
require_fixed '--pcr=7 --pcr=11 --entry-token=os-image-id --force' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime state policy covers PCR7 and PCR11 with a stable image-scoped boot credential'
require_fixed "-name 'pcrlock.*.cred' ! -name \"\$credential_name\" -delete" mkosi.extra/usr/lib/particleos/pcrlock-refresh 'obsolete transient-machine-ID pcrlock credentials are retired after policy commit'
# shellcheck disable=SC2016
require_fixed '[[ ${#boot_credentials[@]} -eq 1' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'pcrlock policy refresh proves exactly one stable EFI boot credential remains'
reject_fixed '--strict' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime policy does not use the unsupported systemd v261 strict option'
require_fixed '650-particleos-uki.pcrlock.d' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'UKI records precede the enter-initrd PCR11 barrier'
require_fixed '750-particleos-uki.pcrlock.d' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'invalid development PCR11 ordering is migrated transactionally'
require_fixed 'lock-secureboot-policy' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'PCR7 policy is derived from live Secure Boot variables'
# shellcheck disable=SC2016
require_fixed 'objcopy --dump-section ".osrel=$scratch/osrelease"' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'candidate authorization verifies the UKI embedded release identity'
# shellcheck disable=SC2016
require_fixed '"$uki" "$scratch/uki.copy"' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime UKI identity inspection cannot rewrite the signed ESP input'
# shellcheck disable=SC2016
reject_fixed 'objcopy --dump-section ".osrel=$osrelease" "$resolved"' mkosi.extra/usr/lib/particleos/pcrlock-refresh 'runtime UKI inspection never invokes objcopy without a disposable output'
# shellcheck disable=SC2016
require_fixed 'pcrlock-refresh candidate "$candidate_version"' mkosi.extra/usr/lib/particleos/sysupdate 'only the authenticated sysupdate candidate is admitted'
# shellcheck disable=SC2016
require_fixed '[[ $candidate_json =~ ^\{\"available\":\"([0-9]+([.][0-9]+)*)\"\}$ ]]' mkosi.extra/usr/lib/particleos/sysupdate 'the stable systemd candidate JSON is parsed with literal quotation marks'
candidate_json='{"available":"54.1"}'
no_update_json='{"available":null}'
if [[ $candidate_json =~ ^\{\"available\":\"([0-9]+([.][0-9]+)*)\"\}$ ]] &&
        [[ ${BASH_REMATCH[1]} == 54.1 ]] &&
        [[ $no_update_json == '{"available":null}' ]] &&
        [[ ! $no_update_json =~ ^\{\"available\":\"([0-9]+([.][0-9]+)*)\"\}$ ]]; then
    pass 'candidate and no-update systemd JSON forms are unambiguous'
else
    fail 'candidate and no-update systemd JSON forms are unambiguous'
fi
reject_fixed 'pcrlock-refresh all' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate.service.d/40-particleos-egress.conf 'updates never authorize an ESP-wide UKI enumeration'
reject_fixed "-name 'ParticleOS-Host_*.efi'" mkosi.extra/usr/lib/particleos/pcrlock-refresh 'arbitrary project-signed ESP entries are not policy inputs'
require_fixed 'pcrlock-bootstrap-pending' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'bootstrap retirement records the enrollment boot'
require_fixed 'cryptsetup open --type luks2 --test-passphrase --token-only' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'the exact pcrlock token is proved on a later boot'
require_fixed 'cryptsetup reencrypt --batch-mode --token-only' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'proved PCR policy rotates the persistent-state volume key'
# shellcheck disable=SC2016
require_fixed '--token-id "$token_id" "$state"' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'volume-key rotation authenticates only through the proved PCR7+11 token'
reject_fixed '--keep-key' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'bootstrap retirement does not retain the replayable volume key'
require_fixed 'pcrlock-volume-key-rotated' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'volume-key rotation has a durable encrypted-state recovery receipt'
# shellcheck disable=SC2016
require_fixed '--wipe-slot="$bootstrap_keyslot"' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'any remaining proved-obsolete PCR7 bootstrap key slot is explicitly retired'
# shellcheck disable=SC2016
require_fixed 'cryptsetup token remove --token-id "$bootstrap_token"' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'orphaned PCR7 token metadata is explicitly retired after volume-key rotation'
require_fixed 'PARTICLEOS_PCRLOCK_FINALIZATION_RECOVERED' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'power loss after key rotation resumes without repeating or bypassing proof'
# shellcheck disable=SC2016
require_fixed '[[ $current_boot != "$previous_boot" ]]' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'bootstrap removal requires a different boot ID'
require_fixed 'systemctl --no-block reboot' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'bootstrap migration queues the proof reboot'
require_fixed 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'bootstrap migration reports an accepted reboot transaction'
reject_fixed 'while :' mkosi.extra/usr/lib/particleos/pcrlock-enroll 'the enrollment start job cannot deadlock its queued reboot'
require_fixed 'ExecStart=/usr/lib/particleos/sysupdate' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate.service.d/40-particleos-egress.conf 'the authenticated update wrapper owns PCR admission'
require_fixed 'Type=oneshot' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate.service.d/40-particleos-egress.conf 'PCR authorization waits for every update transfer to commit'
require_fixed 'TimeoutStartSec=infinity' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate.service.d/40-particleos-egress.conf 'large verified updates are not cut off by the oneshot start timeout'
require_fixed 'ExecCondition=/usr/lib/particleos/pcrlock-update-ready' mkosi.extra/usr/lib/systemd/system/systemd-sysupdate-reboot.service.d/40-particleos-pcrlock.conf 'reboot refuses an update without a committed PCR policy'
require_fixed 'enable systemd-sysupdate-reboot.timer' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'staged updates receive an automatic reboot window'
require_fixed 'enable systemd-bless-boot.service' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'boot completion and blessing are activated'
require_fixed 'disable particleos-workload-health.service' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'workload health gating is administrator opt-in'
require_fixed 'ConditionPathExists=/sys/firmware/efi/efivars/LoaderBootCountPath-' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'workload failure can reboot only a counted candidate'
require_fixed 'RequiredBy=systemd-bless-boot.service' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'opt-in creates a direct blessing requirement'
require_fixed 'Before=systemd-bless-boot.service' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'blessing waits for an enabled health gate'
require_fixed 'ExecStart=/usr/lib/particleos/workload-health-gate /usr/lib/particleos/check-workload-health' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'the production health probe rejects a failing candidate before returning'
reject_fixed '/usr/lib/systemd/systemd-bless-boot bad' mkosi.extra/usr/lib/particleos/workload-health-gate 'an unhealthy candidate retains its remaining counted attempts'
require_fixed 'PARTICLEOS_WORKLOAD_QUARANTINED' mkosi.extra/usr/lib/particleos/workload-health-gate 'a workload can delay two boots but is quarantined on the third attempt'
# shellcheck disable=SC2016
require_fixed '[[ ${#boot_ids[@]} -ge 3 ]]' mkosi.extra/usr/lib/particleos/workload-health-gate 'workload vetoes have a hard three-boot bound'
require_fixed 'ExecStart=/usr/lib/particleos/record-candidate-attempt' mkosi.extra/usr/lib/systemd/system/particleos-candidate-attempt.service 'counted candidate boots create encrypted-state receipts'
require_fixed 'enable particleos-candidate-attempt.service' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'candidate receipt recording is always active'
require_fixed 'TriesLeft=3' mkosi.sysupdate/20-uki.transfer 'locally built candidates receive three boot attempts'
require_fixed 'TriesLeft=3' mkosi.obs.extra/usr/lib/sysupdate.d/20-particleos-kernel.transfer 'OBS candidates receive three boot attempts'
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
require_fixed 'pids_limit = 512' "$containers" 'containers have a hard default process ceiling'
require_fixed 'memory.max=1073741824' "$containers" 'containers have a hard default memory ceiling'
require_fixed 'memory.swap.max=0' "$containers" 'containers cannot extend their memory ceiling through swap'
require_fixed 'cpu.max=200000 100000' "$containers" 'containers have a hard default CPU ceiling'
require_fixed 'default_ulimits = ["nofile=1024:8192", "nproc=512:512"]' "$containers" 'containers have bounded file and process rlimits'
require_fixed 'pull_policy = "always"' "$containers" 'pulls always re-evaluate image trust'
require_fixed 'network_config_dir = "/var/lib/containers/networks"' "$containers" 'Netavark definitions live in encrypted persistent state'
require_fixed 'd /var/lib/containers/networks 0700 root root -' mkosi.extra/usr/lib/tmpfiles.d/etc.conf 'persistent network definitions are administrative-only'
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
reject_fixed '(allow .init_t .udev_var_run_t (lnk_file (create)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the obsolete udev compatibility-link permission is absent'
require_fixed '(type particleos_import_key_t)' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the update key has a dedicated SELinux type'
require_fixed '(allow .systemd_importd_t .particleos_import_key_t' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'only importd receives read access to the update key'
require_fixed '(allow .initrc_t .container_runtime_t (process2 (nosuid_transition)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'system services may enter the confined runtime from authenticated /usr'
require_fixed '/usr/lib/systemd/import-pubring\.pgp -- system_u:object_r:particleos_import_key_t:s0' mkosi.postinst.chroot 'the immutable update key receives only its dedicated label'
require_fixed 'SELINUX=enforcing' mkosi.extra/etc/selinux/config 'SELinux is enforcing in userspace'
require_fixed 'authselect select local --force' mkosi.postinst.chroot 'Fedora local authentication profile is explicit'
require_fixed 'authselect enable-feature with-systemd-homed' mkosi.postinst.chroot 'Fedora PAM enables systemd-homed authentication'
require_fixed "usermod --password '!unprovisioned' root" mkosi.postinst.chroot 'root begins with the systemd-firstboot password sentinel'
require_fixed 'pam_systemd_home\.so' mkosi.postinst.chroot 'PAM activates password-encrypted homed users'
require_fixed '20-systemd-userdb.conf.example' mkosi.postinst.chroot 'the packaged homed SSH userdb integration is enabled'
for unit in \
    authselect-apply-changes.service \
    systemd-tpm2-setup-early.service \
    systemd-pcrlogin@.service \
    systemd-pcrnvdone.service \
    systemd-pcrproduct.service \
    systemd-pcrlock.socket \
    systemd-sysupdate-notify-pcrlock.socket; do
    require_fixed "$unit" mkosi.finalize "$unit is immutably masked"
done
for unit in systemd-homed.service systemd-homed-firstboot.service; do
    require_fixed "enable $unit" mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset "$unit is enabled"
    reject_fixed "    $unit \\" mkosi.finalize "$unit is not immutably masked"
done
firstboot_dropin=mkosi.extra/usr/lib/systemd/system/systemd-firstboot.service.d/40-particleos.conf
homed_firstboot_dropin=mkosi.extra/usr/lib/systemd/system/systemd-homed-firstboot.service.d/40-particleos.conf
require_fixed 'ConditionFirstBoot=' "$firstboot_dropin" 'interrupted root and timezone provisioning resumes'
require_fixed 'TTYPath=/dev/tty1' "$firstboot_dropin" 'root and timezone setup owns the primary VGA terminal'
require_fixed 'ExecStart=/usr/bin/systemd-firstboot --prompt-root-password --mute-console=yes' "$firstboot_dropin" 'the console asks for the recovery root password first'
require_fixed 'ExecStart=/usr/bin/systemd-firstboot --prompt-timezone --mute-console=yes' "$firstboot_dropin" 'the console asks for timezone second'
require_fixed 'ConditionFirstBoot=' "$homed_firstboot_dropin" 'interrupted homed provisioning resumes'
require_fixed 'TTYPath=/dev/tty1' "$homed_firstboot_dropin" 'the administrator wizard owns the primary VGA terminal'
require_fixed 'Requires=systemd-firstboot.service' "$homed_firstboot_dropin" 'homed provisioning follows root and timezone setup'
require_fixed 'Requires=particleos-pcrlock-enroll.service' "$homed_firstboot_dropin" 'homed provisioning requires rollback-policy migration'
require_fixed 'After=systemd-firstboot.service particleos-pcrlock-enroll.service' "$homed_firstboot_dropin" 'the administrator prompt follows system setup and bootstrap retirement'
require_fixed '--prompt-new-user --prompt-shell=no --prompt-groups=no' "$homed_firstboot_dropin" 'the native homed wizard asks only for username and password'
require_fixed '--member-of=wheel,systemd-journal' "$homed_firstboot_dropin" 'the native user is the run0 and journal administrator'
require_fixed '--storage=luks' "$homed_firstboot_dropin" 'the administrator receives a LUKS home image'
require_fixed '--disk-size=1G' "$homed_firstboot_dropin" 'the administrator home cannot consume container state'
require_fixed '--auto-resize-mode=off' "$homed_firstboot_dropin" 'the administrator home cannot grow automatically'
require_fixed '--nosuid=yes --nodev=yes --noexec=yes' "$homed_firstboot_dropin" 'the administrator home has restrictive mount flags'
require_fixed 'DefaultStorage=luks' mkosi.extra/usr/lib/systemd/homed.conf.d/40-particleos.conf 'homed defaults to LUKS storage'
require_fixed '--fs-type=btrfs' "$homed_firstboot_dropin" 'the native administrator home explicitly uses Btrfs'
reject_fixed 'DefaultFileSystemType=' mkosi.extra/usr/lib/systemd/homed.conf.d/40-particleos.conf 'the systemd Btrfs default is not redundantly overridden'
require_fixed 'defcontext=system_u:object_r:user_home_t:s0' mkosi.extra/usr/lib/systemd/system/systemd-homed.service.d/40-particleos-selinux.conf 'homed labels unlabeled Btrfs content before PAM enters it'
reject_fixed 'rootcontext=' mkosi.extra/usr/lib/systemd/system/systemd-homed.service.d/40-particleos-selinux.conf 'homed does not claim an ineffective root-only mount label'
require_fixed 'sysinit.target.wants/systemd-firstboot.service' mkosi.finalize 'root and timezone checks remain reachable after interruption'
require_fixed 'multi-user.target.wants/systemd-homed.service' mkosi.finalize 'homed activation is immutable across A/B updates'
require_fixed 'systemd-homed.service.wants/systemd-homed-firstboot.service' mkosi.finalize 'homed provisioning is immutable across A/B updates'
require_fixed '.systemd_homework_t .container_runtime_t .gvisor_t' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'only homed and container helpers receive user-namespace creation'
require_fixed '(allow .systemd_homed_t .systemd_homework_t (process2 (nosuid_transition)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'homed enters its confined worker from nosuid verified /usr'
require_fixed '(allow .systemd_homework_t .fsadm_t (process2 (nosuid_transition)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the homed worker enters Fedora fsadm only for filesystem creation'
require_fixed '(allow .systemd_homework_t .pidfs_t (filesystem (getattr)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'the homed worker can inspect pidfs metadata during filesystem creation'
require_fixed '(allow .policykit_auth_t .systemd_homed_t (dbus (send_msg)))' mkosi.extra/usr/lib/particleos/selinux/particleos-containerhost.cil 'run0 PAM authentication can talk to homed'
run0_policy=mkosi.extra/usr/share/polkit-1/rules.d/10-particleos-run0.rules
require_fixed 'org.freedesktop.systemd1.manage-units' "$run0_policy" 'run0 systemd authority is explicitly governed'
require_fixed 'subject.isInGroup("wheel")' "$run0_policy" 'run0 is limited to the provisioned administrator group'
require_fixed 'polkit.Result.AUTH_SELF' "$run0_policy" 'run0 requires the administrator own password'
require_fixed 'polkit.Result.NO' "$run0_policy" 'run0 denies non-administrators'
require_fixed '/usr/share/polkit-1/rules.d/empower.rules' mkosi.conf 'upstream passwordless empowerment policy is removed'
require_fixed 'run0 refuses the wheel administrator without authentication' tests/vm-audit.sh 'VM audit tests run0 authentication is mandatory'
require_fixed 'run0 denies a non-wheel account before any root-password fallback' tests/vm-audit.sh 'VM audit tests the run0 non-administrator denial'
require_fixed 'homed and run0 completed without SELinux denials' tests/vm-audit.sh 'VM audit checks homed/run0 SELinux behavior'
require_fixed 'homed-firstboot-audit' tests/run-vm-audit.sh 'VM audit provisions a disposable homed administrator without weakening production firstboot'
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
# shellcheck disable=SC2016
require_fixed 'chmod 0750 "$BUILDROOT/usr/libexec/gvisor/runsc"' mkosi.finalize 'direct runsc execution is restricted'
require_fixed 'gvisor_exec_t' mkosi.postinst.chroot 'gVisor executables receive the dedicated transition type'
require_fixed 'PasswordAuthentication no' mkosi.extra/etc/ssh/sshd_config.d/40-particleos-hardening.conf 'SSH password authentication is disabled'
require_fixed 'PermitRootLogin no' mkosi.extra/etc/ssh/sshd_config.d/40-particleos-hardening.conf 'SSH root login is disabled'
require_fixed 'DNSOverTLS=yes' mkosi.extra/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf 'strict DNS-over-TLS is enabled'
require_fixed 'DNSSEC=yes' mkosi.extra/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf 'DNSSEC is enabled'
require_fixed 'baseurl=https://download.opensuse.org/repositories/system:/systemd:/stable/Fedora_44/' mkosi.profiles/obs-repos/systemd.repo 'systemd comes from the upstream stable OBS project'
require_fixed 'repo_gpgcheck=1' mkosi.profiles/obs-repos/systemd.repo 'local systemd repository metadata is authenticated'
require_fixed 'EXPECTED_SYSTEMD_VERSION = "261.2+5+gb40ecf731-57.14"' mkosi.scripts/validate-systemd-manifest 'the reviewed systemd build is exact'
reject_fixed 'rpm -q --qf' mkosi.postinst.chroot 'the minimal image does not need the RPM CLI for build validation'
require_fixed 'PostOutputScripts=%D/mkosi.scripts/validate-systemd-manifest' mkosi.conf 'local builds enforce the exact systemd package manifest'
require_fixed 'PostOutputScripts=%D/mkosi.scripts/validate-systemd-manifest' mkosi.obs.conf 'OBS publication enforces the exact systemd package manifest'
require_fixed 'EXPECTED_SYSTEMD_PACKAGES' mkosi.scripts/validate-systemd-manifest 'the reviewed systemd package set is exact'
require_fixed 'systemd package set differs' mkosi.scripts/validate-systemd-manifest 'unexpected systemd subpackages fail closed'
# Literal implementation string, not an expression for this validator.
# shellcheck disable=SC2016
require_fixed 'OUTPUTDIR="$directory" "$repository/mkosi.scripts/validate-systemd-manifest"' scripts/validate-artifacts.sh 'downloaded releases revalidate the exact systemd package manifest'
require_fixed '0B2264A151F114677B1D0AAF25688B9E8208EED3' mkosi.postinst.chroot 'the runtime update key has one pinned primary fingerprint'
reject_fixed 'packages built from upstream main' mkosi.profiles/obs-repos/systemd.repo 'the image no longer consumes moving systemd main'
require_fixed '        binutils' mkosi.conf 'objcopy is present for runtime UKI identity verification'

manager_policy=mkosi.extra/usr/lib/systemd/system.conf.d/40-particleos-hardening.conf
require_fixed 'DefaultEnvironment="LD_PRELOAD=libno_rlimit_as.so"' "$manager_policy" 'no_rlimit_as remains in the service environment'
reject_fixed 'libhardened_malloc.so' "$manager_policy" 'hardened_malloc is not redundantly listed in the service environment'
require_fixed 'libhardened_malloc.so' mkosi.extra/etc/ld.so.preload 'hardened_malloc uses the native global preload path'
reject_fixed 'DefaultMemoryAccounting=' "$manager_policy" 'systemd owns its memory-accounting default'
reject_fixed 'DefaultTasksAccounting=' "$manager_policy" 'systemd owns its task-accounting default'

journal_policy=mkosi.extra/usr/lib/systemd/journald.conf.d/40-particleos.conf
for inherited in Storage= Compress= Seal= MaxLevelKMsg= Audit=; do
    reject_fixed "$inherited" "$journal_policy" "journald inherits $inherited from systemd"
done
resolved_policy=mkosi.extra/usr/lib/systemd/resolved.conf.d/40-particleos-dns.conf
for inherited in Cache= DNSStubListener=; do
    reject_fixed "$inherited" "$resolved_policy" "resolved inherits $inherited from systemd"
done

sysctl_network=mkosi.extra/usr/lib/sysctl.d/60-particleos-network.conf
for transport_setting in \
    net.core.default_qdisc \
    net.ipv4.tcp_congestion_control \
    net.ipv4.tcp_ecn \
    net.ipv4.tcp_slow_start_after_idle \
    net.ipv4.tcp_shrink_window \
    net.ipv4.tcp_notsent_lowat \
    net.ipv4.tcp_fin_timeout \
    net.ipv4.tcp_tw_reuse \
    net.ipv4.tcp_syn_retries \
    net.ipv4.tcp_synack_retries \
    net.ipv4.tcp_retries2 \
    net.ipv4.tcp_orphan_retries \
    net.core.rmem_default \
    net.core.wmem_default; do
    if grep -qE "^[[:space:]-]*${transport_setting//./[.]}[[:space:]]*=" "$sysctl_network"; then
        fail "$transport_setting follows Fedora and kernel policy"
    else
        pass "$transport_setting follows Fedora and kernel policy"
    fi
done
require_fixed 'net.ipv4.tcp_rfc1337 = 1' "$sysctl_network" 'TIME-WAIT assassination protection remains explicit'

sysctl_hardening=mkosi.extra/usr/lib/sysctl.d/70-particleos-hardening.conf
reject_fixed 'fs.protected_hardlinks =' "$sysctl_hardening" 'Fedora owns protected-hardlink policy'
reject_fixed 'fs.protected_symlinks =' "$sysctl_hardening" 'Fedora owns protected-symlink policy'
reject_fixed 'kernel.core_uses_pid =' "$sysctl_hardening" 'systemd owns the core PID naming default'

for module in sch_fq tcp_bbr; do
    if grep -qxF "$module" mkosi.extra/usr/lib/particleos/modules.conf; then
        fail "$module is absent from the fixed pre-lockdown module set"
    else
        pass "$module is absent from the fixed pre-lockdown module set"
    fi
done
require_fixed 'blacklist pcspkr' mkosi.extra/usr/lib/modprobe.d/00-pcspkr-blacklist.conf 'the upstream pc-speaker blacklist is restored'

ethernet_profile=mkosi.extra/usr/lib/systemd/network/89-ethernet.network
if [[ -L $ethernet_profile && $(readlink "$ethernet_profile") == 89-ethernet.network.example ]]; then
    pass 'networkd uses the upstream ParticleOS Ethernet profile'
else
    fail 'networkd uses the upstream ParticleOS Ethernet profile'
fi
require_fixed 'IPv6AcceptRA=yes' mkosi.extra/usr/lib/systemd/network/89-ethernet.network.d/40-particleos-dns.conf 'the upstream Ethernet profile retains IPv6 RA while forwarding'

chrony_hardening=mkosi.extra/usr/lib/systemd/system/chronyd.service.d/40-particleos-hardening.conf
reject_fixed 'ProtectClock=yes' "$chrony_hardening" 'chronyd retains CAP_SYS_TIME for clock synchronization'
for inherited in \
    LockPersonality=yes \
    MemoryDenyWriteExecute=yes \
    PrivateTmp=yes \
    ProtectControlGroups=yes \
    ProtectHome=yes \
    ProtectHostname=yes \
    ProtectKernelLogs=yes \
    ProtectKernelModules=yes \
    ProtectKernelTunables=yes \
    ProtectSystem=strict \
    RestrictNamespaces=yes \
    RestrictSUIDSGID=yes \
    SystemCallArchitectures=native; do
    reject_fixed "$inherited" "$chrony_hardening" "chronyd inherits $inherited from Fedora"
done

nftables_hardening=mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf
reject_fixed 'ConditionPathExists=' "$nftables_hardening" 'nftables does not clear a nonexistent vendor condition'
reject_fixed 'Wants=network-pre.target' "$nftables_hardening" 'nftables inherits its network-pre ordering from Fedora'
reject_fixed 'Before=network-pre.target' "$nftables_hardening" 'nftables inherits its network-pre placement from Fedora'
reject_fixed 'ProtectHome=yes' "$nftables_hardening" 'nftables inherits home protection from Fedora'

for runtime_assertion in \
    'Fedora and systemd supply the inherited link and core PID protections' \
    'systemd supplies memory and task accounting by default' \
    'chronyd inherits hardened_malloc and no_rlimit_as through their native paths' \
    'chronyd inherits Fedora service hardening while retaining CAP_SYS_TIME' \
    'the administrator home is Btrfs and mounts nosuid,nodev,noexec with its SELinux label' \
    'the upstream ParticleOS Ethernet profile owns the primary VM interface' \
    'the upstream Ethernet profile is routable and retains IPv6 RA with forwarding' \
    'nftables inherits Fedora home protection and network-pre ordering' \
    'Fedora transport defaults replace BBR/FQ without preloading their modules' \
    'the upstream pc-speaker blacklist remains effective before module lockdown' \
    'journald supplies persistent, compressed, sealing-enabled, audit-enabled defaults' \
    'resolved supplies its cache and local stub defaults'; do
    require_fixed "$runtime_assertion" tests/vm-audit.sh "VM audit verifies $runtime_assertion"
done

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
require_fixed 'type ifname . ipv4_addr . inet_service' "$firewall" 'IPv4 forwarding policy is scoped to an exact Podman bridge'
require_fixed 'type ifname . ipv6_addr . inet_service' "$firewall" 'IPv6 forwarding policy is scoped to an exact Podman bridge'
require_fixed 'iifname . ip daddr . tcp dport @workload_egress_tcp4' "$firewall" 'workload egress lookup includes the ingress bridge'
require_fixed 'iifname "podman*" return' "$firewall" 'Podman traffic reaches exact forwarding policy after source validation'
require_fixed 'iifname "podman*" udp dport 53 counter reject' "$firewall" 'workload DNS over UDP is explicitly blocked'
require_fixed 'iifname "podman*" tcp dport 53 counter reject with tcp reset' "$firewall" 'workload DNS over TCP is explicitly blocked'
reject_fixed 'iifname "podman*" udp dport 53 accept' "$firewall" 'the host DNS proxy is not a workload exfiltration path'
reject_fixed 'iifname "podman*" accept' "$firewall" 'no unrestricted workload forwarding remains'
reject_fixed 'oifname "podman*" ct status dnat accept' "$firewall" 'no unrestricted DNAT forwarding remains'
require_fixed 'include "/etc/particleos/nftables.d/*.nft"' "$firewall" 'root-owned exact forwarding policy persists across boot'
reject_fixed 'flush ruleset' "$firewall" 'host policy does not erase Netavark rules'
require_fixed 'nft_hash' mkosi.extra/usr/lib/particleos/modules.conf 'nftables meter support loads before module lockdown'
require_fixed 'nft_limit' mkosi.extra/usr/lib/particleos/modules.conf 'nftables rate limiting loads before module lockdown'
require_fixed 'After=sysinit.target' mkosi.extra/usr/lib/systemd/system/particleos-module-preload.service 'container-only module preload runs outside the boot-critical sysinit transaction'
require_fixed 'Before=nftables.service particleos-module-lockdown.service network-pre.target' mkosi.extra/usr/lib/systemd/system/particleos-module-preload.service 'fixed modules load before firewall, networking, and irreversible lockdown'
require_fixed 'ExecStart=/usr/lib/particleos/load-modules' mkosi.extra/usr/lib/systemd/system/particleos-module-preload.service 'the fixed module list uses the verified sequential loader'
# shellcheck disable=SC2016
require_fixed '[[ $module =~ ^[a-z0-9_]+$ && -z ${extra:-} ]]' mkosi.extra/usr/lib/particleos/load-modules 'the sequential loader rejects malformed module-list entries'
require_fixed 'Requires=particleos-module-preload.service' mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf 'firewall startup requires the fixed module preload'
require_fixed 'Requires=nftables.service particleos-module-preload.service' mkosi.extra/usr/lib/systemd/system/particleos-module-lockdown.service 'irreversible lockdown requires both firewall and fixed modules'
require_fixed 'Requires=particleos-module-preload.service nftables.service particleos-module-lockdown.service' mkosi.extra/usr/lib/systemd/system/particleos-network-security.target 'network activation has one fail-closed security boundary'
require_fixed 'Requires=particleos-network-security.target' mkosi.extra/usr/lib/systemd/system/systemd-networkd.service.d/40-particleos-security.conf 'networkd cannot start without the security boundary'
require_fixed 'Requires=particleos-network-security.target' mkosi.extra/usr/lib/systemd/system/systemd-user-sessions.service.d/40-particleos-security.conf 'administrator sessions cannot start after a security-boundary failure'
require_fixed 'OnFailure=emergency.target' mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf 'firewall failure enters emergency mode'
require_fixed 'TriggerLimitBurst=0' mkosi.extra/usr/lib/systemd/system/sshd.socket.d/40-particleos-firewall.conf 'distributed unauthenticated connections cannot disable SSH socket activation'
reject_fixed '/usr/lib/modules-load.d/particleos.conf' mkosi.extra/usr/lib/particleos/load-modules 'container-only modules are not loaded in the boot-critical generic sysinit loader'
reject_fixed 'nft delete table inet particleos_filter' mkosi.extra/usr/lib/systemd/system/nftables.service.d/40-particleos-policy.conf 'firewall startup has no expected deletion error'
require_fixed 'MakeDirectories=/boot /efi' mkosi.extra/usr/lib/repart.d/40-root.conf 'the formatted root provides both boot-manager mountpoints'
reject_fixed 'root_skeleton/boot' mkosi.finalize 'the finalizer does not rely on copied empty mountpoints'
reject_fixed 'root_skeleton/efi' mkosi.finalize 'the finalizer does not rely on a copied empty ESP mountpoint'
require_fixed 'Label=ParticleESP' mkosi.repart/00-esp.conf 'the published disk ESP has a stable GPT partition label'
require_fixed 'Label=ParticleESP' mkosi.extra/usr/lib/repart.d/00-esp.conf 'runtime repart preserves the stable ESP GPT partition label'
require_fixed 'What=/dev/disk/by-partlabel/ParticleESP' mkosi.extra/usr/lib/systemd/system/efi.mount 'the ESP mount resolves only the labeled ESP partition'
require_fixed 'Where=/efi' mkosi.extra/usr/lib/systemd/system/efi.mount 'the ESP has one explicit boot-manager path'
require_fixed 'Options=umask=0077,nodev,nosuid,noexec' mkosi.extra/usr/lib/systemd/system/efi.mount 'the writable ESP is root-only and non-executable after boot'
require_fixed 'Requires=particleos-esp-module.service' mkosi.extra/usr/lib/systemd/system/efi.mount 'the ESP mount requires its early signed filesystem module'
require_fixed 'DefaultDependencies=no' mkosi.extra/usr/lib/systemd/system/particleos-esp-module.service 'the ESP filesystem module can load before local filesystems'
require_fixed 'ExecStart=/usr/sbin/modprobe -- vfat' mkosi.extra/usr/lib/systemd/system/particleos-esp-module.service 'the early module loader is limited to vfat'
require_fixed 'PrivateTmp=no' mkosi.extra/usr/lib/systemd/system/particleos-esp-module.service 'the early ESP module loader does not acquire the tmpfiles local-fs dependency'
reject_fixed 'PrivateTmp=yes' mkosi.extra/usr/lib/systemd/system/particleos-esp-module.service 'the early ESP module loader cannot create a local-fs ordering cycle'
if grep -qxF 'vfat' mkosi.extra/usr/lib/particleos/modules.conf; then
    fail 'the early ESP module is absent from the later container module list'
else
    pass 'the early ESP module is absent from the later container module list'
fi
require_fixed 'Requires=efi.mount' mkosi.extra/usr/lib/systemd/system/local-fs.target.d/40-particleos-esp.conf 'local filesystems require the explicit ESP mount'
require_fixed 'RequiresMountsFor=/efi' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-enroll.service 'PCR enrollment cannot proceed without the mounted ESP'
require_fixed 'LoadCredential=vm-audit' tests/vm-audit-getty.conf 'VM audit is injected without modifying the image'
require_fixed 'SuccessAction=poweroff' tests/vm-audit-getty.conf 'successful VM audits power off the guest'
require_fixed 'FailureAction=poweroff' tests/vm-audit-getty.conf 'failed VM audits power off the guest'
require_fixed 'ExecStart=' tests/vm-audit-getty.conf 'VM audit replaces the generated getty command instead of appending to it'
require_fixed 'Restart=no' tests/vm-audit-getty.conf 'VM audit cannot inherit the getty restart loop'
require_fixed 'ConditionPathExists=' tests/vm-audit-getty.conf 'VM audit clears the physical-VT condition before adding its initrd guard'
# shellcheck disable=SC2016
require_fixed '--sign-identity "$signed_identity"' tests/prepare-signed-container-fixture.sh 'VM fixture signs an exact OCI identity'
require_fixed 'busybox@sha256:fc6dddc4c44b1bfe37f41cae8e67d1693828e8f42a91862816d7953e2c9d3f23' tests/prepare-signed-container-fixture.sh 'VM fixture source is immutable by default'
# Literal implementation strings, not expressions for this validator.
# shellcheck disable=SC2016
require_fixed '"$repository/scripts/validate-artifacts.sh" "$artifact_directory"' tests/prepare-ovmf-vars.sh 'OVMF trust enrollment begins with independent release authentication'
# shellcheck disable=SC2016
require_fixed '--set-pk "$owner"' tests/prepare-ovmf-vars.sh 'the VM Secure Boot owner key is the authenticated project certificate'
# shellcheck disable=SC2016
require_fixed '--add-kek "$owner"' tests/prepare-ovmf-vars.sh 'the VM Secure Boot exchange key is the authenticated project certificate'
# shellcheck disable=SC2016
require_fixed '--add-db "$owner"' tests/prepare-ovmf-vars.sh 'the VM Secure Boot allow database contains the authenticated project certificate'
reject_fixed 'microsoft' tests/prepare-ovmf-vars.sh 'the test Secure Boot trust store has no unrelated vendor authority'
require_fixed 'policy-wrong.json' tests/prepare-signed-container-fixture.sh 'VM fixture carries an unrelated negative-test trust root'
# shellcheck disable=SC2016
require_fixed 'skopeo --policy "$host_policy" copy' tests/prepare-signed-container-fixture.sh 'VM fixture verifies its signature before packaging'
# shellcheck disable=SC2016
require_fixed '--signature-policy "$fixture_mount/policy-wrong.json"' tests/vm-audit.sh 'VM audit proves the wrong OCI trust root is rejected'
# shellcheck disable=SC2016
require_fixed '--signature-policy "$fixture_mount/policy-good.json"' tests/vm-audit.sh 'VM audit imports through a narrow valid OCI trust policy'
require_fixed 'podman run' tests/vm-audit.sh 'VM audit executes a trusted image through Podman'
require_fixed 'CapabilityBoundingSet=' tests/vm-audit.sh 'VM audit clears every capability before probing direct runsc execution'
require_fixed 'PARTICLEOS_VM_AUDIT_PASS' tests/vm-audit.sh 'VM audit has an unambiguous success marker'
require_fixed 'kernel.yama.ptrace_scope' tests/vm-audit.sh 'VM audit verifies the systrap-compatible Yama boundary'
require_fixed 'getsebool deny_ptrace' tests/vm-audit.sh 'VM audit verifies the global SELinux ptrace restriction'
require_fixed 'the immutable update trust key has an importd-readable label' tests/vm-audit.sh 'VM audit verifies update-key SELinux access'
require_fixed 'the udev control socket is active and responsive' tests/vm-audit.sh 'VM audit exercises the systemd v261 udev control socket'
require_fixed 'bootctl --print-boot-path' tests/vm-audit.sh 'VM audit asks the boot manager for its active ESP path'
require_fixed 'systemctl is-active --quiet efi.mount' tests/vm-audit.sh 'VM audit requires the explicit ESP mount unit to be active'
require_fixed 'systemctl is-active --quiet particleos-esp-module.service' tests/vm-audit.sh 'VM audit proves the early ESP module service completed'
# shellcheck disable=SC2016
require_fixed 'mountpoint -q "$boot_path"' tests/vm-audit.sh 'VM audit proves the ESP is mounted rather than a plain directory'
require_fixed 'systemd.unit-dropin.getty@tty1.service~90-particleos-vm-audit' tests/run-vm-audit.sh 'VM runner replaces the generated primary console command with the audit'
require_fixed 'systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit' tests/run-vm-audit.sh 'mandatory root-remount completion explicitly starts the injected audit unit'
require_fixed 'ExecStartPost=/usr/bin/systemctl --no-block start getty@tty1.service' tests/audit-activate.conf 'credential-backed test activation starts without blocking sysinit'
require_fixed 'systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit' tests/run-vm-audit.sh 'PCR enrollment output is captured by the audit console'
require_fixed 'systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit' tests/run-vm-audit.sh 'VM audit captures post-udev ESP diagnostics'
require_fixed '[[ ! -e /etc/initrd-release ]] || exit 0' tests/boot-audit-diagnostic 'VM diagnostics do not condition or suppress initrd udev coldplug'
require_fixed 'ID_PART_ENTRY_NAME' tests/boot-audit-diagnostic 'VM boot diagnostics expose the udev GPT identity'
require_fixed 'systemd.mask=serial-getty@ttyS0.service' tests/run-vm-audit.sh 'VM runner reserves the serial console for complete audit output'
# shellcheck disable=SC2016
require_fixed 'readonly=on,file=$container_fixture' tests/run-vm-audit.sh 'VM runner attaches the signed-container fixture read-only'
require_fixed 'run_boot 1 enrollment' tests/run-vm-audit.sh 'VM runner stages PCR7+11 while retaining bootstrap'
require_fixed 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED ' tests/run-vm-audit.sh 'VM runner requires the enrollment proof reboot transaction'
require_fixed 'run_boot 2 audit' tests/run-vm-audit.sh 'VM runner proves the PCR7+11 token on a later boot'
require_fixed 'run_boot 3 audit' tests/run-vm-audit.sh 'VM runner audits persistent TPM unlock'
require_fixed 'stop_tpm' tests/run-vm-audit.sh 'VM runner stops its TPM emulator after every boot'
require_fixed 'zstd --sparse' tests/run-vm-audit.sh 'VM runner preserves sparse disk allocation'
require_fixed 'VM_AUDIT_KEEP_FAILED' tests/run-vm-audit.sh 'VM runner can preserve failed diagnostics without leaving processes running'
require_fixed 'VM_AUDIT_DISPLAY must be none or gtk' tests/run-vm-audit.sh 'VM runner exposes an explicit local GTK display mode'
require_fixed 'VM_UPDATE_AUDIT_DISPLAY must be none or gtk' tests/run-update-rollback-audit.sh 'update runner exposes an explicit local GTK display mode'
require_fixed 'FIRSTBOOT_VM_DISPLAY must be none or gtk' tests/run-firstboot-console-audit.sh 'native firstboot runner exposes a visible GTK display by default'
require_fixed 'FIRSTBOOT_QMP_SOCKET=' tests/run-firstboot-console-audit.sh 'native firstboot automation controls the visible VGA console through QMP'
require_fixed 'screendump' tests/firstboot-console-expect.py 'native firstboot OCR reads the actual VGA framebuffer'
require_fixed 'input-send-event' tests/firstboot-console-expect.py 'native firstboot answers prompts through the VGA keyboard path'
require_fixed 'tesseract' tests/firstboot-console-expect.py 'native firstboot verifies visible prompt text with OCR'
reject_fixed 'systemd.unit-dropin.systemd-firstboot.service~90-particleos-serial' tests/run-firstboot-console-audit.sh 'native root and timezone setup is not redirected away from VGA'
reject_fixed 'systemd.unit-dropin.systemd-homed-firstboot.service~90-particleos-serial' tests/run-firstboot-console-audit.sh 'native user setup is not redirected away from VGA'
reject_fixed 'systemd.mask=particleos-pcrlock-enroll.service' tests/run-firstboot-console-audit.sh 'the prompt audit includes the real rollback enrollment reboot'
require_fixed '"enter the new root password", "empty to skip"' tests/firstboot-console-expect.py 'the VGA audit sees and answers the recovery root password first'
require_fixed '"enter the new timezone", "name or number"' tests/firstboot-console-expect.py 'the VGA audit sees and answers timezone second'
require_fixed '"enter user name", "create"' tests/firstboot-console-expect.py 'the VGA audit sees and answers the native homed username third'
require_fixed '"enter new password", "particleadmin", "repeat"' tests/firstboot-console-expect.py 'the VGA audit sees and answers the homed password last'
require_fixed 'FIRSTBOOT_VGA_PROMPT_VISIBLE' tests/firstboot-console-expect.py 'the VGA audit reports every visually recognized setup prompt'
require_fixed 'SYSTEMD_BOOT_FIRMWARE_ENTRY_VISIBLE' tests/firstboot-console-expect.py 'the VGA audit proves the firmware entry is actually rendered'
require_fixed "readonly password='VgaAdmin261Secure'" tests/firstboot-console-audit 'the guest audit uses the VGA-provisioned administrator password'
require_fixed 'PARTICLEOS_ADMIN_SHELL_READY' tests/firstboot-console-expect.py 'the prompt audit waits for an authenticated homed login shell'
require_fixed 'run0 --no-ask-password --pipe /usr/bin/true' tests/firstboot-console-expect.py 'the console audit rejects unauthenticated run0 elevation'
require_fixed '&& exit 97 ||' tests/firstboot-console-expect.py 'the console audit aborts before authenticated run0 if unauthenticated elevation succeeds'
require_fixed 'run0 --pipe /usr/bin/bash /run/particleos-firstboot-run0-audit' tests/firstboot-console-expect.py 'the native account authenticates run0 on its active console'
require_fixed '_TRANSPORT=audit' tests/firstboot-console-audit 'the console audit reads kernel audit records from journald'
require_fixed 'SERVICE_STOP.*unit=polkit-agent-helper@.*res=success' tests/firstboot-console-audit 'the console audit requires successful polkit helper completion'
require_fixed 'for _ in {1..20}' tests/firstboot-console-audit 'the console audit bounds asynchronous journal indexing retries'
require_fixed '/usr/bin/sleep 0.25' tests/firstboot-console-audit 'the run0 audit tolerates only a short audit-journal propagation delay'
require_fixed '==== AUTHENTICATION COMPLETE ====' tests/firstboot-console-expect.py 'the console audit observes interactive authentication completion'
require_fixed 'ExecStart=/usr/sbin/agetty ' tests/firstboot-console-audit.conf 'the run0 audit creates a real getty, PAM, and logind login session'
require_fixed 'StandardInput=tty-force' tests/firstboot-console-audit.conf 'the run0 audit owns a real controlling console'
require_fixed 'PARTICLEOS_FIRSTBOOT_CONSOLE_PASS ' tests/firstboot-console-expect.py 'the native provisioning audit has an unambiguous success marker'
require_fixed 'SuccessAction=poweroff' tests/firstboot-console-audit.conf 'the native firstboot guest powers off after success'
require_fixed 'FailureAction=poweroff' tests/firstboot-console-audit.conf 'the native firstboot guest powers off after failure'
require_fixed 'state=inactive' tests/homed-ssh-firstboot-audit 'the SSH audit begins with a locked homed account'
require_fixed 'userdbctl ssh-authorized-keys' tests/homed-ssh-firstboot-audit 'the SSH audit verifies the key is available before home activation'
require_fixed 'PasswordAuthentication=no' tests/homed-ssh-expect.py 'the SSH audit cannot fall back to an SSH password'
require_fixed 'please enter password for user particleadmin' tests/homed-ssh-expect.py 'the SSH audit answers only the homed fallback-shell prompt'
require_fixed 'PARTICLEOS_HOMED_SSH_UNLOCK_PASS' tests/homed-ssh-expect.py 'the SSH audit proves an interactive key-then-home-password login'
require_fixed 'PARTICLEOS_HOMED_SSH_AVC_PASS' tests/homed-ssh-expect.py 'the SSH audit rejects SELinux denials on the unlock path'
require_fixed 'HOMED_SSH_VM_DISPLAY:-gtk' tests/run-homed-ssh-audit.sh 'the homed SSH audit exposes a visible VM by default'
require_fixed 'mktemp -d /tmp/phs.XXXXXXXX' tests/run-homed-ssh-audit.sh 'the homed SSH audit keeps TPM socket paths below the Unix socket limit'
require_fixed 'ParticleOS homed SSH unlock audit passed' tests/run-homed-ssh-audit.sh 'the homed SSH runner has an unambiguous success marker'
require_fixed 'Requires=particleos-pcrlock-enroll.service systemd-homed-firstboot.service particleos-network-security.target' tests/vm-audit-getty.conf 'the VM audit cannot race administrator creation or network security'
require_fixed 'Requires=particleos-pcrlock-enroll.service systemd-homed-firstboot.service' tests/update-rollback-audit-getty.conf 'the update audit cannot race native administrator creation'
require_fixed 'After=particleos-pcrlock-enroll.service particleos-pcrlock-fallback-prune.service systemd-homed-firstboot.service' tests/update-rollback-audit-getty.conf 'the update audit waits for fallback policy cleanup when the base supports it'
require_fixed 'SuccessAction=none' tests/update-rollback-audit-getty.conf 'the update audit cannot replace a production reboot with test poweroff'
reject_fixed 'SuccessAction=poweroff' tests/update-rollback-audit-getty.conf 'the update audit leaves successful reboot control to production units'
reject_fixed 'systemd-bless-boot.service' tests/update-rollback-audit-getty.conf 'the getty audit cannot form a boot-completion ordering cycle'
reject_fixed 'particleos-pcrlock-prune.service' tests/update-rollback-audit-getty.conf 'the getty audit cannot form a pruning ordering cycle'
require_fixed 'ExecStartPost=/usr/bin/bash %d/update-rollback-audit' tests/update-rollback-prune-audit.conf 'the lifecycle audit completes only after production PCR pruning'
reject_fixed '^ExecStart=' tests/update-rollback-prune-audit.conf 'the post-prune audit cannot replace the production pruning command'
require_fixed 'systemd.unit-dropin.particleos-pcrlock-prune.service~90-particleos-audit' tests/run-update-rollback-audit.sh 'the VM audit attaches its completion check to production PCR pruning'
require_fixed 'enable particleos-pcrlock-fallback-prune.service' mkosi.extra/usr/lib/systemd/system-preset/10-particleos.preset 'rejected candidates are revoked on the known-good fallback boot'
require_fixed 'ConditionPathExists=!/sys/firmware/efi/efivars/LoaderBootCountPath-' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-fallback-prune.service 'fallback pruning cannot race a counted candidate'
require_fixed 'RequiredBy=multi-user.target' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-fallback-prune.service 'failed fallback pruning blocks normal host operation'
require_fixed 'OnFailure=emergency.target' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-fallback-prune.service 'failed fallback pruning stops without another reboot loop'
require_fixed 'OnFailureJobMode=replace-irreversibly' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-fallback-prune.service 'fallback cleanup failure cannot be canceled back into normal host operation'
# shellcheck disable=SC2016
require_fixed '[[ ${#unique_boots[@]} -eq 3 ]]' mkosi.extra/usr/lib/particleos/pcrlock-prune-fallback 'fallback pruning requires three unique encrypted-state boot receipts'
require_fixed 'pcrlock-candidate-attempts' mkosi.extra/usr/lib/particleos/pcrlock-prune-fallback 'fallback authorization is independent of mutable ESP filenames'
reject_fixed '+0-' mkosi.extra/usr/lib/particleos/pcrlock-prune-fallback 'mutable boot-count filenames are never rejection authority'
require_fixed 'ConditionResult --value' tests/update-rollback-audit.sh 'the lifecycle audit proves fallback pruning was eligible on the known-good boot'
require_fixed 'Result --value' tests/update-rollback-audit.sh 'the lifecycle audit proves fallback pruning completed successfully'
require_fixed 'PARTICLEOS_PCRLOCK_FALLBACK_PRUNED base=' tests/update-rollback-audit.sh 'the lifecycle audit verifies the production fallback-prune journal marker'
require_fixed 'UPDATE_ROLLBACK_AUDIT_FALLBACK_PRUNE_CONFIRMED' tests/run-update-rollback-audit.sh 'the host audit requires guest confirmation of fallback authorization pruning'
require_fixed 'SuccessExitStatus=143' tests/vm-audit.sh 'VM health fixture treats its normal SIGTERM shutdown as successful'
reject_fixed 'After=multi-user.target' tests/vm-audit-getty.conf 'VM audit avoids a target ordering cycle in the generated getty transaction'
reject_fixed 'particleos-workload-health.service' tests/vm-audit-getty.conf 'disabled workload-health policy cannot create an indirect multi-user ordering cycle'
require_fixed 'BASE_ARTIFACT_DIRECTORY CANDIDATE_ARTIFACT_DIRECTORY' tests/run-update-rollback-audit.sh 'update audit requires separately authenticated base and candidate releases'
require_fixed 'systemd.unit-dropin.getty@tty1.service~90-particleos-update-audit' tests/run-update-rollback-audit.sh 'update audit uses the generated primary console activation slot'
require_fixed 'systemd.unit-dropin.systemd-remount-fs.service~90-particleos-audit' tests/run-update-rollback-audit.sh 'update audit starts from a mandatory boot unit on initial and later boots'
require_fixed 'systemd.unit-dropin.particleos-pcrlock-enroll.service~90-particleos-audit' tests/run-update-rollback-audit.sh 'update audit captures PCR enrollment output'
require_fixed 'systemd.unit-dropin.systemd-udev-trigger.service~90-particleos-audit' tests/run-update-rollback-audit.sh 'update audit captures post-udev ESP diagnostics'
reject_fixed 'After=multi-user.target' tests/update-rollback-audit-getty.conf 'update audit avoids a target ordering cycle in the generated getty transaction'
reject_fixed 'particleos-workload-health.service' tests/update-rollback-audit-getty.conf 'update scenarios control optional health without an activation-cycle dependency'
require_fixed 'systemd.unit-dropin.particleos-workload-health.service~90-particleos-update-audit' tests/run-update-rollback-audit.sh 'rollback audit replaces only the production health probe'
# shellcheck disable=SC2016
require_fixed 'pcrlock.${IMAGE_ID}.cred' tests/update-rollback-audit.sh 'update audit requires one stable image-scoped pcrlock boot credential on every boot'
require_fixed 'pcrlock.ParticleOS-Host.cred' tests/vm-audit.sh 'full VM audit rejects transient-machine-ID pcrlock boot credentials'
require_fixed 'UPDATE_ROLLBACK_AUDIT_OLD_UKI_REJECT' tests/update-rollback-audit.sh 'rollback audit reproduces and rejects renamed old signed UKI admission'
require_fixed 'UPDATE_ROLLBACK_AUDIT_USRHASH hash=' tests/update-rollback-audit.sh 'the guest reports explicit per-boot verity identity instead of relying on lossy kernel serial output'
require_fixed 'missing explicit usrhash evidence' tests/run-update-rollback-audit.sh 'the update runner fails clearly when guest verity identity evidence is absent'
require_fixed 'UPDATE_ROLLBACK_AUDIT_OLD_UKI_ONESHOT' tests/update-rollback-audit.sh 'the blessed candidate records the exact superseded UKI selected for the denial boot'
# shellcheck disable=SC2016
require_fixed 'PARTICLEOS_WORKLOAD_QUARANTINED version=$candidate_version attempts=3 status=1' tests/run-update-rollback-audit.sh 'the host audit ties candidate blessing to the exact third-attempt quarantine event'
require_fixed 'VM_UPDATE_AUDIT_SCENARIO' tests/run-update-rollback-audit.sh 'individual rollback scenarios can be reproduced without rerunning unrelated lifecycle boots'
require_fixed 'did not have the expected boot count and usrhash' tests/run-update-rollback-audit.sh 'counted-attempt failures retain actionable guest diagnostics'
require_fixed 'UPDATE_ROLLBACK_AUDIT_COUNTED_HOST_FAILURE' tests/run-update-rollback-audit.sh 'early injected host failures are tied to the exact counted candidate filename'
require_fixed 'UPDATE_ROLLBACK_AUDIT_JSON' tests/update-rollback-audit.sh 'update audit verifies stable systemd machine-readable candidate metadata'
require_fixed 'systemctl status --no-pager --full systemd-sysupdate.service' tests/update-rollback-audit.sh 'update audit preserves the production service failure cause'
require_fixed 'run_guest rollback-denial 0 enrollment' tests/run-update-rollback-audit.sh 'update audit preserves bootstrap through a separate enrollment boot'
require_fixed 'PARTICLEOS_PCRLOCK_BOOTSTRAP_REBOOT_QUEUED ' tests/run-update-rollback-audit.sh 'update audit requires the enrollment proof reboot transaction'
require_fixed 'systemctl --no-block start systemd-sysupdate-reboot.service' tests/update-rollback-audit.sh 'update audit queues the production automatic reboot service without racing its own cancellation'
reject_fixed 'sleep 30' tests/update-rollback-audit.sh 'update audit start jobs cannot deadlock production reboot actions'
# shellcheck disable=SC2016
require_fixed '[[ -e $ready ]]' tests/update-rollback-audit.sh 'an unhealthy unblessed candidate retains the fallback PCR policy until reboot'
require_fixed 'PARTICLEOS_WORKLOAD_CANDIDATE_FAILED' tests/run-update-rollback-audit.sh 'rollback audit observes each failed counted candidate boot'
require_fixed 'assert_counted_attempt 2 2 1' tests/run-update-rollback-audit.sh 'rollback audit proves the first counted candidate boot leaves two attempts'
require_fixed 'assert_counted_attempt 3 1 2' tests/run-update-rollback-audit.sh 'rollback audit proves the second counted candidate boot leaves one attempt'
require_fixed 'assert_counted_attempt 4 0 3' tests/run-update-rollback-audit.sh 'rollback audit proves the third counted candidate boot exhausts its attempts'
require_fixed 'PARTICLEOS_WORKLOAD_QUARANTINED ' tests/run-update-rollback-audit.sh 'rollback audit proves workload veto is bounded at three boots'
require_fixed 'run_guest workload-quarantine 5 denied' tests/run-update-rollback-audit.sh 'workload quarantine is followed by old-UKI rollback denial'
require_fixed 'prepare_scenario host-fallback' tests/run-update-rollback-audit.sh 'rollback audit separately injects a real host-side candidate failure'
require_fixed 'run_guest host-fallback 5 clean' tests/run-update-rollback-audit.sh 'host failure falls back only after three authenticated attempts'
require_fixed 'run_guest rollback-denial 3 denied' tests/run-update-rollback-audit.sh 'rollback audit forces the superseded signed UKI after pruning'
require_fixed 'UPDATE_ROLLBACK_AUDIT_DENIAL_PASS' tests/run-update-rollback-audit.sh 'rollback audit requires TPM denial of the superseded UKI'
require_fixed 'UPDATE_ROLLBACK_AUDIT_FALLBACK_PASS' tests/update-rollback-audit.sh 'rollback audit preserves legitimate pre-blessing fallback'
require_fixed 'FailureAction=reboot' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'candidate workload-health failure consumes the boot-count budget'
require_fixed 'ConditionPathExists=/sys/firmware/efi/efivars/LoaderBootCountPath-' mkosi.extra/usr/lib/systemd/system/particleos-workload-health.service 'rollback audit skips health on the uncounted fallback'
reject_fixed 'FailureAction=' tests/update-rollback-health.conf 'rollback audit cannot weaken the production failure action'
reject_fixed 'ConditionPathExists=' tests/update-rollback-health.conf 'rollback audit cannot replace the production counted-boot condition'
require_fixed 'ExecStart=/usr/lib/particleos/workload-health-gate ' tests/update-rollback-health.conf 'rollback audit retains the production candidate-rejection gate'
require_fixed 'systemctl enable particleos-workload-health.service' tests/update-rollback-audit.sh 'rollback audit opts into the production blessing dependency'
require_fixed 'Requires=particleos-pcrlock-enroll.service' mkosi.extra/usr/lib/systemd/system/boot-complete.target.d/40-particleos-security-gates.conf 'first boot always includes the rollback gate'
reject_fixed 'particleos-workload-health.service' mkosi.extra/usr/lib/systemd/system/boot-complete.target.d/40-particleos-security-gates.conf 'workload health is not mandatory in the factory transaction'
reject_fixed 'particleos-workload-health.service' mkosi.extra/usr/lib/systemd/system/systemd-bless-boot.service.d/40-particleos-rollback.conf 'blessing uses the opt-in dependency created by systemctl enable'
require_fixed 'Requires=particleos-pcrlock-enroll.service particleos-candidate-attempt.service particleos-pcrlock-prune.service' mkosi.extra/usr/lib/systemd/system/systemd-bless-boot.service.d/40-particleos-rollback.conf 'blessing requires the PCR commit transaction'
require_fixed 'Before=systemd-bless-boot.service' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-prune.service 'PCR authorization commits before blessing can succeed'
require_fixed 'ExecStartPre=/usr/lib/particleos/require-optional-workload-health' mkosi.extra/usr/lib/systemd/system/particleos-pcrlock-prune.service 'an enabled workload gate must succeed before PCR commit'
require_fixed 'Notify=healthy' mkosi.extra/usr/lib/particleos/check-workload-health 'Quadlet health must gate systemd readiness'
require_fixed 'an egress tuple for one Podman bridge grants no authority to another' tests/vm-audit.sh 'VM audit exercises per-bridge egress isolation'
require_fixed 'guestfwd=tcp:10.0.2.100:18443-cmd:/bin/cat' tests/run-vm-audit.sh 'bridge isolation uses a deterministic QEMU-local TCP endpoint'
require_fixed 'a forwarding tuple cannot reopen the blocked workload DNS channel' tests/vm-audit.sh 'VM audit exercises workload DNS denial after an allowlist mistake'
require_fixed 'removing an egress tuple revokes an already-established workload flow' tests/vm-audit.sh 'VM audit exercises immediate forwarding revocation'
require_fixed 'a rootful workload cannot address the host SSH socket' tests/vm-audit.sh 'VM audit exercises host-service isolation from Podman bridges'
require_fixed 'distributed unauthenticated connections cannot disable SSH socket activation' tests/vm-audit.sh 'VM audit exercises the unlimited socket activation trigger'
require_fixed 'the default workload has hard cgroup memory, swap, process, and CPU ceilings' tests/vm-audit.sh 'VM audit reads the effective workload cgroup ceilings'
require_fixed 'chain_policy=' tests/vm-audit.sh 'default-deny chain checks cannot fail nondeterministically through grep SIGPIPE'
require_fixed 'PARTICLEOS_LUKS_HEADER_REPLAY_DENIED' tests/run-vm-audit.sh 'VM audit restores and rejects a bootstrap-era LUKS header'
require_fixed 'PARTICLEOS_NETWORK_SECURITY_FAIL_CLOSED' tests/run-vm-audit.sh 'VM audit injects and observes a fail-closed firewall startup failure'
require_fixed 'systemd.mask=systemd-firstboot.service systemd.mask=systemd-homed-firstboot.service' tests/run-vm-audit.sh 'the isolated firewall fault boot cannot stall on resumable provisioning prompts'
require_fixed 'expectation == security-fault' tests/run-vm-audit.sh 'the firewall fault boot does not receive provisioning or workload-audit credentials'
require_fixed 'VM_AUDIT_ONLY_NETWORK_FAULT' tests/run-vm-audit.sh 'the isolated firewall failure can be reproduced without unrelated lifecycle boots'
require_fixed 'PARTICLEOS_NETWORK_SECURITY_FAIL_OPEN' tests/network-failure-audit.conf 'the firewall fault boot has an explicit fail-open canary behind the production security target'
require_fixed "PARTICLEOS_NETWORK_SECURITY_FAIL_OPEN' \"\$log\"" tests/run-vm-audit.sh 'the firewall fault proof rejects execution of the fail-open canary'
require_fixed 'FailureAction=poweroff-force' tests/nftables-failure.conf 'only the injected nftables failure can end the isolated fault guest successfully'

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
require_fixed 'final artifact set differs from the exact release schema' mkosi.scripts/obs-build 'OBS rejects incomplete or surplus signed artifact sets'
require_fixed '0b20710d4dbe312616e660c7359fd836052584172c28ee59dc951afb464ce4e6' mkosi.scripts/obs-build 'the reviewed Fedora 44 mkosi.build helper is pinned'
require_fixed 'fb44ed744620e4ea01d713ebe678ac935670007702c360a9961c35d248dae85e' mkosi.scripts/obs-postoutput 'the reviewed Fedora 44 mkosi.postoutput helper is pinned'
require_fixed "== 'mkosi 26-3.fc44'" mkosi.scripts/obs-build 'the OBS signing helper package build is exact'
require_fixed "== 'mkosi 26-3.fc44'" mkosi.scripts/obs-postoutput 'the OBS post-output helper package build is exact'
require_fixed "[[ \$(mkosi --version) == 'mkosi 26' ]]" mkosi.scripts/obs-build 'OBS rejects a different mkosi release'
# shellcheck disable=SC2016
require_fixed 'sha256sum -c "$checksum_basename"' scripts/validate-artifacts.sh 'artifact validation verifies the authenticated checksum manifest'
require_fixed 'snapshot-artifacts.py' scripts/validate-artifacts.sh 'artifact validation first creates an exact private release snapshot'
# shellcheck disable=SC2016
require_fixed 'primary_fingerprint == "$expected_key_fingerprint"' scripts/validate-artifacts.sh 'artifact validation pins the primary OpenPGP signer fingerprint'
require_fixed 'gpgv --homedir' scripts/validate-artifacts.sh 'artifact validation authenticates the checksum digest in an isolated keyring'
require_fixed 'sbverify --cert' scripts/validate-artifacts.sh 'artifact validation cryptographically verifies the UKI PE signature'
# shellcheck disable=SC2016
require_fixed 'cmp -- "$uki" "$scratch/embedded-uki.efi"' scripts/validate-artifacts.sh 'initial installation authenticates the UKI embedded in the published disk'
require_fixed "('c12a7328-f81f-11d2-ba4b-00a0c93ec93b', 'ParticleESP')" scripts/validate-artifacts.sh 'artifact validation requires the ESP GPT label used by the mount unit'
require_fixed 'etc/ipe/ipe-policy\.p7b' scripts/validate-artifacts.sh 'artifact validation inspects the signed UKI for the IPE policy'
require_fixed 'particleos-containerhost-repart-archive' mkosi.scripts/obs-build 'the OBS signing stage uses the hostile-input archive policy'
require_fixed 'upstream_sources=/usr/src/packages/SOURCES' mkosi.scripts/obs-build 'the stable mkosi signer reads only the validated staged source closure'
require_fixed 'BuildSources=/usr/src/packages/SOURCES:/usr/src/packages/SOURCES' mkosi.scripts/obs-postoutput 'the complete signing inputs remain in the OBS source closure'
require_fixed 'BuildScripts=/usr/bin/make' mkosi.scripts/obs-postoutput 'OBS source-mode normalization cannot disable the signing gate'
require_fixed 'MAKEFLAGS=--file=/work/src/usr/src/packages/SOURCES/particleos-containerhost-signing.mk' mkosi.scripts/obs-postoutput 'the executable make handoff selects only the generated signing recipe'
require_fixed 'particleos-containerhost-security-gate' mkosi.scripts/obs-postoutput 'the first-pass repository gate emits a signing-pass attestation'
# Literal implementation strings, not expressions for this validator.
# shellcheck disable=SC2016
require_fixed 'sha256sum -- "$signing_wrapper"' mkosi.scripts/obs-build 'the signing pass verifies its gate wrapper against the attestation'
# shellcheck disable=SC2016
require_fixed '/usr/bin/python3 "$archive_helper"' mkosi.scripts/obs-build 'archive validation does not trust OBS-preserved executable mode'
# shellcheck disable=SC2016
require_fixed '"$repository/scripts/validate.sh"' mkosi.scripts/obs-build 'OBS publication runs the repository security gate before artifact construction'
require_fixed 'validation=passed' mkosi.scripts/obs-build 'the signing pass requires the first-pass gate attestation'
require_fixed 'name: security-gate' .github/workflows/security.yml 'GitHub reports the repository security gate'
require_fixed 'run: ./scripts/validate.sh' .github/workflows/security.yml 'GitHub executes the same publication policy suite'
require_fixed 'actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09' .github/workflows/security.yml 'the CI checkout action is commit-pinned'
python3 tests/test-repart-archive-policy.py && pass 'hostile repart archive cases are rejected' || failures=$((failures + 1))
python3 tests/test-ipe-signature-archive-policy.py && pass 'hostile IPE signer-response archives are rejected' || failures=$((failures + 1))
python3 tests/test-artifact-snapshot-policy.py && pass 'artifact validation uses an exact immutable release snapshot' || failures=$((failures + 1))
python3 tests/test-uki-snapshot-policy.py && pass 'PCR policy generation uses stable verified UKI copies' || failures=$((failures + 1))
python3 tests/test-systemd-manifest-policy.py && pass 'local and OBS builds reject a rolled-back systemd package set' || failures=$((failures + 1))

for section in \
    '## Purpose' \
    '## ParticleOS Baseline' \
    '## Changes from ParticleOS' \
    '## Architecture' \
    '## Security and Hardening' \
    '## Installation and Provisioning' \
    '## Diagnostics and Tests' \
    '## Residual Risks'; do
    require_fixed "$section" README.md "README contains ${section#\#\# }"
done
reject_fixed 'custom-particleos' README.md 'README describes only the upstream ParticleOS baseline and this image'
for retired_name in Stalwart PostgreSQL nginx; do
    reject_fixed "$retired_name" README.md "README does not inventory retired ${retired_name} roles"
done
if [[ -e TODO ]] || find docs -type f -print -quit 2>/dev/null | grep -q .; then
    fail 'README is the sole project documentation file'
else
    pass 'README is the sole project documentation file'
fi

python3 - <<'PY' || failures=$((failures + 1))
import xml.etree.ElementTree as ET
paths = ('.obs/runsc/_service', '.obs/runsc/package-meta.xml',
         '.obs/ipe-policy-containerhost/package-meta.xml',
         '.obs/particleos-containerhost/_service.example',
         '.obs/particleos-containerhost/package-meta.xml')
for p in paths:
    ET.parse(p)

root = ET.parse('.obs/runsc/_service').getroot()
expected = (
    ('download_url', {
        'protocol': 'https',
        'host': 'storage.googleapis.com',
        'path': 'gvisor/releases/release/20260810.0/x86_64/gvisor.tar.bz2',
        'filename': 'gvisor.tar.bz2',
    }),
    ('verify_file', {
        'file': '_service:download_url:gvisor.tar.bz2',
        'verifier': 'sha256',
        'checksum': '3eca0158249c6b9b1f0d96c8f429c2aec6a4bcabd1a549bf25b15e48ca6d1d0c',
    }),
    ('download_url', {
        'protocol': 'https',
        'host': 'raw.githubusercontent.com',
        'path': 'google/gvisor/release-20260810.0/LICENSE',
        'filename': 'LICENSE.gvisor',
    }),
    ('verify_file', {
        'file': '_service:download_url:LICENSE.gvisor',
        'verifier': 'sha256',
        'checksum': '0fbab5c58efbdf6d31e8085214f2dd821659c03d73cff3ed2b08e98826ea1cd9',
    }),
)
assert root.tag == 'services' and not root.attrib
assert len(root) == len(expected)
for service, (name, parameters) in zip(root, expected, strict=True):
    assert service.tag == 'service' and service.attrib == {'name': name}
    actual = {}
    for parameter in service:
        assert parameter.tag == 'param' and set(parameter.attrib) == {'name'}
        assert len(parameter) == 0 and parameter.attrib['name'] not in actual
        actual[parameter.attrib['name']] = (parameter.text or '').strip()
    assert actual == parameters
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

mapfile -t shell_files < <(find . -type f \( -name '*.sh' -o -name 'mkosi.*' -o -path './mkosi.scripts/*' \) \
    -not -path './.git/*' -exec awk 'FNR == 1 && /^#!.*(ba)?sh/ {print FILENAME}' {} \;)
shellcheck "${shell_files[@]}" && pass 'shell scripts pass shellcheck' || failures=$((failures + 1))

if ((failures > 0)); then
    printf '%d validation check(s) failed\n' "$failures" >&2
    exit 1
fi
printf 'All container-host validation checks passed.\n'
