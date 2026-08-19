# ParticleOS Container Host

A minimal, generic, hardened Fedora container appliance built directly on
[`systemd/particleos`](https://github.com/systemd/particleos).

Requires x86-64 UEFI Secure Boot, TPM 2.0, and a disk of at least 16 GiB.

## Table of Contents

- [Purpose](#purpose)
- [Architecture](#architecture)
- [Features](#features)
- [Security and Hardening](#security-and-hardening)
- [Container Model](#container-model)
- [Disk and Update Model](#disk-and-update-model)
- [Network Model](#network-model)
- [Hardening Review](#hardening-review)
- [Build](#build)
- [Installation and Provisioning](#installation-and-provisioning)
- [Updates and Rollback](#updates-and-rollback)
- [Diagnostics and Tests](#diagnostics-and-tests)
- [Residual Risks](#residual-risks)
- [Dependencies and Provenance](#dependencies-and-provenance)

## Purpose

ParticleOS Container Host runs mutually untrusted OCI workloads through gVisor
on a small, immutable host. It protects booted host code against persistent
offline modification and reduces the host-kernel interface exposed to a
compromised container.

This repository contains one host image. It has no role hierarchy, application
DDIs, installer profile, debug UKI, or built-in workload. Stalwart,
PostgreSQL, nginx, unbound, and other application services deliberately remain
outside the operating-system build.

The host does not claim to survive compromise of firmware, the running kernel,
root, the OBS signing key, the TPM endorsement hierarchy, or an operator's OCI
signing authority. Firmware maintenance, physical security, signing-key
custody, workload policy, secrets, backup, and recovery remain operator
responsibilities.

## Architecture

The authenticated release, boot, and execution chain is:

```text
Pinned OBS OpenPGP fingerprint
  -> signed checksum digest -> checksum manifest -> exact release artifacts
     -> OBS project certificate verifies the PE signature
        -> signed systemd-boot and UKI
           -> embedded kernel, initrd, strict command line, and verity root hash
              -> signed dm-verity + read-only EROFS /usr

TPM bootstrap token (PCR 7)
  -> local TPM NV pcrlock policy (PCR 7 + PCR 11)
     -> encrypted persistent state

SELinux container_runtime_t (Podman)
  -> SELinux gvisor_t (release-pinned runsc, systrap)
     -> OCI workload
```

The OBS project certificate signs the bootloader and UKI and verifies the
PKCS#7 dm-verity root-hash signature. `mkosi-obs` remains the signing
implementation. The local OBS wrapper only assigns the final image-versioned
GPT label before the upstream second signing pass.

The signed UKI embeds the security-critical command line. There is no
less-restricted boot profile and no unsigned installer, recovery, live, debug,
or factory-reset UKI. Recovery uses separately controlled signed media.

## Features

- Fedora 44 on x86-64, built from the upstream ParticleOS model.
- Signed systemd-boot and UKI with UEFI Secure Boot enforcement.
- Read-only EROFS `/usr`, signed dm-verity, and two complete A/B slots.
- Atomic `systemd-sysupdate` transfers for the UKI, `/usr`, verity data, and
  verity signature.
- One LUKS2/Btrfs persistent-state partition automatically unlocked by TPM 2.0.
- TPM NV-backed PCR 7+11 policy with controlled two-version authorization
  during updates and revocation after boot blessing.
- SELinux enforcing with a small host-specific CIL module.
- Signed IPE policy, kernel lockdown, mandatory module signatures, and
  irreversible post-boot module lockdown.
- Rootful Podman with release-pinned gVisor `runsc`; systrap is explicit and
  the only installed OCI runtime.
- Default-deny OCI image policy with no built-in signing identity.
- Default-deny nftables input, forward, and output policy; workload forwarding
  starts with empty destination/protocol/port allowlists.
- DNSSEC and strict DNS-over-TLS through systemd-resolved.
- No rootless containers, subordinate-ID delegation, unprivileged user
  namespaces, rootless network helpers, or Podman user units.
- No workload packages, accounts, credentials, ports, or application policy.

## Security and Hardening

The immutable `/usr` partition is authenticated and mounted
`ro,nosuid,nodev`. All mutable `/etc`, `/var`, `/home`, logs, keys, and Podman
storage live on encrypted persistent state mounted `nosuid,nodev,noexec`.
Executable set-ID bits are removed during the build; only Fedora's
`unix_chkpwd` helper is restored. Podman, runsc, and every gVisor sidecar are
mode `0750`, owned by root, and unavailable to ordinary accounts.

The signed command line enables audit, SELinux and IPE enforcement,
confidentiality lockdown, module signature enforcement, allocation
initialization, slab separation, page-allocation shuffling, randomized kernel
stacks, fail-closed initrd behavior, and
`systemd.credentials_boot_policy=strict`. Null-key boot credentials, legacy
`vsyscall`, IA32 emulation, and firmware frame-buffer tunnels are disabled.

Sysctls restrict kernel pointers and logs, BPF, performance events, io_uring,
userfaultfd, core dumps, unsafe links and FIFOs, line-discipline loading, and
unprivileged user namespaces. Yama mode 2 requires `CAP_SYS_PTRACE`. The
SELinux `deny_ptrace` boolean stays enabled, with one explicit same-domain
`gvisor_t` ptrace edge for systrap's executor initialization.

Unused kernel protocols and filesystems are denied. Required storage,
container-network, IPE, and nftables expression modules load before the
firewall; `kernel.modules_disabled=1` then prevents any later module load.
`hardened_malloc` and `no_rlimit_as` are reused from the existing OBS project.

SELinux additionally:

- denies user-namespace creation to every domain except trusted boot/update
  helpers and the administrative Podman/gVisor runtime domains;
- denies unused host socket families while leaving protocols implemented
  inside gVisor available to workloads;
- limits `nosuid_transition` exceptions to the Fedora services the immutable
  host actually needs;
- transitions only the authenticated gVisor executables from Podman's
  `container_runtime_t` into `gvisor_t`;
- reserves executable anonymous memory and runtime-tmpfs entrypoints for
  `gvisor_t`; and
- permits ptrace only from `gvisor_t` to itself for systrap startup.

### IPE and systrap

Systrap maps anonymous memory executable to run guest code in sandboxed host
processes. Current IPE can authenticate file-backed execution through boot,
dm-verity, or fs-verity evidence, but cannot qualify anonymous executable
memory by SELinux domain. A global `DEFAULT op=EXECUTE action=DENY` therefore
prevents systrap from starting even when `runsc` is authenticated and confined.

The separately signed `ipe-policy-containerhost` makes the exception explicit:
IPE remains enforcing and default-deny for firmware, kernel modules, kexec
images and initrds, policy, and X.509 certificates, allowing those kernel-fed
objects only from verified boot or signed dm-verity. `EXECUTE` is delegated to
authenticated `/usr`, the `noexec` mutable state boundary, and SELinux's
dedicated `gvisor_t` restrictions. IPE itself does not authenticate
systrap-generated code or interpreted scripts.

## Container Model

Rootful Podman is the sole workload interface. It invokes
`/usr/libexec/gvisor/runsc` with `platform=systrap`. `crun`, `newuidmap`,
`newgidmap`, Pasta, passt, slirp4netns, Podman user services, and subordinate ID
mappings are absent. Login users cannot create user namespaces.

The kernel retains a small user-namespace quota because trusted rootful Podman
and gVisor need namespaces internally. SELinux grants creation only to system
plumbing and their administrative runtime domains; mode `0750` entry points,
disabled unprivileged user namespaces, and absent user services keep this from
becoming rootless-container support.

gVisor does not implement SELinux labels inside its sandbox. Per-container
labeling is disabled. Podman remains in `container_runtime_t`; runsc and its
sandbox processes transition into the separate `gvisor_t` domain. The latter
inherits Fedora's common container-runtime baseline, while systrap-only
ptrace, executable-memory, and user-namespace permissions are excluded from
Podman. Guest binaries execute through gVisor's userspace kernel rather than
directly against the host syscall ABI.

Podman defaults to a read-only container root, private namespaces, a fresh
session keyring, host user-ID mapping, fresh pulls, explicit fully qualified
image names, and runsc. Treat
privileged containers, host namespaces, host devices, writable host mounts,
runtime overrides, and signature-policy overrides as reviewed exceptions.

### OCI image authenticity

The factory `/etc/containers/policy.json` is exactly:

```json
{
  "default": [{"type": "reject"}],
  "transports": {}
}
```

No image can be pulled until an administrator installs public verification
material under `/etc/pki/containers/` and replaces the policy with narrow,
repository-scoped `sigstoreSigned` or `signedBy` requirements. Preserve
`default: reject` as the fallback and bind repository identity and issuer where
the policy format permits it.

A registry TLS certificate, registry login, or digest pin is not an
independent image signature. Never use `insecureAcceptAnything`, disable TLS
verification, or configure unqualified registry search. Validate every trust
change with one approved signed image and one deliberately unsigned image; the
unsigned pull must fail before unpacking.

Use root-owned Quadlet definitions under `/etc/containers/systemd/`. Every
`.container` must set both `HealthCmd=` and `Notify=healthy`; otherwise the
generic workload-health gate refuses boot completion and the boot is not
blessed. Pin image identities, use read-only mounts, drop capabilities, set
CPU/memory/PID/storage limits, define restart behavior, and publish only
reviewed ports.

### Workload health

The host discovers rootful `.container` files in the standard `/run`, `/etc`,
and `/usr/share` Quadlet paths. `particleos-workload-health.service` rejects
duplicate unit names, missing health commands, readiness not tied to health,
inactive generated services, missing containers, and any status other than
`healthy`. Hosts with no configured workloads pass as an empty generic host;
once a workload is configured, its real Podman health state gates boot
blessing.

## Disk and Update Model

The disk contains an ESP, two `/usr` + verity + verity-signature slot triples,
and one mutable Btrfs state partition. `systemd-sysupdate` writes only the
inactive UKI and OS slot. Its download timer is paired with an automatic reboot
timer, so a completed update cannot remain staged indefinitely. Reboot is
allowed only after the TPM policy for the candidate UKI has been committed.

Persistent state is LUKS2 encrypted; systemd-repart creates it with a
PCR7-bound bootstrap TPM token. Before the first boot can complete,
`particleos-pcrlock-enroll.service` predicts the current UKI's PCR 11
measurement, creates a strict PCR 7+11 policy in a local TPM NV index, enrolls
a new LUKS token, and atomically wipes the bootstrap TPM token. UKI records use
systemd-pcrlock's 650 kernel component slot, before the `750-enter-initrd`
barrier at which the encrypted root is unlocked. Boot blessing requires that
migration to finish.

After sysupdate installs a candidate, both the running and candidate UKIs are
verified with the immutable OBS project certificate and temporarily admitted
to the NV policy. This preserves boot-counted A/B rollback. A successful boot
is blessed only after system units and configured Quadlet health checks pass;
the superseded UKI is then removed from the state-unlock policy. An offline
attacker can still boot an older Secure-Boot-signed UKI, but it cannot unlock
persistent state after that UKI has been revoked. A Secure Boot or TPM policy
change can require recovery and token reenrollment.

The OBS Secure Boot key is RSA-4096, larger than the external RSA policy key
supported by many TPMs. ParticleOS therefore uses systemd-pcrlock's
machine-local NV authorization instead of publishing an unusable PCR11
public-key policy. No policy-signing private key is present on the host.

First boot is headless. It performs noninteractive repartitioning and TPM
enrollment but never blocks for locale, account, or optional recovery-key
questions. Recovery credentials are enrolled and escrowed later through a
separately authenticated administrative workflow.

## Network Model

systemd-networkd supplies host networking. DHCP-provided DNS is ignored;
systemd-resolved sends all queries to fixed Cloudflare resolvers with DNSSEC
and strict DNS-over-TLS. LLMNR and multicast DNS are disabled.

The host owns only `inet particleos_filter`; it does not flush Netavark's
tables. Input, forwarding, and output default to drop. The baseline permits:

- DHCP, necessary ICMP/ICMPv6, loopback, and established traffic;
- rate-limited SSH when the disabled socket is explicitly enabled;
- strict DNS-over-TLS and chrony NTP/NTS for their service users;
- update HTTPS only from the systemd-sysupdate service cgroup;
- root-operated TLS registry traffic on ports 443 and 8443; and
- Podman bridge access to the host DNS proxy.

There is no general Podman forwarding rule. Eight empty nftables sets cover
IPv4/IPv6, TCP/UDP, and ingress/egress. Site provisioning adds exact
destination-address and destination-port tuples in root-owned files under
`/etc/particleos/nftables.d/`; anything absent remains denied. For example:

```nftables
add element inet particleos_filter workload_egress_tcp4 { 192.0.2.10 . 443 }
add element inet particleos_filter workload_ingress_tcp4 { 10.88.0.8 . 8443 }
```

Use `workload_egress_{tcp,udp}{4,6}` and
`workload_ingress_{tcp,udp}{4,6}`. The ingress destination is the post-DNAT
container address and port. Reload with `systemctl restart nftables`; never
edit Netavark-generated tables. The generic host cannot know workload
endpoints, so the factory set membership is deliberately empty.

## Hardening Review

The former `custom-particleos` project was used only as a control catalogue.
The implementation preserves useful security properties, not its file layout,
role hierarchy, installer, or application architecture.

Control family | Decision | Container-host result
--- | --- | ---
Signed UKIs and Secure Boot | Retain | One production UKI signed by `mkosi-obs`; no weaker profiles.
Signed dm-verity `/usr` | Retain | Signed root hash and read-only EROFS with two A/B slots.
IPE | Adapt | Kernel-fed objects remain default-deny; `EXECUTE` is delegated to dm-verity, `noexec` state, and SELinux for systrap.
A/B `systemd-sysupdate` | Retain | UKI, `/usr`, verity, and signature update together.
Separate role/service DDIs | Drop | Workloads are trusted OCI images, not OS roles.
Installer/live/debug/emergency UKIs | Drop | They expanded the signed attack surface.
TPM2 state encryption | Adapt | PCR7 bootstraps one boot, then an NV-backed strict PCR7+11 LUKS token replaces it.
PCR11/pcrlock rollback control | Adapt | Machine-local TPM NV policy admits current + candidate only, then revokes the superseded UKI after blessing.
SELinux enforcing | Retain | Fedora targeted policy plus one small host CIL module.
Broad application SELinux policy | Drop | Mail, database, proxy, DNS, and installer domains have no host role.
User-namespace prohibition | Adapt | Login domains are denied; trusted helpers and the administrative Podman/gVisor domains retain a quota.
Ptrace prohibition | Adapt | Yama mode 2 and `deny_ptrace=on` remain; only `gvisor_t` self-ptrace is allowed for systrap startup.
Socket-family restrictions | Retain | Unused host protocols are denied; gVisor implements guest protocols.
Set-ID removal | Retain | All bits are stripped, then only `unix_chkpwd` is restored.
Kernel command-line hardening | Retain | Memory, lockdown, signatures, legacy ABI, and initrd fail-closed controls remain.
Sysctl hardening | Adapt | Host controls remain; bounded namespaces and scoped ptrace support rootful gVisor.
Kernel-module policy | Adapt | Required storage, Podman networking, nftables, and IPE modules remain; obsolete protocols do not.
Post-boot module lockdown | Retain | Required modules load first, then loading is irreversibly disabled.
Hardened allocator/no-RLIMIT-AS | Retain | Existing OBS packages are reused.
SSH hardening | Retain | Modern cryptography, no password/root/forwarding; socket is disabled by default.
DNS hardening | Retain | DHCP DNS is ignored; strict DNSSEC and DNS-over-TLS are required.
Default-deny nftables | Adapt | No blanket workload forwarding; exact address/protocol/port sets coexist with Netavark.
Rootless Podman | Drop | Helpers, mappings, user units, and rootless networking are absent.
`crun` runtime | Drop | Release-pinned runsc with systrap is the only installed runtime.
Per-container SELinux MCS | Drop | gVisor does not support it; Podman and gVisor use separate enforcing host domains.
Unsigned/mutable OCI trust | Drop | The initial policy rejects every image until narrow trust is provisioned.
Role accounts and homed | Drop | Accounts and keys are external provisioning concerns.
Stalwart/PostgreSQL/nginx roles | Drop | No application packages, credentials, ports, tests, or policy are included.
Application backup orchestration | Drop | The host updates itself; workload lifecycle stays outside the base OS.

## Build

The repository requires current mkosi with `MinimumVersion=26~devel`. The local
configuration uses only the signed `system:systemd` and
`home:thefutureisprivate` OBS repositories declared in
`mkosi.conf.d/10-local-repositories.conf`.

Run the static policy and structure checks, then build:

```console
./scripts/validate.sh
mkosi build
```

OBS uses the recipes under `.obs/` and upstream deferred signing. Production
packages are published as:

- [`home:thefutureisprivate/particleos-containerhost`](https://build.opensuse.org/package/show/home:thefutureisprivate/particleos-containerhost)
- [`home:thefutureisprivate/runsc`](https://build.opensuse.org/package/show/home:thefutureisprivate/runsc)
- [`home:thefutureisprivate/ipe-policy-containerhost`](https://build.opensuse.org/package/show/home:thefutureisprivate/ipe-policy-containerhost)

The live OBS source service is pinned to one reviewed signed Git commit. The
tracked `.obs/particleos-containerhost/_service.example` documents that service
without creating a self-referential revision change in Git.

`runsc` is built independently from the exact official gVisor
`release-20260810.0` archive and pinned SHA-256 digests. The image consumes its
RPM plus the existing `hardened_malloc`, `no_rlimit_as`, and separately signed
`ipe-policy-containerhost` packages.

## Installation and Provisioning

Clone this repository from GitHub through a separately authenticated path and
verify that the pinned OBS OpenPGP fingerprint is
`0B2264A151F114677B1D0AAF25688B9E8208EED3`. Do not treat
`sbverify --list` as authentication. Before writing a disk, run:

```console
./scripts/validate-artifacts.sh /path/to/obs-artifacts
```

The validator first verifies the detached OpenPGP signature over the checksum
digest, then the checksum manifest and every artifact. It extracts the
project certificate from the signed UKI, pins its SHA-256 fingerprint to
`F18D066F4D25D63875BB0C370061D75A2AED67E81D33AF11669D79860BB9D2B7`,
and makes `sbverify --cert` verify the PE signature cryptographically. A
signature merely being present is not accepted.

Only then write the validated raw image to the whole target disk. Boot UEFI
Secure Boot in setup mode so systemd-boot can enroll the OBS project
certificate carried by the image. Leave setup mode and verify Secure Boot
before provisioning workloads.

After first boot, inspect the host:

```console
bootctl status
systemd-analyze image-policy
systemd-cryptenroll /dev/disk/by-partlabel/ParticleOS-Host-root
cat /var/lib/systemd/pcrlock.json
getenforce
getsebool deny_ptrace
sysctl kernel.yama.ptrace_scope kernel.modules_disabled
cat /sys/kernel/security/ipe/policies/*/active
cat /sys/kernel/security/ipe/policies/*/policy
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt -no SOURCE,FSTYPE,OPTIONS /usr
podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.Security.Rootless}}'
runsc --version
systemd-sysupdate list
systemctl --failed
nft list table inet particleos_filter
```

Expect Secure Boot enabled, SELinux `Enforcing`, `deny_ptrace --> on`, Yama
mode `2`, an active signed IPE policy, encrypted `noexec` root state, read-only
EROFS `/usr`, runsc with rootless `false`, two A/B slots, no failed units,
empty workload-forwarding sets, default-drop firewall chains, and
`kernel.modules_disabled = 1`.

Inspect the state token's JSON metadata before relying on automatic unlock. It
must contain `"tpm2_pcrlock": true`, must not retain a PCR7-only token, and
`/var/lib/systemd/pcrlock.json` must contain both PCR 7 and PCR 11. Device names
vary; resolve them with
`systemd-repart --json=pretty /dev/<disk>` before enrollment operations.

The root account is locked and SSH is disabled. Through a trusted local
provisioning path, create a named administrator, install an Ed25519 authorized
key, and grant only the required sudo or polkit authority. Then create the host
key and enable socket activation explicitly:

```console
systemctl enable --now sshd-keygen@ed25519.service
systemctl enable --now sshd.socket
```

Do not enable password login, direct root login, agent forwarding, TCP
forwarding, X11 forwarding, or user Podman services.

## Updates and Rollback

The enabled update timer downloads and stages signed deployments; the enabled
reboot timer activates a fully staged deployment in its maintenance window.
For an immediate administrator-triggered cycle, use the same guarded units:

```console
systemd-sysupdate list
systemd-sysupdate check-new
systemctl start systemd-sysupdate-update.service
systemctl start systemd-sysupdate-reboot.service
```

Every remote transfer uses `Verify=yes`. The update unit verifies both UKIs
and expands the TPM NV policy before a reboot-ready marker is committed. The
reboot unit refuses to act without that marker. Boot counting keeps the
previous slot authorized only while the candidate is unblessed.

Boot completion requires every configured rootful `.container` Quadlet to be
active and report `healthy`, in addition to systemd's failed-unit check. An
unhealthy workload reboots without blessing; after the boot-count budget is
exhausted, systemd-boot selects the previous slot. Once either candidate or
rollback boot is blessed, `particleos-pcrlock-prune.service` restricts state
unlock to that booted UKI. Never manually bless, relabel, or copy a UKI around
the update services.

Keep independently verified signed recovery media and escrow any LUKS recovery
material under site policy. On suspected host compromise, isolate the machine,
preserve volatile evidence, and rebuild from a known signed image. Rotate OCI
trust, workload, SSH, registry, and TPM-bound secrets as appropriate, and
review OBS signing-key custody and build logs. Rotating only container
credentials is insufficient because root can modify encrypted persistent
state while the host is running.

## Diagnostics and Tests

Validate an OBS artifact directory before deployment:

```console
./scripts/validate-artifacts.sh /path/to/artifacts
```

The validator authenticates the published checksum chain, cryptographically
verifies the UKI against the pinned certificate, and checks the signed command
line, manifest contents, versioned verity-signature label, distributable GPT,
and runtime A/B definitions. The OBS signing-stage extractor separately rejects
absolute paths, traversal, nested names, links, devices, duplicate entries,
special mode bits, compression, and size/count abuse before reading repart
definitions.

For release qualification, first create the disposable signed OCI fixture.
This step needs `skopeo`, GnuPG, `dosfstools`, and `mtools`; it downloads the
configured BusyBox test image, generates one-use signing and negative-test
keys, verifies both policy outcomes, and writes a 32-MiB FAT disk:

```console
./tests/prepare-signed-container-fixture.sh /path/to/container-fixture.raw
```

Then provide an OVMF variable store in which the OBS project certificate has
already been enrolled and run the complete local VM audit:

```console
./tests/run-vm-audit.sh \
  /path/to/artifacts \
  /path/to/enrolled-ovmf-vars.bin \
  /path/to/container-fixture.raw
```

Set `VM_AUDIT_CONTAINER_SOURCE` to another fully qualified source transport
when preparing the fixture. An optional fourth runner argument selects a
different read-only OVMF Secure Boot code image. The runner copies the firmware
variables, attaches the fixture read-only, decompresses a disposable 16-GiB
disk, injects `vm-audit.service` and the audit script as system credentials,
and starts QEMU/KVM with swtpm. Nothing is installed in the guest. It creates
sparse temporary state beside the artifacts by default; set `VM_AUDIT_TMPDIR`
to another writable filesystem when needed. Set `VM_AUDIT_KEEP_FAILED=1` to
preserve a failed guest disk and its logs for diagnosis; QEMU and swtpm are
still stopped.

The first boot validates Secure Boot, signed UKI/dm-verity, replacement of the
PCR7 bootstrap token by the PCR7+11 NV policy, strict credential handling,
SELinux/IPE, the dedicated live `gvisor_t` domain, A/B layout, workload health,
automatic update reboot policy, tuple-based forwarding denial, module
lockdown, administrative runsc modes, rootful Podman, and default-deny image
policy. It rejects the signed fixture under the wrong key, imports it under an
exact valid trust rule, runs the read-only
container through Podman's default runsc/systrap path, starts a health-gated
Quadlet, and proves unlisted egress is denied. It also checks rootless-helper
absence, set-ID state, SSH, and DNS. The second boot reuses the same disk and
TPM state to prove persistent automatic unlock and repeats the signed-container
test from clean storage. Both guests power off on success or failure, each
swtpm process is stopped, and temporary state is removed. Success ends with:

```text
PARTICLEOS_VM_AUDIT_PASS
```

## Residual Risks

- Root is in the trusted computing base and can replace OCI policy, firewall
  rules, or mutable state while the host is running.
- gVisor reduces host-kernel exposure but remains security-critical software;
  it does not make malicious workloads safe.
- IPE does not authenticate anonymous executable memory generated by systrap.
  That boundary depends on signed `/usr`, `noexec` state, and SELinux.
- SELinux cannot label individual processes inside gVisor. All gVisor host
  processes share `gvisor_t`; isolation between sandboxes relies primarily on
  gVisor, namespaces, cgroups, Podman defaults, and workload-specific limits.
- Availability can be exhausted through CPU, memory, PIDs, namespaces,
  storage, logs, or network unless each workload has explicit limits.
- PCR 7 remains part of the NV policy, so every key trusted by firmware remains
  part of the state-unlock trust decision. PCR 11 prevents an otherwise trusted
  but superseded UKI from unlocking state after blessing.
- Root-operated host registry egress remains broad on TLS ports; workload
  forwarding itself is empty until site policy adds exact tuples.
- There is no built-in recovery profile; loss of valid recovery material can
  make persistent state unavailable after TPM or Secure Boot policy changes.

## Dependencies and Provenance

The codebase started from upstream ParticleOS commit `dd4fdc2`. The former
`custom-particleos` repository supplied only hardening requirements and review
evidence; none of its role architecture, application code, installers, or
service complexity was imported.

The operating-system source is LGPL-2.1-or-later; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). Separately packaged gVisor binaries are Apache-2.0 and ship
their upstream license in the RPM.
