# ParticleOS Container Host

A minimal and hardened Fedora container host built on
[`systemd/particleos`](https://github.com/systemd/particleos).

Requires x86-64 UEFI Secure Boot, TPM 2.0, and a disk of at least 16 GiB.

## Table of Contents

- [Purpose](#purpose)
- [ParticleOS Baseline](#particleos-baseline)
- [Changes from ParticleOS](#changes-from-particleos)
- [Architecture](#architecture)
- [Features](#features)
- [Security and Hardening](#security-and-hardening)
- [Container Model](#container-model)
- [Disk and Update Model](#disk-and-update-model)
- [Network Model](#network-model)
- [Dependencies](#dependencies)
- [Build](#build)
- [Installation and Provisioning](#installation-and-provisioning)
- [Updates](#updates)
- [Diagnostics and Tests](#diagnostics-and-tests)
- [Residual Risks](#residual-risks)

## Purpose

ParticleOS Container Host turns the upstream ParticleOS image model into one
small, workload-independent appliance for running OCI containers through
gVisor. The host authenticates its immutable operating-system content,
encrypts mutable state against the local TPM, and reduces the host-kernel
interface exposed to a compromised workload.

The image deliberately has one operational model: administrators provision
trusted OCI identities and root-owned Quadlets, Podman starts them through
runsc with systrap, and real container health gates boot completion. Host
updates, workload trust, network authority, and rollback authorization all
fail closed.

The goal is not to make ParticleOS a container orchestration platform. The
goal is to keep the host boundary small and understandable while preserving
ParticleOS's image-based boot, update, and recovery model.

## ParticleOS Baseline

This repository is based on upstream ParticleOS commit `dd4fdc2`. At that
point, ParticleOS already provided the important image-oriented foundations:

- mkosi-built immutable operating-system images;
- user-controlled Secure Boot, UKI, PCR-policy, and dm-verity signing;
- signed systemd-boot and unified kernel images;
- read-only `/usr` protected by signed dm-verity;
- TPM-bound encryption for mutable state;
- A/B image deployment with systemd-sysupdate and systemd-boot counting; and
- an OBS path where signing keys remain inside the build service and signed
  updates are consumed by the installed system.

ParticleOS was designed as a customizable distribution template. This image
keeps those systemd-native mechanisms and specializes their policy for a
Fedora container host.

## Changes from ParticleOS

Area | ParticleOS baseline | Container-host extension
--- | --- | ---
Image scope | Customizable distribution and package selection | One pinned Fedora 44 x86-64 host image with a fixed security model
Release trust | Signed OBS image and update artifacts | Pinned OBS OpenPGP trust, signed checksum digests, full artifact hashes, and cryptographic UKI certificate verification
Persistent state | TPM-bound encrypted root | One-boot PCR 7 bootstrap followed by a machine-local PCR 7+11 NV policy
Rollback | A/B slots and boot counting | Current and candidate UKIs are authorized together, then the superseded UKI is revoked after health-gated blessing
Workload runtime | General operating-system image | Rootful Podman using release-pinned runsc with `platform=systrap`
Workload trust | Defined by the selected image | Exact default-deny OCI policy with administrator-provisioned repository trust
Mandatory access control | Distribution SELinux and signed image integrity | Enforcing host policy with separate `container_runtime_t` and `gvisor_t` domains
IPE | Signed IPE-capable boot profile | Signed container-host policy that protects kernel-fed objects while delegating systrap execution control to dm-verity, `noexec` state, and SELinux
Networking | Distribution network defaults | Default-drop host and forwarding policy with exact address, protocol, and port tuples
Update activation | systemd-sysupdate workflow | Automatic reboot only after candidate PCR authorization, followed by workload-health-gated blessing
Release qualification | mkosi image build | Hostile archive checks, artifact authentication, structural validation, and a two-boot Secure Boot/TPM/container VM test

## Architecture

The release, boot, state, and workload trust chains are independent until they
meet on the running host:

```text
Pinned OBS OpenPGP key
  -> signed checksum digest
     -> checksum manifest
        -> exact release artifacts
           -> OBS project certificate
              -> signed systemd-boot and UKI
                 -> embedded kernel, initrd, command line, and verity root hash
                    -> signed dm-verity + read-only EROFS /usr

UEFI Secure Boot state (PCR 7) + measured UKI phases (PCR 11)
  -> local TPM NV pcrlock policy
     -> LUKS2 persistent state

Root administrator
  -> Podman in container_runtime_t
     -> runsc/systrap in gvisor_t
        -> OCI workload behind the gVisor userspace kernel
```

The signed UKI carries the security-critical kernel command line. The OBS
project certificate signs the bootloader and UKI and verifies the PKCS#7
dm-verity root-hash signature. The local OBS wrapper assigns the final
image-versioned GPT label before the upstream `mkosi-obs` signing pass.

Authority or responsibility | Host | gVisor sandbox
--- | --- | ---
Boot and `/usr` integrity | Secure Boot, signed UKI, signed dm-verity | Inherited from host
Persistent data | TPM-bound LUKS2/Btrfs | Explicit Podman volumes and mounts
OCI verification | Podman image policy and administrator trust roots | Receives only accepted image content
Host system calls | SELinux, seccomp, namespaces, cgroups, kernel hardening | Guest calls are implemented by gVisor where supported
Network access | nftables and exact forwarding tuples | Workload network stack and application policy
Readiness | systemd and Quadlet health gate | Container `HealthCmd=` result

## Features

- Fedora 44 on x86-64, built with current mkosi and the upstream ParticleOS
  layout.
- Signed systemd-boot and UKI with UEFI Secure Boot enforcement.
- Read-only EROFS `/usr`, signed dm-verity, and two complete A/B slots.
- Atomic systemd-sysupdate transfers for the UKI, `/usr`, verity data, and
  verity signature.
- TPM 2.0-bound LUKS2/Btrfs persistent state with measured-UKI rollback
  protection.
- SELinux enforcing with a dedicated gVisor runtime domain.
- Signed IPE policy, confidentiality lockdown, mandatory module signatures,
  and irreversible post-boot module lockdown.
- Rootful Podman with release-pinned gVisor runsc and systrap as the default
  runtime.
- Signed OCI admission with an exact default-deny policy.
- Health-gated Quadlet boot blessing and guarded automatic update reboot.
- Default-drop nftables policy with exact workload forwarding sets.
- DNSSEC and strict DNS-over-TLS through systemd-resolved.
- Hardened SSH, sysctl, service, filesystem, allocator, and kernel-module
  policy.

## Security and Hardening

ParticleOS Container Host treats hardening as part of the image design rather
than a post-install checklist.

- **Artifact authenticity:** installation validation starts from a pinned OBS
  OpenPGP fingerprint, authenticates the signed checksum digest and manifest,
  hashes every artifact, extracts the project certificate, and uses
  `sbverify --cert` to verify the UKI signature.
- **Verified boot:** systemd-boot, the UKI, its embedded command line, the
  kernel, initrd, and dm-verity root hash are covered by the signed boot chain.
- **Encrypted state:** mutable `/etc`, `/var`, logs, keys, and container storage
  live on LUKS2/Btrfs mounted `nosuid,nodev,noexec` and unlocked by TPM policy.
- **Measured rollback control:** systemd-pcrlock combines live Secure Boot
  policy in PCR 7 with the admitted UKI measurements in PCR 11. The TPM NV
  policy authorizes only the active update window.
- **Strict boot credentials:** the signed command line sets
  `systemd.credentials_boot_policy=strict`. The public pcrlock policy envelope
  follows systemd's dedicated loader and is matched to the LUKS token's SRK
  and NV handles before use.
- **Mandatory access control:** Fedora targeted SELinux stays enforcing.
  Podman runs in `container_runtime_t`; authenticated gVisor executables
  transition into `gvisor_t`, which receives only the systrap-specific ptrace,
  anonymous execution, and namespace permissions it needs.
- **IPE:** firmware, kernel modules, kexec images, kexec initrds, IPE policy,
  and X.509 certificates are accepted only from verified boot or signed
  dm-verity sources. Executable anonymous memory required by systrap is
  controlled through the signed `/usr` boundary, `noexec` mutable state, and
  SELinux.
- **Kernel policy:** the signed command line enables audit, confidentiality
  lockdown, module signature enforcement, memory initialization, slab
  separation, page-allocation shuffling, randomized kernel stacks, and a
  fail-closed initrd.
- **Runtime hardening:** sysctls constrain BPF, performance events, io_uring,
  userfaultfd, kernel logs and pointers, core dumps, unsafe links and FIFOs,
  ptrace, and user namespaces. Required modules load first; the host then sets
  `kernel.modules_disabled=1`.
- **Administrative container boundary:** Podman, runsc, and every gVisor
  sidecar are root-owned mode `0750`. Unprivileged user-namespace creation is
  disabled; the bounded namespace allowance is confined to trusted system and
  runtime domains.
- **Filesystem hardening:** `/usr` is authenticated and mounted read-only with
  `nosuid,nodev`. Executable set-ID bits are stripped during the build and only
  Fedora's `unix_chkpwd` helper is restored.
- **Service hardening:** systemd units use capability, namespace, address
  family, syscall, filesystem, device, memory, and privilege restrictions
  appropriate to their function.
- **Network hardening:** input, output, and forwarding default to drop. DNSSEC,
  strict DNS-over-TLS, NTP/NTS, narrow administrative SSH, update traffic, and
  registry traffic receive explicit host rules.
- **Allocator policy:** `hardened_malloc` is preloaded and `no_rlimit_as`
  preserves allocator behavior for constrained services.

### IPE and systrap

Systrap executes guest code from anonymous mappings. IPE can authenticate
file-backed execution through boot, dm-verity, or fs-verity evidence, but it
cannot attach an SELinux domain to anonymous executable memory. A global IPE
`DEFAULT op=EXECUTE action=DENY` would therefore stop systrap itself.

The signed `ipe-policy-containerhost` keeps IPE default-deny for kernel-fed
objects and delegates ordinary execution control to the authenticated EROFS
`/usr`, the `noexec` mutable-state boundary, and SELinux. The `gvisor_t` domain
then confines systrap's host processes and reserves its executable-memory and
self-ptrace permissions.

## Container Model

Root-owned Podman and Quadlet definitions are the workload control plane.
Podman invokes `/usr/libexec/gvisor/runsc` with `platform=systrap`; runsc and
its sandbox processes transition from the Podman domain into `gvisor_t`.
Guest binaries execute against gVisor's userspace kernel instead of directly
against the host syscall ABI.

Podman defaults to a read-only container root, private namespaces, a fresh
session keyring, host user-ID mapping, fresh pulls, fully qualified image
names, and runsc. Workload definitions should additionally drop capabilities,
set CPU, memory, PID, and storage limits, use read-only mounts, define restart
behavior, and publish only reviewed ports.

The factory `/etc/containers/policy.json` is:

```json
{
  "default": [{"type": "reject"}],
  "transports": {}
}
```

An administrator enables images by installing verification material under
`/etc/pki/containers/` and replacing the policy with narrow,
repository-scoped `sigstoreSigned` or `signedBy` requirements. The fallback
remains `default: reject`, and each trust change is tested with both an
approved signed image and a deliberately untrusted image.

### Workload health

Root-owned `.container` files use the standard Quadlet paths under `/run`,
`/etc`, and `/usr/share`. Each workload declares `HealthCmd=` and
`Notify=healthy`. The host verifies the generated unit, active container, and
real Podman health state before boot completion can be blessed.

## Disk and Update Model

The disk contains an ESP, two `/usr` + verity + verity-signature slot triples,
and one encrypted mutable-state partition. systemd-sysupdate writes the
inactive UKI and operating-system slot as one deployment.

systemd-repart initially creates the LUKS2 state token against PCR 7 so the
first boot can complete. `particleos-pcrlock-enroll.service` then predicts the
current UKI in systemd-pcrlock's 650 kernel component slot, combines PCR 7 and
PCR 11 in a local TPM NV policy, enrolls the new LUKS token, and atomically
replaces the bootstrap token. The 650 placement precedes the
`750-enter-initrd` barrier at which state is unlocked.

After an update is staged, the update service verifies the installed UKIs
against the immutable project certificate and admits the active and candidate
measurements to the TPM NV policy. The reboot timer activates the deployment
only after that policy is committed. Boot counting retains the working slot
while the candidate is evaluated.

Boot blessing requires system health and every configured Quadlet's real
container health. Once the selected boot is blessed,
`particleos-pcrlock-prune.service` restricts state unlock to its UKI and
removes the superseded measurement from the NV policy.

## Network Model

systemd-networkd provides host networking. systemd-resolved ignores
DHCP-supplied resolvers and sends queries to fixed Cloudflare endpoints with
DNSSEC and strict DNS-over-TLS. chronyd uses NTP/NTS under a restricted service
policy.

The host owns the `inet particleos_filter` table and leaves Netavark's tables
intact. Input, output, and forwarding use a drop policy. Explicit baseline
rules cover DHCP, required ICMP and ICMPv6, loopback, established traffic,
DNS-over-TLS, NTP/NTS, update HTTPS, administrator-operated registry HTTPS,
the Podman DNS proxy, and rate-limited SSH when its socket is enabled.

Workload forwarding is expressed through eight sets split by IPv4/IPv6,
TCP/UDP, and ingress/egress. Provisioning adds exact destination-address and
destination-port tuples in root-owned files under
`/etc/particleos/nftables.d/`:

```nftables
add element inet particleos_filter workload_egress_tcp4 { 192.0.2.10 . 443 }
add element inet particleos_filter workload_ingress_tcp4 { 10.88.0.8 . 8443 }
```

The ingress tuple uses the post-DNAT container address and port. Apply changes
with `systemctl restart nftables`.

## Dependencies

Dependency | Version or source | Use
--- | --- | ---
ParticleOS | `dd4fdc2` | Immutable image, boot, repart, and update baseline
Fedora | 44 | Userspace and kernel package base
systemd and mkosi | `system:systemd` OBS packages / current mkosi | Image construction and system lifecycle
gVisor runsc | `release-20260810.0` | OCI sandbox runtime with systrap
Podman | Fedora package | Rootful OCI image and workload management
ipe-policy-containerhost | Signed local OBS package | Kernel-fed object policy compatible with systrap
hardened_malloc | Existing local OBS package | Hardened process allocator
no_rlimit_as | Existing local OBS package | Allocator-compatible service limits

The runsc RPM is built from the exact official gVisor release archive and
pinned SHA-256 digests. The image consumes packages only from the configured
Fedora, `system:systemd`, and `home:thefutureisprivate` repositories.

The operating-system source is LGPL-2.1-or-later; see [LICENSE](LICENSE) and
[NOTICE](NOTICE). gVisor is Apache-2.0 and its RPM carries the upstream license.

## Build

The repository requires current mkosi with `MinimumVersion=26~devel`.

Run policy and structure validation, then build:

```console
./scripts/validate.sh
mkosi build
```

Production OBS packages are:

- [`particleos-containerhost`](https://build.opensuse.org/package/show/home:thefutureisprivate/particleos-containerhost)
- [`runsc`](https://build.opensuse.org/package/show/home:thefutureisprivate/runsc)
- [`ipe-policy-containerhost`](https://build.opensuse.org/package/show/home:thefutureisprivate/ipe-policy-containerhost)

The live container-host source service is pinned to one reviewed signed Git
commit. OBS performs the final Secure Boot, UKI, and verity signing steps.

## Installation and Provisioning

Obtain the image and its companion signature files through an authenticated
path. The pinned OBS OpenPGP fingerprint is:

```text
0B2264A151F114677B1D0AAF25688B9E8208EED3
```

Authenticate the complete artifact directory before writing a disk:

```console
./scripts/validate-artifacts.sh /path/to/obs-artifacts
```

The validator authenticates the detached signature over the checksum digest,
the checksum manifest, and every release file. It extracts the project
certificate from the UKI, requires certificate fingerprint
`F18D066F4D25D63875BB0C370061D75A2AED67E81D33AF11669D79860BB9D2B7`,
and cryptographically verifies the PE signature with `sbverify --cert`.

Write the validated raw image to the whole target disk. Boot with UEFI Secure
Boot in setup mode so systemd-boot can enroll the OBS project certificate,
then leave setup mode and verify Secure Boot before provisioning workloads.

First boot is headless and performs repartitioning and TPM enrollment. Through
a trusted local path, create a named administrator, install an Ed25519
authorized key, create the host key, and enable SSH socket activation:

```console
systemctl enable --now sshd-keygen@ed25519.service
systemctl enable --now sshd.socket
```

Install OCI verification keys and a narrow image policy, add root-owned
Quadlets with health checks, and provision the workload's exact nftables
tuples. Recovery credentials and their escrow remain part of the operator's
separately authenticated recovery process.

## Updates

The enabled systemd-sysupdate download timer stages signed deployments. The
enabled reboot timer activates a complete deployment after its candidate UKI
has been admitted to the TPM policy.

Run an immediate guarded update cycle with:

```console
systemd-sysupdate list
systemd-sysupdate check-new
systemctl start systemd-sysupdate-update.service
systemctl start systemd-sysupdate-reboot.service
```

Every transfer uses `Verify=yes`. The update unit stays active until every
transfer commits, then commits the two-UKI PCR policy before recording reboot
readiness. The rebooted candidate must satisfy system health and Quadlet health
before blessing; otherwise systemd-boot's boot-count budget returns to the
working slot. Blessing either slot prunes the other UKI from state-unlock
authorization.

## Diagnostics and Tests

Inspect a running host with:

```console
bootctl status
systemd-analyze image-policy
systemd-cryptenroll /dev/disk/by-partlabel/ParticleOS-Host-root
cat /var/lib/systemd/pcrlock.json
getenforce
getsebool deny_ptrace
sysctl kernel.yama.ptrace_scope kernel.modules_disabled
cat /sys/kernel/security/ipe/policies/*/active
findmnt -no SOURCE,FSTYPE,OPTIONS /
findmnt -no SOURCE,FSTYPE,OPTIONS /usr
podman info --format '{{.Host.OCIRuntime.Name}} {{.Host.Security.Rootless}}'
systemd-sysupdate list
systemctl --failed
nft list table inet particleos_filter
```

Release qualification begins with static policy validation and the hostile
repart-archive regression suite:

```console
./scripts/validate.sh
./scripts/validate-artifacts.sh /path/to/artifacts
```

Prepare the disposable signed OCI fixture:

```console
./tests/prepare-signed-container-fixture.sh /path/to/container-fixture.raw
```

Then run the complete local VM audit with an OVMF variable store containing
the enrolled OBS project certificate:

```console
./tests/run-vm-audit.sh \
  /path/to/artifacts \
  /path/to/enrolled-ovmf-vars.bin \
  /path/to/container-fixture.raw
```

The first boot verifies Secure Boot, signed UKI and dm-verity, TPM migration to
PCR 7+11, SELinux, IPE, `gvisor_t`, update policy, workload health, firewall
tuples, module lockdown, OCI default-deny, and administrative runtime modes. It
rejects the fixture under the wrong key, accepts it under the exact trust root,
runs it through Podman and runsc/systrap, and validates a healthy Quadlet.

The second boot reuses the same disk and TPM state to prove persistent
automatic unlock and repeats the signed-container path. Both guests and TPM
emulators stop after success or failure. A successful boot prints:

```text
PARTICLEOS_VM_AUDIT_PASS checks=80
```

Set `VM_AUDIT_KEEP_FAILED=1` to retain a failed guest disk and serial logs for
diagnosis. The runner still stops QEMU and swtpm.

Qualify the complete update and rollback lifecycle with two authenticated OBS
releases and the same enrolled OVMF variable store:

```console
./tests/run-update-rollback-audit.sh \
  /path/to/base-artifacts \
  /path/to/candidate-artifacts \
  /path/to/enrolled-ovmf-vars.bin
```

The first scenario downloads the candidate through the production
systemd-sysupdate configuration, verifies the two-UKI PCR policy, boots and
blesses the candidate, confirms pruning to one UKI measurement, and then
forces the superseded signed entry. That entry must reach the initrd emergency
path before persistent state is unlocked. The second scenario repeats the
update on clean state, injects a candidate-only health failure for all three
boot-count attempts, and requires systemd-boot to return to the base version
while the pre-blessing TPM policy still authorizes it.

Set `VM_UPDATE_AUDIT_KEEP_FAILED=1` to retain disks and serial logs after a
failure. The runner stops every QEMU and swtpm process in both scenarios.

## Residual Risks

- Root remains part of the trusted computing base and can change OCI trust,
  firewall policy, or mutable state while the host is running.
- gVisor materially reduces host-kernel exposure but remains
  security-critical software.
- Anonymous executable memory created by systrap is governed by the combined
  signed `/usr`, `noexec` state, and SELinux boundary rather than file-backed
  IPE appraisal.
- All gVisor host processes use `gvisor_t`; isolation between sandboxes also
  depends on gVisor, namespaces, cgroups, and workload limits.
- CPU, memory, PIDs, namespaces, storage, logs, and network require explicit
  per-workload limits to preserve availability.
- PCR 7 includes every key trusted by firmware in the state-unlock decision;
  PCR 11 adds revocation of superseded UKIs after blessing.
- Recovery depends on independently verified signed media and escrowed LUKS
  material. Losing both TPM access and recovery material makes state
  unavailable.
