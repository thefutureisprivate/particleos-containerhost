# ParticleOS Container Host

> A minimal Fedora VM/VPS image for running one signed OCI workload through
> Podman and gVisor, built on
> [`systemd/particleos`](https://github.com/systemd/particleos).

ParticleOS Container Host requires x86-64 UEFI Secure Boot, TPM 2.0, and a
disk of at least 16 GiB. One VM or VPS is one workload security boundary:
deploy a separate instance for every workload.

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
small, workload-independent VM or VPS appliance for running a signed OCI
workload through gVisor. The host authenticates its immutable operating-system
content, encrypts mutable state against the local TPM, and reduces the
host-kernel interface exposed to a compromised workload.

The image deliberately has one operational model: administrators provision
trusted OCI identities and root-owned Quadlets, Podman starts them through
runsc with systrap, and host policy remains independent of the application.
Use a separate VM/VPS for each workload rather than treating Podman bridges as
tenant boundaries. Host updates, workload trust, network authority, and
rollback authorization all fail closed.

The design keeps the host boundary small and understandable while preserving
ParticleOS's image-based boot, update, and recovery model. It is an appliance,
not a multi-tenant container cluster.

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
Persistent state | TPM-bound encrypted root | PCR 7 bootstrap retained until a later boot proves the machine-local PCR 7+11 NV token
Rollback | A/B slots and boot counting | Only the booted UKI and exact authenticated update candidate are authorized; the superseded UKI is revoked after blessing
Workload runtime | General operating-system image | Rootful Podman using release-pinned runsc with `platform=systrap`
Workload trust | Defined by the selected image | Exact default-deny OCI policy with administrator-provisioned repository trust
Mandatory access control | Distribution SELinux and signed image integrity | Enforcing host policy with separate `container_runtime_t` and `gvisor_t` domains
IPE | Signed IPE-capable boot profile | Signed container-host policy that protects kernel-fed objects while delegating systrap execution control to dm-verity, `noexec` state, and SELinux
Networking | Distribution network defaults | Default-drop policy with exact bridge, address, protocol, and port tuples; workload DNS blocked
Update activation | systemd-sysupdate workflow | Automatic reboot only after exact candidate PCR authorization; administrator-optional workload health on counted candidates
Release qualification | mkosi image build | Repository and OBS publication gates, hostile archive checks, artifact authentication, and Secure Boot/TPM/container VM tests

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

- Fedora 44 on x86-64, built with current mkosi, upstream-stable systemd, and
  the upstream ParticleOS layout.
- Signed systemd-boot and UKI with UEFI Secure Boot enforcement.
- Read-only EROFS `/usr`, signed dm-verity, and two complete A/B slots.
- Atomic systemd-sysupdate transfers for the UKI, `/usr`, verity data, and
  verity signature.
- TPM 2.0-bound LUKS2/Btrfs persistent state with measured-UKI rollback
  protection.
- SELinux enforcing with a dedicated gVisor runtime domain.
- Signed IPE policy, confidentiality lockdown, mandatory module signatures,
  fixed post-sysinit module preload, and irreversible module lockdown before
  networking starts.
- Rootful Podman with release-pinned gVisor runsc and systrap as the default
  runtime.
- Signed OCI admission with an exact default-deny policy.
- Optional Quadlet health gating for counted update candidates and guarded
  automatic update reboot.
- Default-drop nftables policy with per-bridge exact forwarding sets and no
  workload DNS path.
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
  policy authorizes only the booted version and the exact newer candidate
  selected from authenticated systemd-sysupdate metadata. A renamed older
  project-signed UKI fails its embedded `IMAGE_VERSION` check.
- **Strict boot credentials:** the signed command line sets
  `systemd.credentials_boot_policy=strict`. The public pcrlock policy envelope
  follows systemd's dedicated loader, uses the stable image ID rather than a
  transient machine ID as its entry token, and is matched to the LUKS token's
  SRK and NV handles before use. Policy refreshes retain exactly one
  image-scoped EFI credential.
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
  ptrace, and user namespaces. Container-host modules load after boot-critical
  sysinit and before nftables or networking; the host then sets
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
`/etc`, and `/usr/share`. Workload health is deliberately disabled in the
factory image: the generic host cannot know when an application is ready.

After deploying and validating the workload on the current version, the
administrator may require `HealthCmd=` and `Notify=healthy` for future update
candidates:

```console
systemctl enable particleos-workload-health.service
```

The service becomes a direct requirement of `systemd-bless-boot.service` only
after that opt-in and runs only when systemd-boot marks the selected deployment
as counted. On a failed probe, the gate marks that candidate bad while its
authoritative boot-count path is still available, then reboots directly into
the uncounted working slot. The fallback skips the workload gate, so one broken
application cannot reboot both A/B deployments forever. Disable the service to
return to host-only blessing.

## Disk and Update Model

The disk contains an ESP, two `/usr` + verity + verity-signature slot triples,
and one encrypted mutable-state partition. systemd-sysupdate writes the
inactive UKI and operating-system slot as one deployment. The factory root
partition definition creates `/efi` and `/boot` while formatting the new
state. A mandatory `efi.mount` resolves the stable `ParticleESP` GPT label and
mounts it at `/efi` with root-only, `nodev,nosuid,noexec` options. This remains
reliable on first boot, when formatting happens too late for the initrd's
earlier GPT auto-discovery pass, and gives UKI admission and updates one
unambiguous boot-manager path. A narrowly confined early unit loads only the
signed `vfat` module needed by this mount; container and network modules remain
in the later fixed preload before irreversible module lockdown.

systemd-repart initially creates the LUKS2 state token against PCR 7 so the
first boot can create the machine-local policy. The enrollment service predicts
the current UKI in systemd-pcrlock's 650 kernel component slot, combines PCR 7
and PCR 11, and adds the new token while retaining the PCR 7 bootstrap. It then
reboots. On the next boot it explicitly unlock-tests that exact pcrlock token;
only after this proof does one atomic enrollment operation remove every older
TPM2 token. The 650 placement precedes the `750-enter-initrd` barrier at which
state is unlocked.

The update wrapper gets the exact newer version from systemd-sysupdate's signed
metadata, installs that version with `Verify=yes`, checks the project signature
and embedded release identity of its UKI, and admits only the booted and exact
candidate measurements. Other files on the writable ESP are never policy
inputs. The reboot timer also rechecks the candidate digest and committed
policy before activation. Boot counting retains the working slot while the
candidate is evaluated.

Boot blessing always requires host health and may require real Quadlet health
after the administrator opts in. Once the selected boot is blessed,
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
and rate-limited SSH when its socket is enabled. Workloads cannot query the
host DNS proxy or send TCP/UDP port 53 through forwarding, so host resolution
cannot bypass destination allowlists. Provision fixed endpoint addresses or
application-level discovery inside the workload trust boundary.

Netavark stores root-owned network definitions under
`/var/lib/containers/networks` on TPM-encrypted persistent state; the immutable
vendor configuration under `/etc/containers` is never used as mutable state.

Workload forwarding is expressed through eight sets split by IPv4/IPv6,
TCP/UDP, and ingress/egress. Every element also carries the exact Podman bridge
interface, so permission on one network is not reusable from another.
Provisioning adds exact tuples in root-owned files under
`/etc/particleos/nftables.d/`:

```nftables
add element inet particleos_filter workload_egress_tcp4 { "podman0" . 192.0.2.10 . 443 }
add element inet particleos_filter workload_ingress_tcp4 { "podman0" . 10.88.0.8 . 8443 }
```

The ingress tuple uses the egress bridge plus post-DNAT container address and
port. DNS port 53 remains blocked even if it is accidentally added to a set.
Apply changes with `systemctl restart nftables`.

## Dependencies

Dependency | Version or source | Use
--- | --- | ---
ParticleOS | `dd4fdc2` | Immutable image, boot, repart, and update baseline
Fedora | 44 | Userspace and kernel package base
systemd and mkosi | upstream `system:systemd:stable` OBS packages / current mkosi | Released system lifecycle and image construction
gVisor runsc | `release-20260810.0` | OCI sandbox runtime with systrap
Podman | Fedora package | Rootful OCI image and workload management
ipe-policy-containerhost | Signed local OBS package | Kernel-fed object policy compatible with systrap
hardened_malloc | Existing local OBS package | Hardened process allocator
no_rlimit_as | Existing local OBS package | Allocator-compatible service limits

The runsc RPM is built from the exact official gVisor release archive and
pinned SHA-256 digests. The image consumes packages only from the configured
Fedora, `system:systemd:stable`, and `home:thefutureisprivate` repositories.
The upstream-maintained stable OBS project replaces both Fedora's older
systemd build and the continuously changing systemd main-branch project.

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
commit. `scripts/validate.sh` is enforced by GitHub CI and again inside the OBS
build wrapper before either publication pass. OBS performs the final Secure
Boot, UKI, and verity signing steps only after that gate passes.

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

Write the validated raw image to the whole disk of a dedicated VM or VPS. Do
not share one instance between unrelated workloads. Boot with UEFI Secure Boot
in setup mode so systemd-boot can enroll the OBS project certificate, then
leave setup mode and verify Secure Boot.

Keep the provider or hypervisor console open for initial setup. The native
systemd first-boot flow asks, in order:

1. a recovery root password;
2. the system timezone;
3. an administrator username; and
4. that administrator's password.

After the timezone is written, the machine automatically reboots once to stage
and prove its PCR 7+11 state-unlock policy. The username and password prompts
continue after that enrollment reboot. The administrator is stored by
systemd-homed in a 1 GiB password-encrypted LUKS/Btrfs image mounted
`nosuid,nodev,noexec` and is added to `wheel` and `systemd-journal`.

Log in as the named administrator. Use `run0` for privileged work; Polkit
requires the administrator's own password for every elevation. The root
password is for console recovery, not routine administration.

SSH remains disabled after provisioning and never accepts root or password
login. To enable key-only access, place an Ed25519 public key in the active
administrator home, import it into the homed identity, generate the host key,
and enable socket activation:

```console
run0 homectl update "$USER" --ssh-authorized-keys=@"$HOME/id_ed25519.pub"
run0 systemctl enable --now sshd-keygen@ed25519.service
run0 systemctl enable --now sshd.socket
```

Install OCI verification keys and a narrow image policy, add root-owned
Quadlets, and provision the workload's exact nftables tuples. Opt into workload
health gating only after its `HealthCmd=` and `Notify=healthy` behavior has been
validated on the currently blessed release. Recovery credentials and their
escrow remain part of the operator's separately authenticated recovery process.

## Updates

The enabled systemd-sysupdate download timer stages signed deployments. The
enabled reboot timer activates a complete deployment after its candidate UKI
has been admitted to the TPM policy.

Run an immediate guarded update cycle with:

```console
systemd-sysupdate list
systemd-sysupdate check-new
systemctl start systemd-sysupdate.service
systemctl start systemd-sysupdate-reboot.service
```

Every transfer uses `Verify=yes`. The update unit stays active until every
transfer commits, then validates the exact candidate UKI and commits the
two-UKI PCR policy before recording reboot readiness. The rebooted candidate
must satisfy host health and, when the administrator has enabled it, Quadlet
health before blessing. A failed workload probe marks only that counted
candidate bad before reboot; the uncounted fallback remains bootable. Blessing
either slot prunes the other UKI from state-unlock authorization.

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
findmnt -no SOURCE,FSTYPE,OPTIONS /efi
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

Create a fresh test variable store from the authenticated release. This first
verifies the signed release manifest and UKI against the repository-pinned OBS
keys, then enrolls only the authenticated project certificate into OVMF's
PK, KEK and db databases:

```console
./tests/prepare-ovmf-vars.sh \
  /path/to/artifacts \
  /path/to/enrolled-ovmf-vars.bin
```

Exercise the native console flow, including the real rollback-policy reboot,
root password, timezone, homed account creation, PAM/logind login,
unauthenticated `run0` denial, and password-authenticated elevation:

```console
./tests/run-firstboot-console-audit.sh \
  /path/to/artifacts \
  /path/to/enrolled-ovmf-vars.bin
```

This test opens a GTK VM display by default. Set `FIRSTBOOT_VM_DISPLAY=none`
for headless automation. A successful run prints:

```text
PARTICLEOS_FIRSTBOOT_CONSOLE_PASS user=particleadmin timezone=Etc/UTC run0=authenticated
```

Then run the complete local VM audit:

```console
./tests/run-vm-audit.sh \
  /path/to/artifacts \
  /path/to/enrolled-ovmf-vars.bin \
  /path/to/container-fixture.raw
```

Set `VM_AUDIT_DISPLAY=gtk` to open the guest display for every boot. The
serial audit log remains authoritative and is still captured in the test
directory. Omit the variable for headless automation.

The enrollment boot retains PCR 7 and reboots. The next boot proves the exact
PCR 7+11 token before removing bootstrap, then verifies Secure Boot, signed UKI
and dm-verity, SELinux, IPE, `gvisor_t`, update policy, optional workload
health, per-bridge firewall tuples, blocked workload DNS, module lockdown, OCI
default-deny, and administrative runtime modes. It
rejects the fixture under the wrong key, accepts it under the exact trust root,
runs it through Podman and runsc/systrap, and validates a healthy Quadlet.

The third boot reuses the same disk and TPM state to prove persistent automatic
unlock and repeats the signed-container path. Every guest and TPM emulator
stops after success or failure. A successful audit boot prints:

```text
PARTICLEOS_VM_AUDIT_PASS checks=94
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

Set `VM_UPDATE_AUDIT_DISPLAY=gtk` to show each update and rollback boot in a
local QEMU window.

The first scenario downloads the candidate through the production
systemd-sysupdate configuration, first proves that a renamed older signed UKI
cannot enter the PCR policy, verifies the exact two-UKI policy, boots and
blesses the candidate, confirms pruning to one UKI measurement, and then
forces the superseded signed entry. That entry must reach the initrd emergency
path before persistent state is unlocked. The second scenario repeats the
update on clean state, injects a health failure on every counted attempt, and
requires systemd-boot to return to the uncounted base version without running
the workload gate there.

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
- Each instance is intended for one workload. If an administrator runs more
  than one anyway, isolation still depends on gVisor, namespaces, cgroups,
  per-bridge firewall policy, and explicit resource limits.
- PCR 7 includes every key trusted by firmware in the state-unlock decision;
  PCR 11 adds revocation of superseded UKIs after blessing.
- Recovery depends on independently verified signed media and escrowed LUKS
  material. Losing both TPM access and recovery material makes state
  unavailable.
