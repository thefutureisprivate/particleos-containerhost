# Security model

## Purpose and boundary

This image is an immutable operating system for running mutually untrusted OCI
workloads through gVisor. It protects the host from a compromised container and
protects booted host code from persistent offline modification. It does not
claim to protect a running host after compromise of the firmware, kernel, root
administrator, OBS signing key, TPM endorsement hierarchy, or the configured
container-image signing authority.

The operator is responsible for firmware updates, Secure Boot enrollment,
physical security, image-signing key custody, workload configuration, secret
provisioning, backup, and recovery.

## Trust chain

```text
OBS project certificate
  -> signed systemd-boot and UKI
     -> embedded kernel, initrd, command line, and signed dm-verity root hash
        -> read-only authenticated /usr
           -> enforced IPE policy for host executable code
```

The same OBS project certificate is installed in `/usr/lib/verity.d` and used
for the UKI/bootloader signatures and the PKCS#7 dm-verity root-hash signature.
`mkosi-obs` remains the signing implementation. A small audited wrapper changes
only the saved verity-signature GPT label to its image version before the
upstream second signing pass.

No unsigned recovery, debug, live, installer, or factory-reset UKI is built.
Recovery therefore requires a separately controlled signed environment.

## Disk and update model

The disk contains an ESP, two complete `/usr` + verity + verity-signature slot
triples, and one mutable Btrfs root partition. `systemd-sysupdate` writes only
the inactive OS slot and UKI, retaining two versions. Boot counting prevents a
failed version from being blessed.

The root partition contains the persistent `/etc`, `/var`, `/home`, and Podman
storage state created from `/usr/share/factory/root`. It is encrypted with
LUKS2 and automatically unlocked by a TPM2 token bound to PCR 7. PCR 7 measures
Secure Boot policy rather than a particular OS version, allowing signed A/B
updates without resealing for every release. A Secure Boot policy change may
require recovery and token reenrollment.

The state token intentionally has no additional public-key PCR11 policy. OBS
uses an RSA-4096 project key, which is valid for firmware and software
signature verification but exceeds the external RSA key size supported by
many TPM 2.0 implementations. Allowing systemd to discover that key as a TPM
policy key would create a token that those TPMs cannot unseal. PCR7 provides
the intended stable binding to the enrolled Secure Boot policy without tying
state to one UKI version or to TPM-specific RSA capabilities.

Current systemd also ships an optional NvPCR and pcrlock stack that needs a
separate TPM-compatible PCR signing key. ParticleOS does not pretend the OBS
Secure Boot key can fill that role: the unused NvPCR definitions and their
setup, login, and product measurement units are removed or masked, as are the
on-demand pcrlock sockets. TPM enrollment and unlock use the standard LUKS2
token directly; ordinary UKI boot-phase PCR measurements remain enabled. This
keeps the selected security property explicit: stable PCR7 sealing of state,
with no unusable auxiliary TPM policy.

The signed command line selects `systemd.firstboot=headless`. Noninteractive
first-boot provisioning still runs, but the generic appliance never blocks on
locale, account, or optional LUKS recovery-key enrollment prompts. Recovery
credentials are an explicit operator provisioning responsibility.

## Workload isolation

Podman runs as root and invokes `/usr/libexec/gvisor/runsc` with the systrap
platform. `crun`, rootless ID-mapping helpers, rootless networking helpers, and
Podman user units are removed. Podman defaults to host user-namespace mapping,
private PID/IPC/UTS/network/cgroup namespaces, a read-only root filesystem, and
no privileged mode.

gVisor requires user namespaces as a trusted host isolation primitive. The
kernel therefore has a small namespace quota, while the custom SELinux policy
denies creation to all domains except the boot/update plumbing and
`container_runtime_t`. This is different from enabling unprivileged user
namespaces for login users.

gVisor does not implement SELinux labels inside its sandbox. Podman label
separation is disabled for containers, but the host remains enforcing and
confines Podman/runsc as `container_runtime_t`. Container processes are handled
by the userspace kernel and do not execute their image binaries directly on the
host kernel.

## Image authenticity

`/etc/containers/policy.json` has `default: reject` and grants no transport an
exception. `registries.conf` disables unqualified search and enforces short-name
resolution. Sigstore attachment discovery is enabled, but no trust identity is
baked into this generic image.

Before the first pull, the administrator must replace the default policy with
the narrowest `sigstoreSigned` or `signedBy` rule for each registry/repository
and install its trust anchor in encrypted state. A registry TLS certificate or
authenticated registry login is not an image signature. Digest pinning is
useful but is not a substitute for an independently trusted signature.

## Network model

The host uses systemd-networkd and systemd-resolved. DHCP-provided DNS is
ignored; DNSSEC and strict DNS-over-TLS are sent to fixed resolvers. nftables
has default-deny input, forwarding, and output chains. It permits DHCP, ICMP,
NTS/NTP, signed OS update HTTPS, root-operated TLS registry access, SSH, and the
minimum Podman bridge/DNAT forwarding paths. Netavark owns its separate Podman
nftables state; host rules do not flush the full ruleset.

The signed `nft_hash` and `nft_limit` expression modules are loaded before the
ruleset so ICMP, SSH, and updater rate limits are available. After the firewall
is active, ParticleOS irreversibly disables further kernel module loading.

This baseline allows broad outbound TLS by root because root invokes image
pulls. Repository-specific destination filtering belongs to site provisioning
and should be added when registry addresses are stable.

## Residual risks

- Root remains inside the trusted computing base and can replace image policy,
  firewall rules, or persistent state.
- gVisor reduces the host-kernel attack surface but is another security-critical
  runtime and does not make malicious workloads safe.
- SELinux cannot label individual gVisor container processes; isolation between
  workloads relies primarily on gVisor, namespaces, cgroups, Podman defaults,
  and application-specific policy.
- Availability can be exhausted through storage, CPU, memory, namespace, log,
  or network consumption unless each workload receives explicit limits.
- The generic firewall cannot know application ingress ports. Operators must
  add narrowly scoped published-port rules as part of workload provisioning.
