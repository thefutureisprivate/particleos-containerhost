# Hardening review

This is the disposition record for controls found in the previous
`custom-particleos` project. “Retain” means the same security property remains
useful; “adapt” means the control was redesigned for a rootful Podman/gVisor
host; “drop” means it was role-specific, obsolete, or harmful to this model.

| Control family | Decision | Container-host implementation or rationale |
|---|---|---|
| Signed UKIs and Secure Boot | Retain | One production UKI, signed by upstream `mkosi-obs`; no less-restricted profiles. |
| Signed dm-verity `/usr` | Retain | Signed root hash and read-only EROFS `/usr`, with two A/B slots. |
| IPE | Retain | Enforcement starts on the kernel command line; packaged policy authenticates host execution. |
| A/B `systemd-sysupdate` | Retain | Four verified transfers update UKI, `/usr`, verity, and signature together. |
| Separate role and service DDIs | Drop | The host is deliberately one generic image; workloads are signed OCI images. |
| Built-in installer/live/debug/emergency UKIs | Drop | They expanded the signed attack surface and carried weaker boot parameters. |
| TPM2 state encryption | Adapt | One PCR 7-bound LUKS2/Btrfs state partition replaces role-specific root/home/swap layouts; optional PCR11/NvPCR/pcrlock enrollment and its setup units are suppressed because they require a separate TPM-compatible policy-signing key and the RSA-4096 OBS key is not loadable by common TPMs. First boot remains noninteractive. |
| SELinux enforcing | Retain | Fedora targeted policy plus a small host-specific CIL module. |
| Broad custom SELinux role policy | Drop | Application domains, databases, mail, DNS, proxy, and installer rules have no host purpose. |
| User-namespace prohibition | Adapt | Login/service domains are denied; only trusted system helpers and gVisor's `container_runtime_t` may create them. |
| Socket-family restrictions | Retain | Unused host protocol families remain denied; guest protocols are implemented by gVisor. |
| Set-ID removal | Retain | Build strips every setuid/setgid bit, then restores only `unix_chkpwd`. |
| Kernel command-line hardening | Retain | Memory initialization, slab, stack, lockdown, module signature, legacy ABI, and initrd fail-closed controls remain. |
| Sysctl hardening | Adapt | Host protections remain; forwarding and a bounded namespace quota are enabled for rootful Podman/gVisor. |
| Kernel module allow/deny policy | Adapt | Obsolete network/filesystem protocols are denied; overlay, bridge, veth, tun, nftables, Btrfs, dm-crypt, and IPE dependencies remain. |
| Post-boot module lockdown | Retain | Required modules, including nftables hash/limit expressions, load first; subsequent module loading is disabled. |
| Hardened allocator and no-RLIMIT-AS | Retain | Reuses the existing OBS packages and preload policy. |
| SSH hardening | Retain | Modern keys/KEX, no password/root login/forwarding; socket remains disabled until provisioned. |
| DNS hardening | Retain | DHCP DNS ignored; strict DNSSEC and DNS-over-TLS are required. |
| Default-deny nftables | Adapt | Preserves host egress policy while adding only Netavark bridge, DNAT, and registry/update flows. |
| Raw prerouting firewall ownership | Drop | The host does not flush or replace Netavark's tables; it owns only `inet particleos_filter`. |
| Rootless Podman | Drop | Rootless helpers, subordinate-ID mappings, user socket/service, and rootless network stacks are removed. |
| `crun` default runtime | Drop | Only official, pinned `runsc` is installed and systrap is explicit. |
| Per-container SELinux MCS labels | Drop | gVisor does not support them; host SELinux remains enforcing around the runtime. |
| Unsigned or mutable OCI trust | Drop | Default policy rejects all images until the operator provisions a narrow signature policy. |
| Role accounts, homed, admin enrollment | Drop | Account and key creation are external provisioning concerns; homed and Fedora's mutable authselect refresh unit are masked. |
| Stalwart/PostgreSQL/nginx/unbound roles | Drop | Application-specific packages, ports, credentials, policy, tests, and docs are absent. |
| Backup/update application orchestration | Drop | The OS updates itself; workload lifecycle belongs outside the base image. |

The review preserves security properties, not file structure. Configuration was
rewritten against upstream ParticleOS and current Fedora/Podman/gVisor behavior.
