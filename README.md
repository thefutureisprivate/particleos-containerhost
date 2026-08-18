# ParticleOS Container Host

ParticleOS Container Host is one generic, workload-independent Fedora 44
container appliance. It is based directly on upstream
[`systemd/particleos`](https://github.com/systemd/particleos) and retains its
signed UKI, dm-verity, Discoverable Partitions, and `systemd-sysupdate` model.
The repository intentionally contains no mail, database, proxy, or application
roles.

The mutable boundary is a TPM2-sealed LUKS2/Btrfs root partition. The OS is a
signed, read-only `/usr` DDI with two A/B slots. Secure Boot authenticates the
UKI and bootloader; the UKI authenticates the selected dm-verity root hash; IPE
then prevents execution of host code outside the authenticated OS policy.

Rootful Podman is the sole workload interface. Its default and only installed
OCI runtime is release-pinned gVisor `runsc` using systrap. Containers are
read-only by default, short names are disabled, every pull is fresh, and the
containers/image policy rejects every image until an administrator installs an
explicit signature rule and trust anchor. Rootless Podman helpers and user
units are absent.

## Security invariants

- Secure Boot, a signed UKI, signed dm-verity root hashes, and IPE enforcement
  form one verified boot-to-execution chain.
- `/usr` is read-only, verity protected, and mounted `nosuid,nodev`.
- all persistent `/etc`, container storage, logs, keys, and user data reside on
  the TPM2 PCR 7-bound encrypted state partition;
- SELinux is enforcing and a local CIL policy restricts user namespaces and
  unused host socket families;
- only `unix_chkpwd` remains setuid; Podman is executable only by root or an
  explicitly delegated administrative group;
- SSH is key-only and disabled until an operator provisions a host key,
  account, and authorized key;
- systemd-resolved uses DNSSEC and DNS-over-TLS, while nftables defaults to
  deny for input, forwarding, and output;
- application images and credentials never belong in the OS build.

See [the security model](docs/SECURITY-MODEL.md), [the hardening review](docs/HARDENING-REVIEW.md),
and [the operations guide](docs/OPERATIONS.md) before provisioning a machine.

## Build and validate

The normal local path uses current mkosi:

```console
./scripts/validate.sh
mkosi build
```

Local builds intentionally use only the signed `system:systemd` and
`home:thefutureisprivate` OBS repositories configured in
`mkosi.conf.d/10-local-repositories.conf`. OBS uses `.obs/` recipes and the
upstream `mkosi-obs` deferred-signing implementation. The OBS project
certificate is the Secure Boot and dm-verity trust root.

The `runsc` OBS package is built independently from an exact official gVisor
release archive and pinned checksums. The image consumes that package plus the
existing `hardened_malloc`, `ipe-policy`, and `no_rlimit_as` packages.

Production packages are published as
[`home:thefutureisprivate/particleos-containerhost`](https://build.opensuse.org/package/show/home:thefutureisprivate/particleos-containerhost)
and [`home:thefutureisprivate/runsc`](https://build.opensuse.org/package/show/home:thefutureisprivate/runsc).
The live image service is pinned to a reviewed signed Git commit; the tracked
`_service.example` documents the exact source-service shape without creating a
self-referential revision update in Git.

## Upstream and reference provenance

The initial baseline is upstream ParticleOS commit `dd4fdc2`. The previous
`custom-particleos` repository was reviewed only as a control catalogue. No
role-image hierarchy, installer, application service, or workload-specific
policy was imported. Each retained, adapted, or rejected control is recorded
in `docs/HARDENING-REVIEW.md`.

## License

ParticleOS is licensed under LGPL-2.1-or-later; see [LICENSE](LICENSE). The
separately packaged gVisor binaries are Apache-2.0 and ship their upstream
license in the RPM.
