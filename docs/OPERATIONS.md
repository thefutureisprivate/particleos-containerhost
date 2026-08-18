# Operations

## Installation and Secure Boot enrollment

Write the OBS-produced raw image to the whole target disk using a separately
trusted environment. Verify its published checksum and provenance before
writing it. Boot with UEFI Secure Boot in setup mode so systemd-boot can enroll
the OBS project key contained in the signed image, then leave setup mode and
confirm Secure Boot is active.

The image has no alternate installer or recovery profile. Keep independently
verified, signed recovery media and escrow any LUKS recovery material according
to site policy.

After the first boot, verify at minimum:

```console
bootctl status
systemd-analyze image-policy
systemd-cryptenroll /dev/disk/by-partlabel/ParticleOS-Host-root
getenforce
cat /sys/kernel/security/ipe/policies/*/active
podman info --format '{{.Host.OCIRuntime.Name}}'
runsc --version
systemd-sysupdate list
```

Expected results include Secure Boot enabled, SELinux `Enforcing`, `runsc` as
the OCI runtime, and two OS-version slots. Device names vary; inspect them with
`systemd-repart --json=pretty /dev/<disk>` before using enrollment commands.

## Administrative access

The root account is locked and SSH is not enabled by the image. Provision a
named administrative account, its Ed25519 authorized key, and the minimum sudo
or polkit authorization through a trusted local mechanism. Then create host
keys and enable the socket explicitly:

```console
systemctl enable --now sshd-keygen@ed25519.service
systemctl enable --now sshd.socket
```

Do not enable password login, direct root login, agent forwarding, TCP
forwarding, X11 forwarding, or user Podman services.

## Provision OCI trust before pulling

The factory image rejects every image. Install public verification material
under `/etc/pki/containers/` and replace `/etc/containers/policy.json` with
repository-scoped `sigstoreSigned` or `signedBy` requirements. Bind the expected
repository identity and signature issuer where the policy format supports it.
Keep `default: reject` as the final fallback.

Validate the policy with a deliberately unsigned image as well as an approved
signed image. An unsigned image must fail before unpacking. Never use
`insecureAcceptAnything`, disable TLS verification, or add an unqualified-search
registry.

## Workloads

Use root-owned Quadlet files in `/etc/containers/systemd/`. Specify immutable
image references, read-only mounts where possible, dropped capabilities,
resource limits, health checks, restart policy, and only the required network
ports. Treat `--privileged`, host namespaces, host devices, host filesystem
mounts, runtime overrides, and policy overrides as exceptions requiring review.

The base firewall accepts inbound SSH and Podman DNAT traffic, but a site should
add destination- and port-specific host rules for every workload. Do not edit
the generated Netavark nftables tables directly.

## Updating and rollback

```console
systemd-sysupdate list
systemd-sysupdate check-new
systemd-sysupdate update
systemctl reboot
```

The update service is the only non-root process granted update HTTPS by the
host firewall. `Verify=yes` is mandatory on all remote transfers. Boot counting
keeps the previous slot until the new boot is healthy and blessed. Investigate
a rollback before retrying; do not manually relabel an unverified slot.

## Incident response

On suspected host compromise, isolate the machine, preserve volatile evidence,
and rebuild from a known signed image. Rotating only container credentials is
not sufficient because root can alter encrypted persistent state. Rotate image
trust, workload, SSH, registry, and TPM-bound secrets according to exposure,
and review OBS signing-key custody and build logs.
