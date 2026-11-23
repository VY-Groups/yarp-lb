# RHEL-family Linux Data Protection userspace compatibility

The workflow at .github/workflows/rhel-ubi9-dp-compat.yml pulls the
official Red Hat UBI 9 .NET 10 SDK image from registry.access.redhat.com
and freezes its actual OCI repository digest for that run. It launches a
disposable, non-root, no-network, read-only container with restricted
capabilities and a temporary writable private filesystem. The source
checkout is mounted read-only; the only copied linked dependency is the
GatewayCore private-file security module.

The job runs the REAL existing LinuxKeyProtectionTests assembly, including
certificate-wrapped encrypted ASP.NET Data Protection XML, linked-file
and permission rejection, certificate overlap and cookie continuity,
separately signed anti-rollback inventory verification, and the new
offline P-256 checkpoint issuer/verifier integration. No customer keys,
cookies or signing material are supplied or exported.

**Precise limitation:** This executes on the Ubuntu GitHub runner's Linux
kernel inside Red Hat UBI9 *userspace*. A PASS is useful evidence that the
code and .NET 10 dependency graph execute on that userspace without
network access, but DOES NOT qualify RHEL 9 host systemd, SELinux enforcing
file contexts, kernel behavior, host PKI/HSM/backup custody or an actual
cross-host recovery. RHEL host deployment remains NOT QUALIFIED until
an authorized disposable RHEL 9 VM runs the service/reboot/SELinux and
recovery matrix in ops/acceptance/ISSUE_48_KEYRING_RECOVERY_MATRIX.md.

This is an additive #48 software compatibility test, not permission to
enable unsupported production platforms or to close #36. No CI thresholds
or existing Linux/Windows Data Protection security checks are relaxed.
