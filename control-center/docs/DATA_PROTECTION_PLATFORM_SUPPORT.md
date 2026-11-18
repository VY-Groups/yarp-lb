# Data Protection platform support

This matrix describes the current Data Protection key protection path. It is not
a general operating-system certification or a production support commitment.
Only isolated GitHub Actions runners have been exercised for the Linux process
acceptance described below.

| Platform | Key protection and persistence | Evidence in this repository | Current boundary |
| --- | --- | --- | --- |
| Windows Server 2022 | ASP.NET Core key ring persisted under `C:\ProgramData\GatewayCoreYarp\ControlPlane\data-protection-keys`, protected with Windows DPAPI LocalMachine scope. | Windows Control Center build/source Actions and Data Protection engine tests. | Real Windows Service identity, ACL, restart, backup/restore, and representative-server recovery acceptance are not recorded. Keep the key ring machine-bound; copying it to another host does not make it decryptable there. |
| Ubuntu 24.04 | Persistent key ring under `$YARP_CONTROL_PLANE_DIR/data-protection-keys`, certificate-wrapped with the configured RSA PFX. Production Linux requires a private state root and runtime config path. | Linux Actions build and product-process startup test with disposable key/cert fixtures; test asserts private directories and wrapped key XML. | This tests a GitHub-hosted Ubuntu VM, not a customer host. KMS/HSM integration, OS service identity, backup/restore, fleet sharing, and recovery drills remain unverified. |
| RHEL-family Linux | No separate platform-specific qualification recorded. | None. | Do not infer support from Ubuntu or .NET portability. Validate the exact distribution, .NET 10 runtime, crypto provider, service identity, filesystem, and certificate store before use. |

## Linux production configuration requirements

The Linux mode fails startup when these inputs are absent or invalid; it has no
persistent plaintext fallback:

- `YARP_CONTROL_PLANE_DIR`: absolute private root owned by the service identity.
- `YARP_RUNTIME_CONFIG_PATH`: exactly `config/appsettings.json` beneath that root.
- `YARP_LINUX_DP_CERT_PFX_PATH` and `YARP_LINUX_DP_CERT_PASSWORD_FILE`: RSA private
  certificate and its password file. Both files must be regular, non-symlinked,
  owner-readable/writable only (`0600`); the root and key directory must be
  non-symlinked and owner-only (`0700`).
- For certificate rotation, configure both `YARP_LINUX_DP_OLD_CERT_PFX_PATH` and
  `YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE` during the overlap period. Keep the old
  private key available until every key encrypted with it has expired or been
  deliberately retired and session compatibility is accepted.

Provision these files through a protected secret-delivery mechanism. Do not put
PFX passwords in command-line arguments, unit files, source control, or logs.
Restrict backups containing the private key and key ring together, and rehearse
restore before relying on encrypted state. This repository does not implement
KMS/HSM key retrieval, authenticated shared-fleet storage, anti-rollback, or
automated disaster recovery. A shared directory or copied certificate is not
proof of safe multi-node cookie/session continuity.

The Linux process test now starts the real Control Center in Production mode,
inspects the persisted key XML for certificate wrapping, terminates it, and
restarts it against the same key ring. This is repeatable CI evidence only; it
does not replace a service-manager restart, host reboot, tamper, or lost-key
drill on representative Ubuntu and Windows Server machines. Issue #48 remains
open until those requirements are accepted.
