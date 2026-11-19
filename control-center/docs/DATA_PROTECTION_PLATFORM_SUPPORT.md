# Platform support and Data Protection lifecycle

This is a **tested-behavior matrix**, not a general OS certification or a
production support commitment. CI builds the shipping project for Windows
Server 2022 and Ubuntu 24.04 images; the Windows DPAPI and Ubuntu Linux key-ring
tests run on isolated GitHub-hosted machines. CI evidence is not a customer-host
service-manager, reboot, backup-recovery, or availability acceptance.

The project targets `net10.0` and pins .NET SDK `10.0.100` with feature-band
roll-forward. CI installs .NET `10.0.x`. Deployment hosts need a currently
supported .NET 10 runtime; this repository does not publish a self-contained
runtime bundle.

| Host / feature | Current implementation | CI or artifact evidence | Support boundary |
| --- | --- | --- | --- |
| Windows Server 2022 | ASP.NET Data Protection XML is stored under `%ProgramData%\GatewayCoreYarp\ControlPlane\data-protection-keys` and protected with Windows DPAPI LocalMachine scope. Backend mTLS lookup uses `LocalMachine\My` by certificate thumbprint. Isolated traffic/management listeners load PFX files from paths. | `windows-2022` build and DPAPI acceptance inspect protected XML, reopen persisted keys, decrypt pre-restart data, and reject tampered wrapped material. | Windows Service hosting and installation are not implemented or qualified. `INSTALL.ps1` is an offline source-staging installer for an existing Windows Server/.NET 10 host, not a service installer. CI does not qualify production service identity, explicit ACLs, host reboot, or recovery. DPAPI LocalMachine data is host-bound; copying its key-ring directory to another server is not a recovery method. |
| Ubuntu 24.04 | Linux Data Protection keys are persisted below `$YARP_CONTROL_PLANE_DIR/data-protection-keys` and RSA-certificate-wrapped. State and secret files require owner-only permissions. Isolated HTTPS listeners load path-based PFX files with protected password files. | `ubuntu-24.04` build, filesystem/key-wrapping tests, certificate-overlap tests, and real Control Center process restart/cookie acceptance run in Actions. `ops/systemd/gatewaycore-yarp.service` is a template artifact. | The systemd template is not installed or exercised by current CI acceptance. Production systemd identity, reboot/restart, host backup/recovery, and a separate physical host remain unverified. The template is not a complete installer or secret-provisioning procedure. |
| RHEL-family Linux | No RHEL-specific build or Data Protection qualification is recorded. Linux source paths use .NET file APIs and an RSA PFX, but portability is not qualification. | None. | **Not qualified for deployment.** Do not infer RHEL support from Ubuntu or .NET portability. Test the exact RHEL release, .NET 10 runtime, OpenSSL/crypto provider, service identity, filesystem, certificate handling, and systemd lifecycle first. |
| HTTP load-balancing policy behavior | The application exposes YARP `RoundRobin`, `PowerOfTwoChoices`, `LeastRequests`, `Random`, and `FirstAlphabetical`, plus GatewayCore `WeightedRandom`, `SourceIpHash`, and `PrimaryBackup`. These are HTTP destination policies, not OS-specific behavior. | Selected policies and failure behavior have Windows and Ubuntu L7 Actions acceptance. | The list does not certify every policy, protocol, or capacity on every host OS. It does not add L4, DNS/GSLB, or WAF support to the Control Center process. |
| Product containers | The repository has Docker-based CI/acceptance fixtures for selected integrations. | Disposable test containers only. | No production GatewayCore container image, entrypoint, key-volume lifecycle, or container-host support matrix is published. Do not deploy an acceptance image as a product image. |

On Windows, protect the ProgramData state tree with an explicit ACL granting
access only to the intended service identity and administrators. The current
application does not create or validate that service identity or ACL, and there
is no supported Windows Service registration script. Until those are qualified,
the Windows service lifecycle is **not supported by this release**.

## Linux production configuration requirements

The Linux mode fails startup when these inputs are absent or invalid; it has no
persistent plaintext fallback:

- `YARP_CONTROL_PLANE_DIR`: absolute private root owned by the service identity.
- `YARP_RUNTIME_CONFIG_PATH`: exactly `config/appsettings.json` beneath that root.
- `YARP_LINUX_DP_CERT_PFX_PATH` and `YARP_LINUX_DP_CERT_PASSWORD_FILE`: RSA private
  certificate and its password file. Both files must be regular, non-symlinked,
  owner-readable/writable only (`0600`); the root and key directory must be
  non-symlinked and owner-only (`0700`).
- For certificate rotation, set the current certificate to the replacement and
  configure both `YARP_LINUX_DP_OLD_CERT_PFX_PATH` and
  `YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE` with the previous certificate during
  overlap. CI verifies that existing protected data can be opened during this
  overlap. Existing key XML files are **not automatically rewrapped**. Keep each
  previous private key and password available while any persisted XML key it
  protects remains in the ring. Key expiry alone is not sufficient reason to
  delete a protector: old Data Protection keys may still be needed to
  authenticate unexpired cookies or unprotect retained data. There is no
  supported key-ring rewrap/retirement tool yet.

Provision secret files through a protected delivery mechanism. Do not put PFX
passwords in command-line arguments, unit files, source control, or logs.
Treat the Linux key ring, every certificate that wraps a key in that ring, and
their passwords as one protected recovery set. Back them up only to an
access-controlled, encrypted target. Restore first to an isolated host running
as the intended service identity, then verify both a pre-backup cookie and a
new cookie before receiving traffic. Do not restore an older key ring over a
newer one without accounting for sessions issued since the backup; anti-rollback
protection is not implemented. Backup/restore has not been qualified in CI or
on a customer host.

Windows DPAPI LocalMachine keys are machine-bound. Preserve the protected key
ring with a machine-level recovery plan, but do not assume it can be restored to
another Windows host or after OS reprovisioning. No portable Windows key backup
or cross-host recovery procedure is qualified. A missing or undecryptable key
ring invalidates sessions protected by those keys.

The Data Protection directory is per instance. Shared-fleet key storage and
coordinated rotation are not implemented or qualified. Do not point multiple
production instances at an uncoordinated shared directory or copy a Linux
protector certificate/key ring between hosts to imply safe multi-node session
continuity. KMS/HSM key retrieval, authenticated shared storage, anti-rollback,
and automated disaster recovery are also absent.

## Operational lifecycle status

| Operation | Documented safe boundary | Current status |
| --- | --- | --- |
| First install | Provision a dedicated service identity, private state path, runtime config, and secret files before start. Keep the Linux systemd template's `ReadWritePaths`, `UMask=0077`, and `NoNewPrivileges` safeguards; use a measured service-specific resource override rather than copying invented limits. | Windows staging installer and Linux systemd unit are templates, not production installers. Do not use either as evidence of a qualified service lifecycle. |
| Backup and restore | Back up the full protected state plus every key/certificate/password required to decrypt it. Restrict, encrypt, version, and audit backups. Restore in isolation first, run cookie and state integrity checks, then use the existing reviewed rollout/rollback process. | No automated backup, restore validation, immutable audit integration, or tested customer recovery runbook. Windows DPAPI state is machine-bound. |
| Linux wrapping-certificate rotation | Set the replacement as current and the previous certificate as old; keep both available while any persisted XML key requires the old certificate. Restart one isolated instance and verify old-cookie unprotect plus new-key persistence before rollout. | Certificate-overlap source/CI tests exist. Production operator rotation, XML rewrap, fleet coordination, and a safe certificate-removal criterion are not qualified. |
| Key loss or tamper | Fail closed; do not generate a replacement ring over the old state and claim sessions were recovered. Revoke affected sessions and restore from a verified compatible backup if available. | Linux tamper rejection is tested. Windows/Linux service recovery after lost or corrupted key material is not accepted on representative hosts. |
| Move between hosts | Do not copy Windows DPAPI keys to another machine. Linux requires the matching wrapping private certificate and same application/purpose configuration; host-level state and anti-rollback controls still need independent review. | Cross-host key-ring migration and multi-node cookie continuity are unsupported. |

The Linux process test starts the real Control Center in Production mode,
inspects persisted key XML for certificate wrapping, creates an authenticated
administrative cookie, terminates the process, then restarts it against the same
key ring and verifies the pre-restart cookie still authenticates. This is
repeatable CI evidence only; it does not replace a service-manager restart, host
reboot, tamper, or lost-key drill on representative Ubuntu and Windows Server
machines. RHEL remains unqualified. Issue #48 remains open until the missing
host lifecycle, recovery, rotation, and customer-host acceptance is completed.
