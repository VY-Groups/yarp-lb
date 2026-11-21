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
| Windows Server 2022 | ASP.NET Data Protection XML is stored under `%ProgramData%\GatewayCoreYarp\ControlPlane\data-protection-keys`, protected with Windows DPAPI LocalMachine scope, and access-controlled for the current process identity, SYSTEM and local Administrators. Startup rejects inherited or broadly accessible product/state/key directories and existing key files; it does not rewrite an existing unsafe ACL or key ring. Backend mTLS lookup uses `LocalMachine\My` by certificate thumbprint. Isolated traffic/management listeners load PFX files from paths. | `windows-2022` build and DPAPI acceptance inspect protected XML and key-file ACLs, reopen approved persisted keys, decrypt pre-restart data, reject tampered wrapped material, and prove existing unsafe ACLs are rejected without mutation. | Windows Service hosting and installation are not implemented or qualified. `INSTALL.ps1` is an offline source-staging installer for an existing Windows Server/.NET 10 host, not a service installer. An installation created before explicit ACL enforcement may fail startup until an independently reviewed offline ACL migration is performed; this release does not migrate it. CI does not qualify production service identity, host reboot, or recovery. DPAPI LocalMachine data is host-bound; copying its key-ring directory to another server is not a recovery method. |
| Ubuntu 24.04 | Linux Data Protection keys are persisted below `$YARP_CONTROL_PLANE_DIR/data-protection-keys` and RSA-certificate-wrapped. State and secret files require owner-only permissions. Isolated HTTPS listeners load path-based PFX files with protected password files. | `ubuntu-24.04` build, filesystem/key-wrapping tests, certificate-overlap tests, real Control Center process restart/cookie acceptance, and a temporary systemd service start/restart using the shipped unit template run in Actions. The service test uses an isolated runner account and disposable paths. | CI exercises a template-derived temporary unit, not a production installation. Production provisioning, service identity/ACLs, host reboot, backup/recovery, and a separate physical host remain unverified. The template is not a complete installer or secret-provisioning procedure. |
| RHEL-family Linux | No RHEL-specific build or Data Protection qualification is recorded. Linux source paths use .NET file APIs and an RSA PFX, but portability is not qualification. | None. | **Not qualified for deployment.** Do not infer RHEL support from Ubuntu or .NET portability. Test the exact RHEL release, .NET 10 runtime, OpenSSL/crypto provider, service identity, filesystem, certificate handling, and systemd lifecycle first. |
| HTTP load-balancing policy behavior | The application exposes YARP `RoundRobin`, `PowerOfTwoChoices`, `LeastRequests`, `Random`, and `FirstAlphabetical`, plus GatewayCore `WeightedRandom`, `SourceIpHash`, and `PrimaryBackup`. These are HTTP destination policies, not OS-specific behavior. | Selected policies and failure behavior have Windows and Ubuntu L7 Actions acceptance. | The list does not certify every policy, protocol, or capacity on every host OS. It does not add L4, DNS/GSLB, or WAF support to the Control Center process. |
| Product containers | The repository has Docker-based CI/acceptance fixtures for selected integrations. | Disposable test containers only. | No production GatewayCore container image, entrypoint, key-volume lifecycle, or container-host support matrix is published. Do not deploy an acceptance image as a product image. |

## HTTP protocol and optional-engine support boundary

“CI tested” means the named isolated runner exercised the stated code path. It
does not mean externally deployed or production-qualified. HTTP/3 is opt-in;
the application does not turn it on by default.

| Protocol / engine | CI-tested behavior | Current support status and boundary |
| --- | --- | --- |
| HTTP/1.1 | Real L7 HTTP requests run on Windows Server 2022 and Ubuntu 24.04 Actions in `tests/L7/Acceptance/Program.cs`, via `.github/workflows/l7-acceptance.yml`. The TLS listener test also checks HTTP/1.1 when its protocol test can run. | CI-tested for the lab paths. Customer listener, firewall, TLS, streaming and capacity qualification remain open. |
| HTTP/2 | `control-center/tests/TlsInventoryTests/TrafficHttp3Acceptance.cs` explicitly requests HTTP/2; `.github/workflows/control-center-ci.yml` runs the test on Windows and Ubuntu. The test performs wire checks when MsQuic is available; Windows does so, Ubuntu exits after configuration assertions when MsQuic is absent. | Windows CI-tested; Ubuntu wire behavior is unqualified by current Actions. No customer protocol, gRPC or long-lived stream qualification. |
| HTTP/3 | `control-center/tests/TlsInventoryTests/TrafficHttp3Acceptance.cs` performs an actual TLS 1.3/QUIC request and verifies protocol negotiation on the Windows runner from `.github/workflows/control-center-ci.yml`. Ubuntu reports `SKIP` because MsQuic is unavailable. | Opt-in and Windows-CI-tested only. Ubuntu wire behavior and every physical/cloud firewall path are unqualified. Requires .NET 10 runtime with MsQuic and TCP+UDP reachability to the HTTPS port. |
| HTTPS | `tests/L7/Acceptance/Program.cs` sends a real HTTPS request through an isolated TLS listener with a disposable localhost certificate, via `.github/workflows/l7-acceptance.yml` on Windows and Ubuntu. | Lab-tested on Windows and Ubuntu; this does not qualify customer CA chains, public certificate lifecycle, external TLS termination, or deployed listener hardening. |
| L4 TCP/UDP | `tests/L4Acceptance/Program.cs` tests real sockets on Windows and Ubuntu via `.github/workflows/l4-acceptance.yml`. | Isolated external engine, CI-lab-tested only; not integrated into GatewayCore Control Center lifecycle and not supported as a production product deployment. |
| DNS/GSLB | `tests/GslbAcceptance/Program.cs` covers selected authoritative DNS and failover paths on Windows and Ubuntu. `.github/workflows/gslb-acceptance.yml` also runs two-node validators, signed agent reports, DNSSEC signing/independent validation, and IPv6 interop in Linux CI. | Experimental standalone engine. DNSSEC test-chain behavior is CI-tested; production key storage/rollover, licensed GeoIP/ECS operations, public delegation, multi-network authoritative conformance, and physical authority acceptance remain unqualified; see issue #52. |
| WAF | `tests/WafCrs/verify.sh` exercises selected benign and blocking traffic through ModSecurity/OWASP CRS via `.github/workflows/waf-crs-acceptance.yml`. | Optional external lab integration only. No built-in GatewayCore WAF, production ruleset operations, false-positive qualification, or supported production WAF deployment is claimed; see issue #51. |

On Windows, a fresh startup creates protected product, state and key directories
with explicit ACLs granting access only to the current process identity,
LocalSystem and local Administrators. Existing directories must already have a
protected ACL with no additional allow principals; persisted Data Protection key
files are checked for the same allowlist. Unsafe pre-existing ACLs fail startup
without being changed. Apply any required migration offline through a reviewed
procedure that preserves the DPAPI key bytes and validates cookie recovery; no
automatic ACL or key-ring migration is included. There is no supported Windows
Service registration script. The Windows service lifecycle is not supported by this release
until service identity provisioning, installation, reboot and recovery are qualified.

## Linux production configuration requirements

The Linux mode fails startup when these inputs are absent or invalid; it has no
persistent plaintext fallback. Before registering certificate wrapping, it
also checks existing key-ring XML for owner-only permissions, symlinks and an
encrypted-secret envelope. A legacy plaintext ring is refused without deleting
or rewriting it. This is a read-only startup format check, not proof that every
wrapped key decrypts, authentication of the on-disk ring, or anti-rollback.
Recover an approved protected backup in isolation; do not remove existing
keys merely to make the service start:

- `YARP_CONTROL_PLANE_DIR`: absolute private root owned by the service identity.
- `YARP_RUNTIME_CONFIG_PATH`: exactly `config/appsettings.json` beneath that root.
- `YARP_LINUX_DP_CERT_PFX_PATH` and `YARP_LINUX_DP_CERT_PASSWORD_FILE`: RSA private
  certificate and its password file. The RSA private-key certificate must
  be a valid, non-CA leaf with explicit X.509 `keyEncipherment` key usage
  and a BasicConstraints extension declaring CA=false. Signing-only and CA
  certificates, or certificates missing these declarations, fail startup;
  provision a dedicated replacement certificate before upgrading if your
  current wrapping PFX is not compliant. Do not remove an old protector while
  existing key-ring entries still depend on it. Both files must be regular,
  non-symlinked, owner-readable/writable only (`0600`); the root and key
  directory must be non-symlinked and owner-only (`0700`).
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
| First install | Provision a dedicated service identity, private state path, runtime config, and secret files before start. Keep the Linux systemd template's `ReadWritePaths`, `UMask=0077`, and `NoNewPrivileges` safeguards; use a measured service-specific resource override rather than copying invented limits. | Actions validate and exercise a temporary service derived from the Linux unit template. The Windows staging installer and Linux systemd unit remain templates, not production installers. CI does not qualify an installed production service lifecycle. |
| Backup and restore | Back up the full protected state plus every key/certificate/password required to decrypt it. Restrict, encrypt, version, and audit backups. Restore in isolation first, run cookie and state integrity checks, then use the existing reviewed rollout/rollback process. | No automated backup, restore validation, immutable audit integration, or tested customer recovery runbook. Windows DPAPI state is machine-bound. |
| Linux wrapping-certificate rotation | Set the replacement as current and the previous certificate as old; keep both available while any persisted XML key requires the old certificate. Restart one isolated instance and verify old-cookie unprotect plus new-key persistence before rollout. | Certificate-overlap source/CI tests exist. Production operator rotation, XML rewrap, fleet coordination, and a safe certificate-removal criterion are not qualified. |
| Key loss or tamper | Fail closed; do not generate a replacement ring over the old state and claim sessions were recovered. Revoke affected sessions and restore from a verified compatible backup if available. | Linux tamper rejection is tested. Windows/Linux service recovery after lost or corrupted key material is not accepted on representative hosts. |
| Move between hosts | Do not copy Windows DPAPI keys to another machine. Linux requires the matching wrapping private certificate and same application/purpose configuration; host-level state and anti-rollback controls still need independent review. | Cross-host key-ring migration and multi-node cookie continuity are unsupported. |

The Linux process test starts the real Control Center in Production mode,
inspects persisted key XML for certificate wrapping, creates an authenticated
administrative cookie, terminates the process, then restarts it against the same
key ring and verifies the pre-restart cookie still authenticates. An additional
Ubuntu Actions test renders a temporary unit from the shipped systemd template,
runs the application as a disposable unprivileged account, and verifies that
`systemctl restart` preserves the encrypted key ring and pre-restart cookie.
These are repeatable CI checks only; they do not replace production service
installation, host reboot, backup/recovery, tamper, or lost-key drills on
representative Ubuntu and Windows Server machines. RHEL remains unqualified.
Issue #48 remains open until the missing host lifecycle, recovery, rotation, and
customer-host acceptance is completed.

## Linux secret path hardening

Wrapping PFX files (up to 1 MiB), password files (up to 4 KiB) and startup key-ring XML inspection now use the shared no-follow file reader. It validates ownership, declared object type and permissions on opened handles, traverses each ancestor without following symlinks, rejects unsafe writable ancestors, bounds input, detects size changes and clears temporary PFX/password byte arrays. Linux state/key directories also validate their ancestor chain. Protected parents and service ownership remain required throughout operation; framework-managed key-ring reads/writes are not replaced by this startup inspection, and this is not a complete defense against a compromised service identity. Existing tests are extended for secret ancestor links, writable parents and oversized password files. No key-ring migration, cross-host key sharing or anti-rollback is implied.

### Linux state bootstrap no-follow boundary (#48)

State-directory and `data-protection-keys` directory creation now walks each
Linux path component through an already-opened directory descriptor and
rejects symlinks before creating children beneath them. Previously ordinary
path-based `Directory.CreateDirectory` could follow a linked parent and create
an unwanted subtree before the later ancestry check refused startup.
Regression tests cover existing and dangling linked ancestors and a linked
key-ring directory; all must fail without touching the external target.
The final directories still require service-owner-only mode `0700`.
This closes one local bootstrap race class, but **does not** prove fleet
anti-rollback, shared key-ring disaster recovery, Windows Server/RHEL
operational acceptance or production readiness.

### Linux encrypted-key-ring restore identity checks (#48)

Linux Data Protection startup now requires each encrypted `<key id=GUID>` XML
file to use its matching `key-GUID.xml` filename and to have a unique
in-ring GUID. At most **512 XML entries** (keys and revocations combined) may
be present. Rewritten key IDs, renamed/copied XML and oversized inventories
fail before the ASP.NET Data Protection provider can import ambiguous state.
The checker does not modify or decrypt a rejected file; tests confirm an
existing encrypted session remains decryptable after the rejected tampering
is reversed. These limits apply to the existing at-rest certificate wrapping
and independent per-process startup path.

**Important:** filename/GUID consistency is local integrity validation, not
a cryptographically anchored anti-rollback guarantee. A privileged attacker
could restore an older internally consistent key set. A fleet recovery plan
still needs separately verified immutable backup checkpoints, shared wrapping
key custody, version attestation, secure cross-host synchronization and a DR
rotation exercise. Do not claim full #48 or production acceptance from this
increment alone.

### Signed, operator-anchored Linux key-ring restore verification (#48)

A new **opt-in restore gate** validates the exact encrypted key-ring inventory
against an independently signed, versioned checkpoint **before** ASP.NET Data
Protection imports the restored keys. This gate is intentionally separate from
the normal on-disk certificate wrapping, key GUID checks and shared-fleet
operations. It never writes, repairs, rewraps or decrypts a restored key.

For a deliberately staged recovery, provision all three settings:

- `YARP_LINUX_DP_RECOVERY_MANIFEST_FILE`: absolute, 0600, non-symlinked
  trusted checkpoint JSON, independent of the backup whose integrity is checked
- `YARP_LINUX_DP_RECOVERY_TRUST_PUBLIC_KEY_FILE`: absolute, 0600, non-symlinked
  SubjectPublicKeyInfo PEM for an independently managed **ECDSA P-256** signer
- `YARP_LINUX_DP_RECOVERY_MINIMUM_REVISION`: positive decimal sequence
  maintained outside the restored snapshot by an independent operator/control
  authority; a signed older revision is rejected even if otherwise valid

Setting one or two of these values without all three is a startup error. The
manifest is a JSON object with exactly the `Version` (1), `Revision`,
`InventorySha256` (64 uppercase hex digits) and `SignatureBase64` fields.
Unknown fields and duplicate/case-aliased names fail closed. `SignatureBase64`
is an ECDSA P-256 SHA-256 **IEEE P1363 64-byte** signature, not DER, over the
canonical ASCII payload:

```text
GatewayCore.LinuxDP.RecoveryAttestation.v1
<Revision, invariant unsigned decimal>
<InventorySha256, uppercase hex>
```

Each displayed line terminates with a newline (LF). The inventory digest is
SHA-256 over the exact ASCII prefix
`GatewayCore.LinuxDP.Inventory.v1\n` followed by, for **each** XML entry
in ordinal filename order, `<filename>\n<SHA256 of exact XML bytes in uppercase hex>\n`.
The manifest supports 1–512 XML files, each at most 1 MiB, and every file is
read from its validated owner-only, non-symlinked handle. The signature
**must be generated offline** by an operator-approved signing system from a
reviewed inventory. Do not put a signing private key or an untrusted signer in
the GatewayCore runtime or inside the restored backup. The verifier only needs
the independently pinned public key.

CI acceptance uses genuine certificate-wrapped key files and a disposable
offline signing identity. It verifies an unchanged authenticated session
survives a signed restore and rejects forged signatures, stale (signed)
revisions, case-aliased JSON, changed XML bytes and missing attestation inputs.
This does not prove custody of the signing key, real fleet monotonic counter
storage, Windows DPAPI cross-host recovery, RHEL deployment or a physical DR
drill. A privileged attacker who can replace the externally trusted public key
**and** lower the independently protected minimum revision can still authorize
an older ring. Operators must safeguard those inputs outside the recovery
domain. Do not declare fleet-wide anti-rollback or production GO from the
presence of this optional gate.
