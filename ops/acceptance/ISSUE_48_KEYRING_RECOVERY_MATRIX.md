# GatewayCore #48 — key-ring recovery and platform acceptance matrix

**Status: NOT ACCEPTED.** This is a reproducible evidence plan, not a test report. Evidence snapshot revision: `9d7fcee0836c51f6dfb2b33ee1d1bcbfd93293fd`. Do not close #48 on documentation alone. Never copy live authentication keys or cookies into CI or GitHub.



## Certificate expiration during staged rotation (decrypt-only retention)

An active Linux fleet wrapper requires a currently valid RSA encryption leaf,
including its minimum remaining validity window. A *previous* RSA wrapper
is not allowed to generate newly persisted keys, but may have expired
while encrypted historical XML and authentication cookies remain live.
The runtime must permit that previous certificate's private key for
**decryption only**, retaining strict RSA/key-encipherment, non-CA,
permissions, owner-only PFX and separate password checks. New key XML
must use the current unexpired RSA recipient only.

Do not delete an expired previous private PFX based solely on the public
X.509 NotAfter timestamp. Retire it only after verified expiry/revocation
of every session and backup depending on that XML key, followed by
approved retention and attested data-destruction handling. An expired
certificate is not authorized as the active new-key writer. Dispose
only disposable test keys in CI; host service owners must keep custody
and audit of historic decrypt identities.

## Latest automated evidence (2026-11-23; CI only)

These runs exercise real processes on disposable GitHub-hosted runners. They update the rows below but do **not** qualify an operator-managed installation or production platform.

- **Windows Server 2022 DPAPI and SCM:** PR #476 exact-head checks (Actions run 45165804522) completed 41/41 with no failures. The dedicated SCM restart test (Actions run 45165804189, job 137662317769) ran the real executable as LocalSystem, checked protected state/DPAPI XML, and verified the original cookie after service stop/start. It did not test a customer service SID, VM reboot, installed package, or Windows event-log operations.
- **Ubuntu 24.04 systemd and encrypted key ring:** the same exact-head Linux build/acceptance job (Actions run 45165804522, job 137662320118) passed the real systemd restart, mode-0700 encrypted key-ring, and pre-restart cookie continuity checks. This is hosted-runner evidence, not a customer VM restore/DR drill.
- **UBI 9 .NET 10 userspace:** PR #478 checks (Actions run 45166799728) completed without failures; the actual Linux DP suite in UBI 9 (Actions run 45166799728, job 137665716627) passed with a digest-recorded Red Hat base image. It ran inside a container on an Ubuntu runner; **RHEL 9 host systemd, SELinux and kernel behavior remain untested**.

The PR heads were #476 `1f09eef7595bc78bfd971a5f0381c82714eb75e7` and #478 `9c3b76ec0852d3511d56bde84413cbe4ba2bab93`. The rows below distinguish CI passes from still-unrun deployment and recovery work.

## Prerequisites and custody

Use **disposable** Windows Server 2022 and Ubuntu 24.04 VMs, plus a separately provisioned RHEL 9 VM for the stated support claim. Each needs .NET 10 ASP.NET Core runtime, an isolated GatewayCore installation, a nonadministrator service identity, a private writable state directory, and an independently stored, authorized recovery key/certificate. Record OS build, runtime version (`dotnet --info`), source SHA (`git rev-parse HEAD`), package hashes (`sha256sum` on Linux; `Get-FileHash -Algorithm SHA256` on Windows), service identity, ACLs, and configuration digest with secrets redacted. Never use production CA credentials or customer sessions.

The supported/unsupported matrix is **unverified** until all rows below have actual output:

| Platform / lifetime | Protection | Required evidence | Status |
| --- | --- | --- | --- |
| Windows Server 2022 interactive | DPAPI LocalMachine | restart, cookie continuity, ACL and negative access | CI PASS on hosted Windows Server 2022 runner (see above); customer interactive installation NOT RUN |
| Windows Server 2022 SCM service | DPAPI LocalMachine | install/start/reboot/stop, identity, event log, same-machine recovery | CI PASS for LocalSystem start/stop/start and cookie continuity; customer service SID, VM reboot and event-log review NOT RUN |
| Ubuntu 24.04 systemd | encrypted certificate-backed key ring | real headless restart, XML inspection, permissions, key loss/restore | CI PASS for encrypted ring, permissions and restart cookie continuity; customer VM key-loss/restore NOT RUN |
| RHEL 9 systemd | encrypted certificate-backed key ring | SELinux enforcing, file contexts, headless restart and recovery | RHEL host NOT RUN; UBI 9 userspace suite passed, but host systemd/SELinux remain unqualified |
| Linux container | explicit persistent encrypted volume and recovery material | restart/recreate with volume, fail closed without wrapper | NOT RUN |
| Cross-machine shared fleet | explicitly provisioned shared encryption and key-ring identity | cookie continuity, staged rotation, rollback and partition | NOT RUN |

## Baseline and evidence capture

Linux (run from an isolated checkout, with test fixtures only):

```sh
set -eu
git rev-parse HEAD
dotnet --info
dotnet build control-center/GatewayCoreYarp.csproj -c Release
id
umask
find /path/to/disposable/state -maxdepth 2 -printf '%m %u:%g %y %p\n'
systemctl show gatewaycore -p User -p Group -p ExecStart -p StateDirectory -p FragmentPath
journalctl -u gatewaycore --since '15 minutes ago' --no-pager
```

Replace `/path/to/disposable/state` and the service name with the actual documented test installation. If the path or service does not exist, record **NOT RUN**, not PASS. Inspect Data Protection XML **locally**, redact all key/certificate payloads, and assert that no persistent key contains unencrypted secret material. A directory listing is not proof of encryption.

Windows (PowerShell on a disposable VM):

```powershell
git rev-parse HEAD
dotnet --info
dotnet build control-center/GatewayCoreYarp.csproj -c Release
Get-CimInstance Win32_Service | Where-Object { $_.Name -like '*GatewayCore*' } | Select-Object Name,State,StartName,PathName
Get-WinEvent -FilterHashtable @{ LogName='System'; StartTime=(Get-Date).AddMinutes(-15) } | Where-Object { $_.ProviderName -eq 'Service Control Manager' } | Select-Object TimeCreated,Id,Message
```

Do not treat a successful console build or SCM registration as proof that the installed service starts. Capture the actual service name, service SID, configured DPAPI scope, ACLs, restart event sequence and health endpoint response; redact tokens.

## Mandatory negative and recovery cases

1. **Normal restart:** issue a disposable authenticated cookie, restart the real service, and prove the same cookie remains valid within its original lifetime. Expected: HTTP authenticated response, unchanged principal, no key rewrite or auth bypass.
2. **Wrapper absent or invalid:** with a clean isolated state directory, remove only the disposable wrapping certificate/private-key access. Expected: startup or key persistence fails closed; **never** silently creates persistent plaintext keys. Restore the fixture and verify recovery.
3. **Tamper/rollback:** corrupt a copy of an encrypted XML key, substitute a different key-ring identity, duplicate key GUIDs, and restore an older snapshot. Expected: deterministic rejection and audit without silently adopting attacker-controlled state; test anti-rollback separately from XML parsing.
4. **Rotation:** preserve old keys while introducing the new wrapper; verify old cookie and new cookie across two independently restarted nodes. Expected: no session invalidation, no cross-tenant acceptance, bounded rollback procedure. If this behavior is not implemented, mark **FAIL / software gap**, not an environment dependency.
5. **Disaster recovery:** take an encrypted, integrity-protected backup plus separately escrowed recovery material; restore to a fresh disposable host under approved identity. Expected: authorized cookie continuity and no access with an unrelated identity. Record exact restore steps and key version fingerprints, not secret bytes.
6. **Permissions and path attacks:** deny unprivileged service users access to other instances' key rings; test symlink/hardlink/parent-directory substitution and read-only or missing state paths. Expected: fail closed with no unauthorized read/write.
7. **Windows machine boundary:** attempt to use LocalMachine DPAPI-protected material on a different machine without an authorized recovery/migration process. Expected: cannot decrypt. Test the documented supported migration path separately; do not assume DPAPI keys are portable.
8. **RHEL enforcing:** run `getenforce`, `ls -Zd` on the private directory, and start/restart via systemd. Expected: Enforcing, correct policy/contexts, no permissive workaround.
9. **Fleet partition:** independently restart each node during peer unavailability and rotation. Expected: no automatic credential downgrade, plaintext fallback or false success; authenticated sessions behave according to a documented fail-closed policy.

For **every case**, retain: source SHA, OS/runtime, disposable fixture SHA256, exact commands, expected and observed exit codes/HTTP status, redacted logs, timestamps, PASS/FAIL/NOT RUN, reviewer, and rollback result. No test passes based on a mocked assertion alone when a real disposable service test is required.

## Release decision and issue boundary

A #48 software PASS requires merged implementation, Windows and Linux exact-head CI, real disposable service restart and negative tests, deterministic recovery/rotation/anti-rollback tests, supported-platform matrix, offline dependency/install/rollback instructions, and independent review. Any missing code or disposable-lab test stays **#48**. Only authorized physical site identity/PKI/HSM/backup restore and operational drills transfer to **#36**. Preserve Windows DPAPI defaults and existing L7/HA thresholds. Do not publish a release or declare production GO based on this matrix.
