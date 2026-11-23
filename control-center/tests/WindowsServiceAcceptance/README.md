# Disposable Windows Service/DPAPI acceptance (#48)

This directory contains a **real SCM process** acceptance check for
Windows Server 2022 GitHub-hosted runners, not a production installer.

The test fails before modifying anything unless it is running as a
local administrator with GITHUB_ACTIONS=true, RUNNER_OS=Windows, and a
runner temp directory. It refuses a pre-existing GatewayCoreYarp service
or ProgramData state. It publishes the real .NET 10 GatewayCoreYarp
executable, creates a loopback-only disposable appsettings file with no
upstream routes, installs a manual SCM service named GatewayCoreYarp under
LocalSystem, and starts the actual application.

The acceptance asserts:
- SCM starts the shipping executable, and /gateway/health returns HTTP 200
  on loopback.
- The ControlPlane directory created by the service has a protected
  non-inheriting Windows ACL.
- A disposable administrator can bootstrap, obtain an authenticated cookie
  and request an authenticated session.
- Persisted Data Protection XML has an encryptedSecret wrapper and does
  not contain a raw masterKey element.
- After **stopping and restarting the real SCM service**, the original
  client cookie still authenticates as the same test administrator.
- The service and disposable files are deleted in a finally block,
  including on assertion failure; no real host state is modified.

The script intentionally uses the Windows LocalSystem identity as the
existing ACL/DPAPI LocalMachine baseline. It does NOT prove a customer
nonadministrator account, an existing neutral-state migration, true
cross-machine DPAPI decryption, unattended reboot/recovery, production
Windows event logging, external IdP, real TLS identity, or RHEL/Ubuntu
fleet key distribution. Production service installation remains a
separately reviewed operational workflow.

Run via the dedicated
.github/workflows/windows-scm-acceptance.yml workflow. Never invoke the
test script manually on a real server or move its disposable credentials
into production. Its CI PASS alone does not complete #48, and the real
two-host production acceptance remains in #36.
