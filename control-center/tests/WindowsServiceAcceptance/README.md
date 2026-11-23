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

## Restricted built-in Windows LocalService SCM coverage

The same test now accepts one explicit opt-in argument,
`-Identity LocalService`, used by an **independent Windows Server 2022
GitHub-hosted CI job**. This does not create a local user, set a service
password or place credential material in the workflow logs.

Only on a clean disposable GitHub runner, an elevated test process first
creates the otherwise nonexistent `%ProgramData%\GatewayCoreYarp` root
with inheritance disabled and **read/execute-only** allow rights for
LocalService, while SYSTEM and Administrators retain full control. A
separate protected `ControlPlane` directory grants the service its required
write rights for keys, session state and audit; the service is expressly
refused any write/delete/ACL-owner rights over its **published executable**
directory. It stages the application executable under that restricted
directory, registers
a manual SCM service running `NT AUTHORITY\LocalService` (not
LocalSystem), verifies its observed SCM identity and startup, and checks
the same protected state ACL, encrypted key XML and original cookie
continuity across a real SCM stop/restart. It removes the test service
and state in `finally`. Preexisting product state/service or non-CI
execution is refused before any modification.

This supplements the original LocalSystem SCM integration; both
acceptance jobs must remain green. A PASS establishes that the actual
gateway can run under a built-in low-privilege Windows service identity
with this **pre-provisioned isolated ACL**. It does not prove arbitrary
domain-managed account access, machine-certificate private-key ACLs,
Active Directory/LDAPS, production Windows reboot, encrypted key-ring
migration from a live instance, or physical two-host DR. Customer
service identities still need explicit certificate, firewall, state
and event-log permissions plus site acceptance in #36.

The built-in LocalService SID is shared by other local services.
This test demonstrates reduced privileges relative to LocalSystem, but
**does not establish isolation from a different service using that SID**.
Customer deployments should prefer a dedicated service SID or approved
managed identity with narrower state ACLs and independently verified
private-key permissions; those remain unqualified here.

The `-Identity LocalService` setting is a **test fixture**, not an
installer option. Do not run this verification against real
`%ProgramData%\GatewayCoreYarp` state; it deliberately refuses any
existing directory or service name.
