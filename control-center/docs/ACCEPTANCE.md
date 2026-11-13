# 0.1 test plan — Windows Server 2022 lab

Stop an old YARP process before building. Run installer from elevated PowerShell only after reviewing it.

## Build

- Run `dotnet build --no-restore` on the Windows test host: **must succeed with 0 errors**.
- Start `dotnet run --no-build --no-launch-profile` and confirm `http://127.0.0.1:8080/gateway/health` returns 200.
- Log into `http://127.0.0.1:8080/dashboard` with a test administrator; check browser console for JavaScript or CSP violations.

## Onboarding

1. Initial login when no `onboarding-topology.json` exists must show **Architecture & setup**.
2. Choose **Standalone**. Confirm 1 gateway is required and a second destination is available for a shared application name. Save draft and reload; data must persist.
3. Choose **HA pair**. Confirm 2 gateway entries are required, agent origins must be HTTPS, and a VIP with health-aware upstream distribution is required.
4. Choose **Fleet**. Confirm 3 or more gateways are required. A `http://` agent origin must be rejected.
5. Introduce duplicate IDs; server validation must reject them.
6. Submit two saves with the same outdated revision; the second must return HTTP 409.
7. Confirm design with all fields valid; navigate to dashboard. Verify the design is shown but no gateway claims verified health.
8. Verify no changes to the SHA-256 checksum of `C:\YARP\SpeedSignYarp\appsettings.json` after onboarding.
9. Verify the audit event and topology backups under `%ProgramData%\SpeedSignYarp\ControlPlane`.
10. Sign in with an Operator or Viewer; attempts to POST onboarding configuration must return 403. Unauthenticated calls must return 401.
11. Choose Standalone, confirm, and verify POST fleet registration/rollout is blocked with 409. A HA design permits reaching the agent mTLS validation (not proof of agent enrollment).
12. Confirm that no administration endpoint is accessible from a remote machine; the current console is localhost-only.

## Live traffic go/no-go

A successful design review is *not* a go-live signal. HA frontend load balancing, SSO, mTLS agent enrollment, certificate-chain correctness, alerting, zone ACLs, OCSP/CRL semantics, Pgpool availability, rollback, and two-person approval still require independent verification. Do not put the management console on public interfaces.
