# GatewayCore #48 — Key continuity and recovery acceptance worksheet

Status: **NOT ACCEPTED**. This is an executable evidence protocol, not proof that any scenario passed. The canonical requirements remain in issue #48; site-only steps are recorded in issue #36. Keep production NO-GO until all applicable gates are independently accepted.

## Scope and invariant

Test Windows DPAPI default and explicitly configured Linux encrypted ASP.NET Data Protection key rings. Never silently substitute plaintext persistence, generate a new ring when the configured ring is inaccessible, or treat a successful process start as evidence of cookie continuity. A restored key ring must preserve pre-existing authentication cookies and authorization isolation; revoked sessions must remain revoked. A stale backup must not roll back the fleet to a prior accepted generation. Every failure must preserve the previous encrypted ring and produce a redacted actionable error.

Use **disposable** test identities, self-issued lab certificates, isolated storage and test-only cookies. Do not upload private keys, cookies, raw session tokens, customer data or machine identity secrets to GitHub.

## Reproducible source-level entry gates

From a clean checkout at the **exact candidate SHA**, with .NET 10 SDK installed:

```sh
git rev-parse HEAD
dotnet --info
dotnet build control-center/GatewayCoreYarp/GatewayCoreYarp.csproj -c Release
```

Expected: zero exit codes, recorded SDK/runtime versions and exact commit. Also run all existing dedicated Data Protection tests, Windows HA tests, Control Center API/browser tests, Linux real-start/systemd and RHEL-family UBI9 workflows at the same head; capture workflow/job URLs and artifact digests. A build alone does not pass any lifecycle test. If a path or test command changes, record the actual invocation from the checked-out CI workflow rather than silently substituting a smoke test.

## Disposable integration matrix

| ID | Setup / action | Expected observable result | Fail condition |
| --- | --- | --- | --- |
| DP-01 | Windows service identity, default DPAPI, encrypted persistent ring; create login cookie, restart service | Existing cookie remains valid; ring material remains protected by DPAPI; service ACL unchanged | New identity or unprotected key |
| DP-02 | Windows different service identity without authorized access | Startup/session decryption fails closed with redacted diagnostic | Automatic new ring or plaintext fallback |
| DP-03 | Ubuntu systemd with dedicated non-CA RSA key-wrap leaf and owner-only state; restart | Encrypted ring survives restart, old cookie works | Unencrypted XML or permissive directory |
| DP-04 | RHEL-family supported runtime/service with same policy | Same encrypted persistence and cookie continuity | Platform-specific silent downgrade |
| DP-05 | Remove wrapping certificate/private key before restart | Explicit failure without destroying prior ring | Key regeneration or destructive overwrite |
| DP-06 | Substitute CA certificate, missing keyEncipherment or invalid EKU/key usage | Configuration rejected before session serving | Certificate accepted |
| DP-07 | Symlink any Linux key/state ancestor, dangling leaf, or replace file during read | No-follow/ownership checks reject; old ring intact | Traversal or unauthorized read |
| DP-08 | Corrupt XML, duplicate key GUID, rename file to mismatch key ID | Fail closed with bounded diagnostic | Partial acceptance or key reset |
| DP-09 | Two disposable gateways share authorized encrypted ring; authenticate on A, validate on B; rotate key on A, roll B | Cross-node session continuity and compatible rotation | Cookie invalidation, cross-fleet leakage |
| DP-10 | Back up ring + protected wrapping material, restore to clean isolated node under authorized identity | Old pre-backup cookie works, revocation rules remain enforced | Restored ring decrypts but authorization regresses |
| DP-11 | Attempt older snapshot after newer committed generation | Anti-rollback policy rejects older generation | Stale snapshot becomes authoritative |
| DP-12 | Interrupted rotation/restore, process kill at every write boundary | Atomic recovery to prior or new complete generation, never partial XML | Truncated ring or loss of existing sessions |
| DP-13 | Separate tenants/fleets with distinct purpose/application discriminator | Cookies from other fleet rejected | Cross-fleet session acceptance |
| DP-14 | Revoke session on one node; restart and validate on other node | Revocation survives restart and propagates within approved bound | Previously revoked session accepted |

DP-09 through DP-14 require deterministic disposable **multi-process** integration tests, not only mocks. Missing test coverage is an unfinished development requirement in #48, not a #36 exception. Physical Windows Server, Ubuntu/RHEL service identity, backup media and operator DR drill evidence belong to #36 only after the software tests pass.

## Evidence capture and gate

For every row record: test ID, exact candidate SHA, OS image/build, .NET runtime, executable command, sanitized configuration fingerprint, test timestamp, exit code, relevant assertions, log/artifact URL and SHA256, expected versus actual, PASS/FAIL, and independent reviewer. Record any skipped row as **NOT TESTED**, never PASS. On failures preserve artifacts privately, create a focused fix PR and rerun the failed test plus the full affected regression matrix.

Required acceptance: all supported-platform rows PASS, unsupported combinations explicitly fail closed and are documented, exact-head Windows/Linux/RHEL relevant workflows PASS, no critical code-scanning findings, independent code/security review completed, offline installation/upgrade/rollback documented, and #48 requirements linked to evidence. Do not close #48 based solely on this worksheet. Never change established p99, zero-error, traffic or security thresholds to achieve a green result.

## Physical handover after software acceptance

At #36, independently validate real service accounts, DPAPI scope, host key-store permissions, encrypted backup custody, certificate rotation, loss-of-key recovery, signed configuration parity, and uninterrupted authenticated sessions across physical gateways. The production decision additionally requires **each node alone** to sustain at least 750 Mbps response-body and 1.5× measured peak RPS in every one-minute window of a full 60-minute run, zero errors and the preapproved unchanged p99/NIC/GC/logging gates. Capture redacted switch/ISP peak evidence first to confirm that 500 Mbps, not 500 MB/s, is the correct baseline. Keep the real-world signoff and CAB approval outside source CI.
