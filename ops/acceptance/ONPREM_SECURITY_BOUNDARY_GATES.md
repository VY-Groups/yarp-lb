# GatewayCore v1 on-prem security-boundary acceptance — NOT RUN

This is a **physical test plan**, not evidence of tests conducted, and not
permission to access any production system. Execute only in an authorized
staging window and record results offline before the owner approves
production. Keep secrets, private IP topology, customer data and captured
requests outside GitHub.

## Scope and source of the threat model

This test plan applies the fail-closed, protected signing-state,
immediate-peer proxy trust, private management transport and distributed
fencing lessons documented by the
[GatewayCore GSLB branch engineering review](../../control-center/docs/GSLB_BRANCH_DEEP_REVIEW.md).
That document is a **static review** of an unrelated, removed runtime, not a
tested GatewayCore implementation or code source. The GatewayCore .NET
implementation must be verified on its own merit. Optional DNS/GSLB and
external WAF are **not** automatically part of v1 L7 production acceptance.

## Prerequisites (STOP if any are missing)

1. The exact GitHub release/head SHA, signed configuration revision, signer
   identity and approved rollback floor are frozen and equal across the two
   separately hosted gateways. Preserve the signed manifest/digest offline.
2. Management-only addresses, data listener addresses, firewall segmentation,
   protected backend/origin addresses, and the **actual immediate ingress
   proxy CIDRs** are approved by the site security team. No management
   endpoint or unprotected origin may be reachable from a user traffic zone.
3. The authorized tester has trusted CA certificates, short-lived mTLS
   identity, a controlled staging hostname, fixed harmless attack fixtures,
   and independent external vantage points. Do not use `curl -k` to claim
   valid TLS; do not import test credentials into repository artifacts.
4. Windows: record service identity, protected ProgramData/key-ring ACLs and
   host-bound DPAPI backup/recovery method. Linux: record systemd identity,
   protected PFX/key-ring/checkpoint permissions, externally held verifier,
   signed inventory and **minimum trusted revision**. A recovery verifier or
   manifest must not be supplied by the same restored snapshot, including
   symbolic-link or hardlink aliases.
5. Record physical measured peak *unit* (Mbps vs MB/s), peak RPS, approved p99
   and headroom. These security checks are **additional** to #36's unchanged
   60-minute per-node >=750 Mbps body-byte / 1.5x RPS gate if the actual
   measured peak is 500 Mbps and 50% headroom is approved.

## Gate matrix — run on each independent gateway and from outside each trust zone

| Gate | Controlled test | Required result | Evidence to retain privately |
| --- | --- | --- | --- |
| Management transport | Connect from untrusted traffic network to each management/API/metrics listener; repeat without mTLS and with an untrusted certificate | No usable protected API response; no unauthorized mutation; correct mTLS/CA/source rejection | Timestamp, TLS handshake result, HTTP status if any, firewall rule/counters, identity-free audit correlation |
| Proxy identity | Send otherwise identical staging requests from an **untrusted immediate peer** with forged `X-Forwarded-For`, `X-Real-IP`, `Forwarded`; repeat through one explicitly configured **trusted** proxy | Untrusted peer cannot acquire trusted-source permissions; approved peer is accepted only with strict bounded address parsing; multi-hop/untrusted chains cannot bypass RBAC or network ACL | Actual socket peer, trust config hash, route and authorization decision (no raw addresses in GitHub) |
| Protected origin/WAF | With explicitly enabled external WAF, send approved synthetic XSS/SQLi/traversal fixtures through staging WAF with and without forged headers; try only approved firewall reachability tests directly to origin | Blocking remains active and an untrusted network cannot bypass the WAF to origin; exact scope/expiry on any PKIX exception; no broad allow rule | WAF rule/version/digest, 403/other status, redacted CRS rule category, allow/deny firewall evidence |
| Signed configuration | Deliberately propose an older signed revision, same-revision different digest and mismatched signer on **isolated staging**; sever coordination during test | Mutations refused until both gateways agree on approved monotonic revision, signer and digest; no silent rollback or split-brain control-plane writes | SHA256, revision, signatures verified, 2-node state transitions, fail-closed audit |
| Key-ring recovery | Restore a **disposable** encrypted-key backup on a designated isolated node; test wrong wrapper, unsigned/stale inventory, removed independent recovery verifier, and conflicting checkpoint | Fail closed before keys are imported; no plaintext fallback; no silent session loss or cross-host DPAPI migration | Redacted key-ring inventory digest, revision floor, exact negative-test results, successful old/new test-cookie decrypt |
| Telemetry and audit | Break collector transport and blocked console output on an isolated test node, restore it, and independently inject high-priority log-loss/writer-error alerts | Traffic path remains non-blocking; no secret leakage; loss counters and external alert delivery observed; independent audit outbox retains event continuity | p99/errors, queue/write/drop counters, alert receiver acknowledgement, audit chain IDs |
| Optional DNS authority | **Only if DNS/GSLB is in approved scope**: isolate an authority, expire observer quorum, force signer failure, run independent validating resolver tests incl. NXDOMAIN/wildcard/delegation | Stale authority answers fail closed, no private signing keys through management API, ECS accepted only from trusted resolver; DNSSEC proof validates | Signed report epochs/quorum, DNS packets and external validator outputs, serial and DS/rollover records |

A single false authorization, unauthorized origin bypass, plaintext key
fallback, unsigned DNSSEC response when signing is mandatory, stale config
mutation, or missing loss alert is a **FAIL**, not a waived requirement.
Distinguish `FAIL`, `PASS`, `NOT RUN`, and `NOT APPLICABLE`; the last
requires a written capability/scope decision, not a skipped test.

## Evidence and sign-off template (one entry per gate, node and fault)

Record **privately**: test ID, exact software SHA, signed config revision and
digest, node role, tester and second reviewer, approved date/window, allowed
scope, command/tool version, start/end UTC timestamps, preconditions, expected
and actual behavior, raw redacted logs/metrics location, absolute errors and
outage window, result, remediation commit and retest result. Preserve
independent operator approval, CAB/PKI signoff and site rollback authorization.

**Final release decision stays NO-GO** unless all applicable software gates
are merged and verified, then all #36 physical capacity, HA, security and
operational acceptance is independently signed off. This file alone never
satisfies a physical test and must not be cited as real host evidence.
