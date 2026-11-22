# GatewayCore v1 consolidated acceptance evidence manifest (template)

Status: **UNEXECUTED TEMPLATE — NOT PRODUCTION APPROVAL**. This file defines evidence required for an independent review and physical handover. It is not evidence that any test passed. Follow `AGENTS.md`, `CODEX_HANDOFF.md`, `ops/automation/ONPREM_RUN_ORDER.md`, and each canonical issue; the canonical acceptance criteria always prevail.

## Record format (one entry per issue and platform)

Record: issue number; requirement identifier and canonical URL; implementation PR and exact merged main SHA; executable command and fixture/config digest; OS/runtime/architecture; timestamp UTC; raw artifact path and SHA256; expected result; actual result; PASS/FAIL/NOT RUN; reviewer identity and review URL; remediation PR and retest; rollback procedure; environment-dependent remainder linked to #36. Never store secrets, private keys, customer payloads or identifying topology in GitHub. Never turn NOT RUN into PASS.

## Software entry gate (before physical testing)

For each *currently open* development issue, copy every acceptance criterion from the live issue into the ledger; do not use a historical issue count. Verify implementation and disposable integration tests on the exact merged main commit, relevant Windows and Linux workflows, independent review, installation/rollback documentation and negative security tests. Record `git rev-parse HEAD`, `git status --porcelain`, `dotnet --info`, workflow/job URLs and failed-step logs. Inspect **push** runs for the exact main SHA using `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<MAIN_SHA>&event=push&per_page=100`; PR-only workflow lookups do not establish main health. Include pagination and distinguish skipped/cancelled from success.

| Issue | Software evidence required before closure | Environment-only handover to #36 |
| --- | --- | --- |
| #34 | Three pinned paired before/after profiles with allocation stacks, uncertainty, GC, p95/p99, RPS, streaming/TLS/affinity and no-POST-retry characterization on Windows/Ubuntu | Site workload CPU/GC/WS/p99 and throughput |
| #35 | CA/PKI/OCSP/CRL/HSM capability and failure-mode tests, cert rotation and rollback | Authorized enterprise endpoints and hardware |
| #37 | HTTP-01/DNS-01 issuance/renewal/revoke negative cases, TSIG and cleanup, concurrent nodes, crash recovery, offline chain/rollback | Approved domain, CA staging, DNS delegation and issuance |
| #38 | Gateway-wide durable audit, signed receipts, retention and fail-closed mutation paths, IdP/session revocation and replay/restart acceptance | Real IdP, collector/WORM and mail delivery |
| #48 | Encrypted keyring, antirollback, rotation/restore, missing-key fail-closed and Windows/Ubuntu/RHEL service tests | Machine identity and restore/DR |
| #49 | GitOps/registry/Kubernetes reconciliation, permissions, idempotence, signed rollout and rollback | Authorized real Git/cluster |
| #50 | Collector/Grafana container E2E, loss/backpressure, privacy, cardinality, alert rules and overhead on Windows/Linux | Live monitoring and alert delivery |
| #51 | Pinned benign/malicious corpora, per-route FP/FN, shadow/block, expiry/rollback, direct/proxy/WAF matched load | Approved representative traffic and deployment |
| #52 | Authoritative UDP/TCP, DNSSEC/NSEC3/DS/serial/key rollover, delegation/GeoIP and resolver/partition regression | Authorized public DNS and cross-network resolver proof |
| #53 | L4 real-socket TCP/UDP reset/half-close/stop/load tests on Windows/Linux | WAN, packet loss, soak and host limits |
| #100 | Per-destination bounded queue overflow/fairness, timeout/cancel, health, no non-idempotent replay | Multi-backend live load |
| #101 | Peer registry replay/freshness, restart/partition/rollback and convergence tests | Independent peers/partition |
| #109 | Signed mTLS observers, authority quorum, replay/clock/partition fencing, RBAC/operator UI, DNS convergence | Independent physical vantage and authority nodes |

Issues #39 and #61 remain deferred; do not silently include them in v1. Closed issues require verification of their actual merged evidence, not merely a closed label. Any newly opened successor issue must be added before freeze.

## Physical #36 execution order and objective gates

**Prerequisites:** frozen software release SHA and SHA256-verified offline artifact; independent reviewer acceptance; signed configuration revision and digest on each host; separate hosts and management/data interfaces; approved CA/IdP/mail/DNS and CAB window; recorded real switch/ISP peak Mbps (not MB/s), peak RPS, request/response mix, concurrency, p99 limit and NIC capability. No production changes are authorized by this template.

1. Baseline backend and load generators, then identical reference and gateway scenarios. Collect exact config, generator commands, body-size weighted requests, errors, RPS, body throughput, p50/p95/p99, CPU, GC, memory, sockets and NIC drops. Stop if baseline is saturated.
2. Run each gateway **alone** for at least 3600 seconds with **60 complete consecutive one-minute windows**. For a verified 500 Mbps peak with 50% headroom, **every** window must reach at least **750 Mbps response-body** and **1.5 × measured peak RPS**, with **zero HTTP and transport errors**, p99 strictly below the preapproved cap and unchanged NIC/log-drop gates. Preserve the raw per-minute CSV, aggregate report, test scripts, generator/target host clocks and SHA256 hashes. No averaged-throughput substitution.
3. Verify signed configuration digest/revision equality and monotonic rollback rejection, then graceful drain, abrupt kill, VIP/ECMP migration, host loss, network partition, failback, rolling upgrade, cert rotation and no automatic replay of signing POSTs. Record absolute failed requests and last-failure time for each injection; do not reuse CI timing as a physical SLA.
4. Prove management mTLS/IP allowlist, data-plane isolation, real DNS/delegation/DS, IdP/PKI/mail and collector integrations. Inject gateway-down, 5xx, p99, unhealthy backend, certificate-expiry and high-priority log-loss alerts; record delivery receipt and acknowledgement.
5. Obtain independent tester signature and CAB signoff against the immutable evidence index. Any failure remains FAIL and reopens the relevant software ticket if caused by code. #36 stays open until all site gates pass.

## Commands for evidence capture (adapt paths, never include secrets)

```sh
git rev-parse HEAD
git status --porcelain
dotnet --info
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
sha256sum <release-artifact> <redacted-test-report>
```

Expected: clean source checkout, successful build and GSLB acceptance, reproducible artifact hashes. Any nonzero exit or missing output is **FAIL/NOT RUN**, never inferred success. Platform-specific test commands and capacity tools must be taken from the current checked-out runbooks and recorded verbatim. Do not upload unredacted site evidence.
