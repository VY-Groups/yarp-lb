# GatewayCore — remaining software and physical acceptance evidence matrix

This is a **reproducible evidence collection template**, not a claim that any gate passed. Refresh `git rev-parse HEAD`, the canonical issue bodies, exact-head Actions runs, and independent review before using it. Record UTC timestamps, SHA, OS, commands, exit codes, raw artifacts and reviewer in the final evidence ledger. Do not commit secrets or customer traffic. A green component test cannot replace a failed whole-gateway test.

## Entry / source provenance

```sh
git fetch origin main
git rev-parse origin/main
git status --short
dotnet --info
git diff --check
```

Expected: clean checkout and recorded immutable SHA, supported .NET 10 SDK/runtime. **FAIL** on uncommitted changes, unknown SHA or incompatible runtime. For each PR, independently verify required Windows/Linux exact-head checks, including each failed job and logs; do not infer post-merge push CI from PR-only runs. The GitHub Actions REST endpoint is `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<main-sha>&event=push&per_page=100`; fetch each run's `/jobs` and failed job logs. Preserve run/job URLs and distinguish cancellation, infrastructure, test and compile failures.

## #34 — whole-proxy allocations

Prerequisites: same source SHA, runtime, CPU governor, response-size mix, TLS mode, backend, request count, concurrency and warm-up on both sides of a paired comparison. Run the repository's Issue 34 paired-allocation workflow and capture its raw artifacts, then repeat the *whole forwarding path* on supported Windows and Ubuntu, not only an isolated trace/privacy function. Record `dotnet-counters` GC allocation rate, bytes/request, p50/p95/p99, errors, RPS, CPU and GC collections. Calculate paired deltas and confidence intervals, preserve per-run samples and compare against the canonical remaining ~8.6 KiB/request target. **PASS:** demonstrable improvement without regression to p99, error, privacy, retries or throughput thresholds; otherwise **FAIL**. Do not equate a small isolated allocation delta with full issue closure.

## #48 — key protection, continuity and disaster recovery

Prerequisites: disposable Windows Server and Ubuntu/RHEL service identities; distinct dedicated Linux wrapping certificate with keyEncipherment, CA=false, owner-only permissions; encrypted key-ring backup; disposable sessions; no real secrets. Start services, issue an auth cookie, restart and verify continuity. Rotate wrapper and keys, restart both fleet members, restore a verified older backup in an isolated environment, then exercise replay/rollback, duplicate GUID, malformed XML, symlink, wrong key, revoked key, disk-full and unauthorized-user negatives. Inspect persisted XML for encryption, and verify no plaintext fallback. Record service logs, redacted configuration, OS permission listing, encrypted inventory hashes and cookie validity across the permitted rotation window. **PASS:** approved sessions survive normal rotation and controlled recovery, while tampering, rollback and missing protection fail closed with actionable diagnostics. Windows DPAPI remains default. Real site restore remains #36, but missing disposable recovery tests remain #48.

## #50 — observability end-to-end

Prerequisites: disposable gateway, backend, OTLP Collector, Prometheus and Grafana; pinned configuration and dashboard versions. Exercise HTTP/1.1, HTTP/2, success, 502/503/504, slow backend, ejection, recovery, queue saturation, rollout, certificate warning, audit exporter outage and collector outage/restart. Capture trace IDs end-to-end and verify redacted route/backend dimensions and cardinality budget. Confirm all required counters, histogram buckets, alerts, high-priority log drops and dashboard panels against observed requests. Compare direct/proxy/telemetry-on/telemetry-off p50/p95/p99, CPU, allocation and RPS. During collector loss traffic must not block; drop/error counters must reflect actual loss and shutdown must drain within bounds. **PASS:** real container integration and Windows/Linux parity, no private-data leaks or silent loss, accurate quiet/idle 5xx alert fractions and no performance gate regression. Live monitoring/delivery belongs to #36.

## #51 — WAF policy, correctness and load

Prerequisites: pinned rule set, private synthetic benign/malicious labeled corpus, explicit route policy, owned scoped exceptions with expiry, no external customer payloads. Replay JSON, XML, uploads, cookies, Unicode/protocol evasions and CA-sensitive payloads in shadow and block modes through real local origins. For each route record TP/FP/TN/FN, category/severity, rule ID, HTTP method, exact origin response, false-positive exception and audit evidence. Verify rollback, expiry, tampered corpus rejection, no redirects, no broad bypass, non-idempotent POST non-replay and real origin contract (not a spoofable marker). Repeat direct-vs-proxy-vs-WAF matched-load profiles; capture p95/p99, RPS, CPU, allocations, rejection and high-priority audit drops. **PASS:** agreed predeclared FP/FN thresholds, no uncontrolled bypass, real Windows/Linux acceptance and unchanged latency/security gates. Representative site traffic and approval remain #36, not a substitute for disposable tests.

## #36 — single consolidated physical acceptance (Codex / independent site tester)

Entry: zero outstanding development acceptance, independently reviewed merged code, clean exact-main push CI, frozen artifact and SHA256, offline install/upgrade/rollback evidence, CAB-approved topology and redacted configs. Do not run production tests from this document. Independent tester records two physical hosts, signed revision parity, management/data isolation, VRRP/ECMP failover, partitions, no CA transaction replay, certificate rollover, real DNS/PKI/IdP/mail and alerts. Verify peak units from network telemetry. If approved peak is **500 Mbps**, test **each gateway alone** for **60 consecutive one-minute windows**, each >= **750 Mbps response-body** and >= **1.5x measured peak RPS**, with **zero errors**, unchanged preapproved p99, log-drop, NIC-drop and GC gates. Record actual fault loss window and absolute failures rather than substituting CI timers. **FAIL** if any window misses a gate. Production remains **NO-GO** until independent evidence and CAB signoff.

## Evidence record per issue

| Field | Required |
| --- | --- |
| Issue / PR / reviewer | Canonical issue URL, exact reviewed PR SHA, genuine independent review URL |
| Build | Main SHA, artifact SHA256, OS/runtime, configuration digest |
| Test | Exact command, fixture version, environment, UTC start/end, exit code |
| Result | Expected and actual numeric outputs, raw logs/artifact URLs, PASS/FAIL |
| Negative tests | Failure mode, fail-closed observation, recovery and retest |
| Remaining work | Software defect stays in its development issue; only actual site/environment evidence belongs to #36 |

Do not close any issue on this checklist alone. This document is a template for recording evidence, not evidence itself.
