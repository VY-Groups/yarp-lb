# GatewayCore — remaining software acceptance evidence ledger

Updated 2026-11-22. This is a reproducible **evidence collection specification**, not a claim that any gate passed. Use the issue bodies as canonical acceptance criteria. Record commit SHA, workflow run/job URLs, UTC timestamps, exact commands, pinned fixture hashes, measured output, PASS/FAIL and reviewer for every gate. A passing CI workflow is not physical acceptance.

## Preflight for every candidate

```bash
git fetch origin main
git rev-parse origin/main
git status --porcelain
dotnet --info
git diff --check origin/main...HEAD
```

Require clean checkout, supported .NET 10 SDK, and immutable candidate SHA. Inspect GitHub Actions **push** runs for the exact candidate main SHA using `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<SHA>&event=push&per_page=100`; paginate and inspect `GET /repos/VY-Groups/yarp-lb/actions/runs/<RUN_ID>/jobs?per_page=100`. This is separate from PR checks. Never count a cancelled, skipped or in-progress job as passed. If the API returns no runs, record **UNKNOWN**, not green. Record failed job step/log and fix in a focused PR.

## #34 — whole-gateway allocation and safety

Prerequisites: pinned before/after SHAs, identical .NET runtime, OS, hardware/runner, payload distribution, warmup, concurrency, logging, TLS, tracing and backends. Run at least three **paired** baseline/candidate trials per OS; retain raw per-window observations, not just averages. Capture `dotnet-trace collect --process-id <PID> --providers Microsoft-Windows-DotNETRuntime:0x1C000080018:5` on disposable processes, alongside `dotnet-counters monitor --process-id <PID> System.Runtime`. Capture request counts, allocated B/request, Gen0/1/2, pause, RSS/working set, CPU, p50/p95/p99, throughput and errors. Analyze allocation stacks for middleware, async continuations, YARP forwarder, metrics and transforms. Test streaming, CA signing POST with zero replay, source-IP affinity, TLS, health/panic and shutdown on Windows and Ubuntu. **PASS** only if statistically supported end-to-end improvement with no safety or latency regression under unchanged gates; isolated component savings do not satisfy the 8.6 KiB request-path gap. Publish raw data, scripts and uncertainty calculations.

## #48 — secure platform Data Protection lifecycle

Prerequisites: disposable Windows service and Ubuntu/RHEL service identities; dedicated non-CA wrapping certificate with correct KeyUsage; private key-ring and backup locations; never use production keys. On each supported OS: start service, authenticate, restart, rotate wrapping certificate with old key available, restore backed-up ring, verify cookie continuity and encryption-at-rest; then test revoked/missing/wrong key, modified XML, duplicate IDs, rollback to older inventory, symlink traversal and insufficient permissions. Record `dotnet --info`, `systemctl status <unit>` or `sc.exe query <service>`, process identity, file ACL/mode, redacted ring metadata and restart outcomes. **PASS** requires fail-closed tamper/rollback, no plaintext persistent fallback, no cross-instance session leakage, documented backup/restore/DR and Windows DPAPI compatibility. Mark RHEL unsupported explicitly if not tested.

## #50 — telemetry and alert pipeline

Prerequisites: pinned disposable Collector, Prometheus and Grafana images/configs, isolated network, no real customer data. Exercise HTTP/1.1, HTTP/2 and streaming requests through actual gateway process, then remove Collector, exhaust bounded exporter queue, restart Collector and gracefully shut down. Verify W3C propagation and safe route/backend labels; reject PII/secret headers, unbounded cardinality and request-path blocking. Check counts, duration histograms, active/passive ejection, queue drop/write-error, audit export, GC, cert expiry and failover alerts. Test idle, low-RPS 5xx, 502/503/504 and >0 high-priority log drops. Compare p95/p99, CPU, allocations and error rate with telemetry on/off on both Windows and Linux. **PASS** requires real containerized end-to-end dashboards/alert tests, accurate loss counters, bounded behavior during Collector failure and retained artifacts. Never claim live monitoring from disposable CI.

## #51 — WAF correctness, false positives and cost

Prerequisites: version-pinned policy/rules, scoped owner-approved allowlist with expiry and audit, rollback plan; private labeled benign/malicious fixture corpus with no secrets. Replay JSON, XML, Unicode, cookies, large uploads and CA/PKI payloads plus relevant XSS, SQLi, traversal and protocol-evasion cases against direct origin, detect-only and blocking mode. Preserve per-route TP/FP/TN/FN counts, severity and exact fixture hashes; verify detect-only forwards and audits, blocking denies, exceptions expire, and rollback restores prior behavior. Repeat direct/proxy/WAF at matched concurrency and response sizes, collect p95/p99, throughput, CPU, allocations, errors and blocking. Exercise Windows/Linux deployment and incident redaction. **PASS** only against preapproved FP/FN and unchanged performance thresholds with no uncontrolled bypass or unsafe retry; do not invent targets after results.

## #36 — consolidated external physical acceptance (never substitute for software tests)

Entry: independently reviewed and integrated software, exact-main push CI, frozen offline installer/rollback, SHA256 release manifest, no open development defects. On two independent physical gateways verify signed monotonic config parity, VRRP/ECMP and mTLS management isolation. Each node **alone** must sustain at least 750 Mbps response-body and 1.5× measured real peak RPS for **60 consecutive one-minute windows**, zero transport/HTTP errors, unchanged preapproved p99, NIC-drop and log-loss gates. Confirm 500 Mbps versus MB/s from primary switch/ISP evidence before calculating. Execute graceful/abrupt kill, blackhole, host/network partition, failback, key rotation and CA non-idempotent no-replay. Include public delegation/DNSSEC, IdP, CA/PKI/mail, live monitoring/alerts and CAB signoff where applicable. Record exact commands, topology (redacted), windowed raw measurements, timestamps, independent tester, approval and rollback. **FAIL/UNKNOWN** until every applicable external gate is signed off.

## Disposition discipline

Only #36 contains genuinely site-dependent proof. Missing reproducible lab tests, unsupported platforms, failed CI, incomplete UI/API behavior and unreviewed code remain development work. Never merge, approve, close issues, publish a release or deploy as a side effect of this ledger. Codex independently reviews feature PRs. Deferred #39/#61 remain outside v1.
