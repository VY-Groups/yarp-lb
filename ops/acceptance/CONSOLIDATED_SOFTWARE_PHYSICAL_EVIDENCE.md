# GatewayCore v1 consolidated acceptance evidence worksheet

Status: **unexecuted worksheet**, not a test result, release approval or replacement for canonical issue acceptance. Source of truth: each issue's original criteria and `AGENTS.md`. Use a disposable environment for software tests. Codex independently records physical tests in #36. Never publish credentials, topology, private payloads or private certificates.

## Evidence schema (one row per command and per failure injection)

| Field | Required value |
|---|---|
| Issue and requirement | Exact issue number, original criterion, software versus #36 site-only scope |
| Provenance | main SHA, PR head SHA, reviewed diff SHA, workflow run and job URLs, artifact SHA256 |
| Environment | OS/build, .NET version, component version, isolated test topology, redacted configuration digest |
| Execution | UTC timestamp, exact command, exit status, fixture hash, raw output/artifact location |
| Result | Expected and actual counts, latency distribution, failures, pass/fail decision |
| Accountability | Independent reviewer, finding disposition, retest SHA, physical tester and CAB signoff where applicable |

Never use a successful PR workflow to claim a successful exact-main push workflow. Query the Actions REST endpoint `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<MAIN_SHA>&event=push&per_page=100`, paginate, then `GET /repos/VY-Groups/yarp-lb/actions/runs/<RUN_ID>/jobs?per_page=100` and inspect each failed job's steps/logs. Store run IDs and job IDs. Do not infer an empty result means success.

## Software entry gate — execute before physical #36

1. Record `git rev-parse HEAD`, `git status --porcelain`, `dotnet --info`, and `git diff --check` from a clean pinned checkout. Expected: pinned SHA, clean tree, supported .NET 10 runtime, no whitespace errors.
2. Run `dotnet build engines/GslbDns/GslbDns.csproj -c Release` and `dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"` for #52/#109 on disposable Windows and Linux. Expected: exit 0, all actual assertions pass, no skipped security tests. Save both logs, not just summary.
3. For every remaining issue run its documented exact test project and actual disposable integration environment. Capture exact command, fixture and pass/fail. Missing documented command or fixture is a **software gap**, not a site dependency.
4. Verify approved, current PR heads, independent review, exact-head Windows/Linux CI, merged-main push CI and source-to-artifact traceability. A queued, cancelled or failed required check is **FAIL**, not pending approval.
5. Check offline install/upgrade/rollback on supported OSes with cryptographically verified package and manifest. Expected: reversible deployment, preserved auth/keys/routes, no plaintext secret fallback, no customer-server interaction.

## Issue-by-issue software and site evidence

| Issue | Software acceptance to prove before closure | Physical/environment-only acceptance retained in #36 |
|---|---|---|
| #34 | Three or more pinned paired before/after allocation profiles, ETW/dotnet-trace stacks, request counts and uncertainty, Gen0/1/2, pause/WS, p95/p99 and throughput; streaming, non-retry POST, affinity, TLS and health regression on Windows/Linux | Representative host CPU/GC/WS and traffic mix |
| #35 | Offline CA/PKI/OCSP/CRL integration fixtures, fail-closed certificate validation, rotation/rollback and security negative cases | Authorized enterprise CA/HSM, live OCSP/CRL |
| #37 | Deterministic HTTP-01/DNS-01 challenge, TXT publication/cleanup, idempotent retry/orphan recovery, protected credentials, renew/rollback, multi-node and CA staging-compatible disposable protocol tests | Authorized domain and staging/approved CA live order |
| #38 | All administrative mutations audited before commit with collector-independent durability, signed receipts, retention/recovery, federated logout and distributed session revocation, identity negative tests | Real IdP, retention/WORM and independent collector |
| #48 | Windows DPAPI and encrypted Linux keys; no-follow permissions, rotation, backup/restore, anti-rollback, tamper/lost-key, cross-node session continuity and Windows/Ubuntu/RHEL service tests | Real OS service accounts, restore/DR drill |
| #49 | Signed GitOps reconcile, scoped grants, Kubernetes/Terraform provider conformance, conflict/rollback and unauthorized change negatives | Real Git/registry and cluster permissions |
| #50 | Collector/Grafana container CI, bounded exporter backpressure and loss counters, redacted traces, HTTP/2, metrics/alerts, overhead and Windows/Linux tests | Site retention, alert delivery and live dashboard |
| #51 | Pinned rule corpus and versions, benign/malicious FP/FN by route, shadow/block/rollback, approved scoped exceptions, matched direct/proxy/WAF load and Windows/Linux CI | Representative site traffic, approved FP/FN limits and deployment |
| #52 | DNS authoritative UDP/TCP, DNSSEC NSEC/NSEC3 and serial/key rollover, negative/cut/glue/EDNS/ECS, multi-authority convergence and partition/replay tests | Authorized public delegation, DS, resolvers and GeoIP licensing |
| #53 | Real-socket TCP/UDP resource ceilings, stop/drain/restart, packet loss/reorder and no replay, Windows/Linux acceptance | Physical WAN and soak |
| #100 | Per-destination bounded queue limits, overload fairness, cancellation, retries disabled for unsafe POST, load and recovery tests | Actual multi-backend one-hour load |
| #101 | Authenticated peer registry sync, restart/replay/partition fencing, bounded stale state and deterministic conflict resolution | Independent physical peer partition/recovery |
| #109 | mTLS signing chain and revocation, clock skew, signed monotonic health authority, quorum, replay/partition fencing, observer failure, RBAC/UI and DNS convergence in disposable integration | Independent vantage hosts, live partitions and DNS convergence |

Also review any **new open development issues** and their original criteria; this table is not permission to omit them. #39 and #61 are deferred post-v1 unless separately authorized.

## Physical #36 — independent run order and pass/fail

Prerequisites: verified frozen software artifact SHA256, signed monotonic configuration on both separate hosts, approved topology and firewall/mTLS segmentation, measured real peak **in Mbps versus MB/s**, peak RPS from switch/ISP and request telemetry, CAB-approved strict p99 threshold and workload mix. Do not use two containers on one runner as independent hosts.

1. Validate two separate hosts, identical signed config revision/digest and protected management/data/metrics listeners. Expected: mismatched or rolled-back config rejected; untrusted management mTLS rejected.
2. Record `sha256sum <artifact>` (PowerShell: `Get-FileHash <artifact> -Algorithm SHA256`) and `date -u` (PowerShell: `Get-Date -AsUTC`). Attach manifest, redacted topology and source commit. Expected: digest exactly equals signed release manifest.
3. For **each gateway alone**, run the pinned traffic generator profile for **60 consecutive one-minute windows** at **>=750 Mbps response-body and >=1.5 times measured peak RPS**, assuming the confirmed peak is 500 Mbps and approved headroom is 50%. Calculate Mbps as `8 * response_body_bytes / elapsed_seconds / 1e6`; report both RPS and body Mbps per minute. Expected: every window meets both throughput floors, **zero HTTP and transport errors**, p99 within the *preapproved unchanged* limit, no unacceptable NIC drops, GC/logging loss or resource exhaustion. An aggregate hourly average cannot pass a failing minute. Never substitute network link speed for response-body throughput.
4. Repeat graceful drain, hard kill, VIP/ECMP convergence, blackhole, host loss, network partition, signed config divergence, rolling upgrade, certificate rotation and failback with real fault timestamps. Record absolute failed requests, first/last failure, p95/p99, and exact recovery interval. Do not treat CI's 1.5-second kill timer as the physical VRRP SLA.
5. Verify live Prometheus/blackbox alert delivery for gateway loss, 5xx, p99, unhealthy destinations, certificate expiry and warning/error log loss; retain alert receipts and operator acknowledgment. Verify no unsafe transaction replay and CA signing behavior.
6. Record actual public DNS delegation/DS/resolver behavior, enterprise CA/PKI/IdP/mail delivery and site monitoring, only in authorized environments. Record CAB decision and independent signatures.

**PASS** requires every original applicable software criterion, all required exact-head/main checks, independent review, complete physical observations and approved CAB signoff. Any failed minute, missing proof, unreviewed change, failed CI or untested recovery is **NO-GO**. Record remediation and rerun; never silently lower gates.

## Handover ledger template

| Issue | Open/closed as verified | Implementation PR/SHA | Exact-head CI jobs | Software PASS/FAIL | Site #36 evidence | Reviewer |
|---|---|---|---|---|---|---|
| #36 | OPEN until physical acceptance | — | — | Entry gate pending | NOT RUN | Pending |

Populate from live GitHub and real execution, not historical summaries. Keep the original issue open for incomplete code or disposable tests; reserve #36 only for genuinely environment-dependent proof.
