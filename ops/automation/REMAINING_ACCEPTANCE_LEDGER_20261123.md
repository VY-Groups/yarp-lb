# GatewayCore remaining acceptance ledger — 2026-11-23

This ledger is a reproducible **unverified-gates** checklist, not a certification. The 2026-11-23 issue inventory identified open software issues #34, #48, #50 and #51, plus separate physical #36; it is a **historical snapshot**, not a claim of live issue state. **No hardcoded commit in a documentation template is authoritative for the current `main` branch.** At each acceptance attempt fetch `GET /repos/{owner}/{repo}/git/ref/heads/main`, record its full SHA and UTC observation in the immutable evidence manifest, verify required exact-head checks and reviewer approval, and re-read the ref immediately after collecting push-run/job evidence. A changed branch tip, missing required workflow, or any failed/unrun gate means NOT ACCEPTED. Refresh open issues and successors before release decisions. A merged PR alone never completes its parent issue.

## Evidence contract (applies to every issue)

For every acceptance attempt record UTC start/end, OS/runtime and commit SHA, disposable configuration digest, exact invocation, exit status, raw stdout/stderr or artifact URL, expected vs actual counts, independent reviewer, and explicit PASS/FAIL. Redact identities, keys, topology, user data and customer payloads. Record failures and retest links; never edit thresholds after seeing results. No live environment actions are authorized by this document. Before integrating, verify the PR's **exact head** required Windows/Linux and security jobs and independent Codex review; inspect push-triggered workflows for the **merged main SHA** separately through `GET /repos/{owner}/{repo}/actions/runs?head_sha=<MAIN_SHA>&event=push&per_page=100` (paginate), then `GET /repos/{owner}/{repo}/actions/runs/<RUN_ID>/jobs?per_page=100` and failed job logs. PR-filtered workflow summaries do not prove main health.

## #34 — gateway allocations and safety

Prerequisites: pinned before/after SHAs, same runner and .NET SDK, same direct-backend and gateway configuration, fixed payload/concurrency and no concurrent workload. Run three or more **paired** direct-vs-proxy profiles on each supported Windows and Ubuntu runner using the repository's issue-34 allocation workflow and capacity harness; capture its exact command from the workflow at the tested SHA. Independently collect `dotnet-trace collect --process-id <PID> --providers Microsoft-Windows-DotNETRuntime:0x1:4` for each representative process (adapt provider flags after checking the runtime tool version). Expected: raw allocation stacks, B/request with uncertainty, GC Gen0/1/2, pauses, RSS, throughput, p95/p99 and streaming/TLS/POST/affinity/health regression evidence. PASS only if measurable improvement, unchanged privacy/no-retry semantics and all preexisting gates; otherwise FAIL and retain #34.

## #48 — key protection, rotation and DR

Prerequisites: disposable Windows service identity and Ubuntu/RHEL test hosts, encrypted test key ring, dedicated wrapping certificate with required key usages, backup store and documented restore/rollback procedure. Run `dotnet test -c Release` for relevant Data Protection test projects identified in the tested tree; then start the actual service as the restricted OS identity, authenticate, restart, rotate wrapping material, restore an earlier backup and reauthenticate on each OS. Inject missing/invalid wrapper, altered XML, duplicate key IDs, symlinked state and rollback snapshots. Expected: no plaintext persistent master keys, fail-closed startup/recovery, no silent session loss on approved rotation, explicit anti-rollback and audit. PASS only with actual disposable cross-platform recovery evidence and reviewed operational matrix; do not classify missing DR implementation as a site-only test.

## #50 — telemetry and alerts

Prerequisites: disposable OTLP Collector + Prometheus/Grafana, pinned dashboards, isolated gateway and backend, TLS credentials. Run the repository's telemetry integration workflow on Windows and Linux; send HTTP/1.1, HTTP/2, success, timeout, ejection, queue overflow and denied admin requests. Stop the Collector while traffic continues and restart it. Expected: bounded nonblocking exporter, accurate dropped-record counters, W3C propagation, no credentials/PII in spans, stable route/cluster/backend labels, dashboards and alerts for 5xx, p99, log loss, failover and certificate expiry. PASS only if real containerized integration, negative exporter tests and matched overhead profile are retained; absence of live Grafana is separately physical #36.

## #51 — WAF correctness and load

Prerequisites: pinned ruleset and shadow/block policy, privately owned synthetic origin, versioned benign JSON/XML/CA payload and malicious CRS-category corpus with expected outcomes, no public target. Run `python -m unittest discover -s tests/WafCrs -p 'test_*.py'` and the repository's WAF Docker acceptance workflow. Then replay corpus in shadow and blocking modes with rollback, measuring per-route TP/FP/TN/FN and unexpected ERROR separately. Compare direct/proxy/WAF at identical concurrency, payload and TLS settings; capture p95/p99, CPU, allocation and throughput. Expected: no uncontrolled bypass, no sensitive payload in report, exact backend-response validation, expiry/ownership/audit of exceptions and effective rollback. PASS only against preapproved FP/FN and performance thresholds with Windows/Linux evidence. Customer corpus and production deployment remain physical #36; missing ruleset governance or lab tests remain #51.

## #36 — independent physical acceptance (Codex/site team)

**Entry gate:** all development issues fully accepted and integrated, frozen reviewed release artifact and SHA256, offline install/upgrade/rollback documentation, verified main push CI. Prerequisites: two independent hosts, approved VRRP/ECMP, signed monotonically versioned identical routing config, management mTLS isolation, real peak switch/ISP graph and RPS, authorized public DNS/DS/delegation, CA/PKI/IdP/mail credentials and CAB plan. Never put secrets in repository.

Confirm measured 500 **Mbps**, not MB/s. If the real peak is 500 Mbps and approved headroom 50%, test **each gateway alone** at >=750 Mbps response-body **and** >=1.5x measured peak RPS for **every one of 60 consecutive one-minute windows**, zero HTTP/transport errors, and unchanged preapproved p99/NIC-drop/GC/log-loss gates. Exercise graceful drain, abrupt kill, blackhole, VIP migration, split network, signed-config divergence/replay, cert rotation, DNS convergence, failback and rolling rollback. Collect timestamped per-minute raw generator, NIC, proxy, backend and monitor evidence, absolute failed requests, loss interval and alerts delivered to the real destination. Verify real CA signing POST never replays, real enterprise SSO/OTP recovery, audit retention, public DNS resolvers, monitoring and CAB signoff. FAIL on any missing gate; retain #36 open and production NO-GO.

## Canonical evidence index and physical handover details

This ledger is the proposed single living checklist; related draft-only worksheets
#419,
#420,
#421,
#422,
#423,
#424, and
#425 are reference
drafts, **not execution evidence**. Preserve their unique prerequisites here
before marking any as superseded; never merge multiple conflicting checklists.

For each acceptance row maintain: issue / test identifier; reviewer and
operator; approval and UTC start/end; exact merged source SHA and release
artifact hash; OS, runtime, service identity and sanitized topology; signed
configuration revision/digest; exact commands with versions and exit codes;
expected and observed results; raw log/metric/trace/packet artifact references
and SHA-256; explicit PASS / FAIL / BLOCKED; remediation and retest reference.
Keep confidential raw evidence in an access-controlled location, not public
GitHub. A missing artifact or unrun test must not count as PASS.

Physical execution under #36 is a separate **authorized operator** batch,
after the software entry gate, and must record these independently witnessed
subgates:

| Subgate | Evidence and fail-closed decision |
|---|---|
| Topology and isolation | Two physically independent power/network failure domains; health from each node; external unauthorized probes against management and metrics; accepted mTLS only from approved management IPs |
| Signed routing and rollback | Signed monotonic config revision, signer identity and digest on both nodes; invalid/stale/divergent revision and mutation fencing; signed receipts and rollback audit |
| Failover | Graceful drain, process kill, physical host loss, VIP/ECMP loss, link flap, blackhole, asymmetric partition, failback and upgrade; preserve absolute errors and first/last error timestamps for each independently repeated drill; no CA signing POST replay |
| Solo-node capacity | Verify actual peak **Mbps versus MB/s** and peak RPS with switch/ISP records before defining targets; for a proven 500 Mbps peak each *individual* surviving node must achieve >=750 Mbps **response-body** and >=1.5x measured peak RPS in **each of 60 consecutive one-minute windows**, zero errors, unchanged approved p99, NIC-drop, GC and log-loss gates |
| External integrations | Authorized public DNS delegation/DS and independent resolvers; test CA/OCSP/CRL/HSM; enterprise identity/OTP/mail; real Collector/Grafana alert delivery and retention; platform-specific restricted service start/restart, key restore and rollback |
| Release / CAB | Immutable release SHA, signed package/hash, offline installation and recovery, approval records, unredacted restricted evidence inventory and independent witness; any missing required result remains NO-GO |

CI process-kill timings do not establish physical VRRP/ECMP convergence.
Do not transfer missing deterministic software acceptance, unsupported
platform implementations or failed exact-head checks into #36.

## Scope and handoff

#39 and #61 remain deferred post-v1. No branch merges, issue closures, release publication, server changes or production GO are authorized by this checklist. This file records the currently open work without shifting incomplete software to physical testing. If later issue search shows additional open or reopened development tickets, add their original criteria before final handoff.
