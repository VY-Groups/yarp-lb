# GatewayCore v1 — software-to-physical acceptance ledger (2026-11-21)

This is a **reproducible review checklist**, not an acceptance certificate. Snapshot base: `70d67a5f06bc3be92cd9ac4c8797d3d7cbb6bc45`. Refresh the GitHub issue list, PR heads, and main SHA before using it. Never mark a pending check PASS. Keep secrets, customer traffic and topology outside the repository. Codex independently reviews software PRs and performs the real-site phase; no author self-approval.

## Current canonical open issue inventory

At snapshot: **software #34, #48, #50, #51; physical #36**. The other historical issue numbers are not presumed open. #39 and #61 remain deferred. The open PRs are #384 (performance), #404/#409 (overlapping main-push evidence tools), and #408 (Linux DP signed-recovery policy). Review #404 against #409 before integrating either; never merge duplicate tooling blindly. A closed issue is not evidence that physical release gates passed.

| Issue | Software prerequisites and reproducible evidence | PASS / FAIL and remaining boundary |
|---|---|---|
| #34 | Record main/PR SHAs and pinned hardware/runtime/payload/concurrency. Collect three or more **paired** before/after runs; capture dotnet-trace/ETW allocation stacks, bytes/request, Gen0/1/2, pauses, working set, p95/p99, throughput and errors. Run streaming, signing POST no-retry, affinity, health/panic and TLS characterization on Windows and Ubuntu. | PASS only for a statistically supported whole-proxy improvement with unchanged correctness/safety and complete raw paired artifacts. Isolated helper allocation wins are insufficient. Representative-site hardware remains #36. |
| #48 | Validate Windows DPAPI scope and restart, Linux certificate/KMS-wrapped persisted ring, missing/invalid wrapper fail-closed, tamper/restart, backup, rotation, signed antirollback recovery and cookie compatibility. Test actual Windows/Ubuntu service startup and document RHEL support or NOT SUPPORTED. Review #408 enforcement inputs against independently protected service-manager policy. | PASS only with encrypted XML inspection, real disposable lifecycle and recovery evidence, secure permissions, platform matrix and reviewed exact-head checks. Live fleet/host DR remains #36; missing software fleet coordination stays #48. |
| #50 | Validate W3C propagation, privacy-safe route/backend tags, bounded exporter queue and loss counters, collector unavailable/restart, shutdown, HTTP/2 and sampled spans. Run containerized OTLP Collector/Grafana, inspect versioned dashboards and alert rules, compare matched before/after p50/p95/p99, allocations, throughput and 502/503/504 behavior on Windows/Ubuntu. | PASS only with raw collector/dashboards evidence, cardinality and retention budgets, verified fail-open telemetry without blocking traffic, and no private data. Real monitoring delivery/retention remains #36. |
| #51 | Pin CRS/policy version and threat model; test benign JSON/XML/uploads/CA payloads and malicious XSS/SQLi/LFI, Unicode/cookie/protocol evasion in both shadow and block. Record ground-truth per-route TP/FP/TN/FN, ownership/expiry of exceptions, rollback, redaction, Windows/Linux behavior and matched direct/proxy/WAF p95/p99/CPU/allocations. | PASS only against **preapproved** FP/FN and performance gates with no uncontrolled bypass and retained raw fixtures. Representative customer corpus, policy governance and deployed rollback remain #36. |
| #36 | Enter only after all development issues are independently reviewed and integrated, exact-head CI and frozen offline artifact/checksum are recorded. Prepare two independent physical gateways, approved signed configuration, management mTLS, VRRP/ECMP, traffic generator(s), switch/ISP peak evidence, site-approved CA/PKI/IdP/mail/DNS and monitoring/CAB owners. | PASS only on signed real-site evidence below. Do not substitute GitHub-hosted runners, cloud lab simulation, or a development issue closure. |

## Commands and immutable software evidence

From a clean repository checkout at the **exact SHA under review**, capture the command, exit code, timestamp, OS/runtime, logs and SHA-256 of artifacts. Commands are examples; run the issue-specific existing CI harnesses referenced in `AGENTS.md` and `CODEX_HANDOFF.md` as well.

```sh
git rev-parse HEAD
dotnet --info
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
```

For GitHub main-push evidence, use the REST API **with event=push and the exact full main SHA**; the PR-only workflow wrapper cannot prove main is green. List every run's jobs and failed steps, not just workflow conclusions:

```sh
curl -fsS -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
 "https://api.github.com/repos/VY-Groups/yarp-lb/actions/runs?event=push&head_sha=$MAIN_SHA&per_page=100"
curl -fsS -H "Authorization: Bearer $GH_TOKEN" -H "Accept: application/vnd.github+json" \
 "https://api.github.com/repos/VY-Groups/yarp-lb/actions/runs/$RUN_ID/jobs?per_page=100"
```

Paginate both endpoints when necessary. Fail the evidence gate on missing expected workflows, incomplete jobs, failure, cancellation or inaccessible logs. Review and select **one** of #404/#409 after independent testing rather than assuming either is merged. On snapshot main SHA, four push workflows were reported successful (branding, WAF, L7, CodeQL); that observation does not establish all possible workflows ran, nor does it prove a future main commit is green.

## #36 one-batch physical execution and evidence record

1. **Freeze and identify:** capture signed release commit, installer/offline package SHA-256, both machine identities, OS versions, runtime, config signer, monotonic revision and identical digest; record install, upgrade, rollback and signature rejection commands/results. Abort if either node differs.
2. **Separate management and data:** prove only 80/443 on approved data listener, allowlisted management mTLS/API/UI and management-only metrics; inspect host firewall and effective binding output. Abort on public admin/metrics exposure.
3. **Prove each node alone:** from switch/ISP evidence establish whether the reported peak is **500 Mbps or 500 MB/s** and measure peak RPS. For a confirmed 500 Mbps with approved 50% headroom, test **each gateway independently** at >=750 Mbps *response body* AND >=1.5x measured peak RPS in **every one of 60 consecutive one-minute windows**. Record request/response bytes, absolute HTTP/transport errors (must be zero), per-minute p99 against unchanged preapproved threshold, CPU, GC, working set, NIC drops, queue/log drops and generator saturation. A 60-minute average is not enough.
4. **Fault matrix:** record timestamps, absolute errors and recovery interval for graceful drain, abrupt kill, host loss, VIP failover/failback, blackhole, partition, stale/rollback config, cert rotation, rolling upgrade and backend readiness. Do not silently replay CA/signing POST. Verify divergence fences mutations.
5. **External acceptance:** authorized public DNS delegation/DS and resolver diversity, DNSSEC rollover, approved CA staging/renewal and OCSP/CRL/HSM, enterprise IdP/mail delivery, real OTLP/Prometheus/Grafana alerts and retention, WAF representative FP/FN, and independent network-vantage/health quorum. Record each external authority's explicit approval; never store credentials.
6. **CAB decision:** for every gate retain prerequisites, exact invocation/config reference, expected/actual, UTC time, raw artifact location/hash, PASS/FAIL, defect link, retest, independent reviewer and CAB signer. A FAIL keeps #36 open; software defects reopen their canonical development issue.

### Evidence record template

```text
Issue/gate:
Release SHA / artifact SHA256:
PR head / independent review:
Host OS/runtime/topology (redacted):
Prerequisites and approval:
Command/config revision:
UTC start/end:
Expected threshold:
Observed metrics/errors:
Raw logs/metrics location and SHA256:
PASS / FAIL / NOT RUN:
Defect, remediation and retest:
Independent tester / CAB signoff:
```

**Status at authorship:** No physical acceptance performed here. No production GO, release publication, issue closure or main-branch mutation is authorized by this ledger.
