# GatewayCore v1 software and physical acceptance ledger

> Snapshot baseline: main `5c4efabd999efa9f58726725f2df77ab49a00b54` (2026-11-21). This is a **work-in-progress evidence contract**, not a claim of acceptance. Re-query live issues/PRs and exact-head Actions before every decision. Never close an issue solely from this ledger.

## Hard boundaries

* Scope: single-organization on-prem .NET 10/YARP. #39 and #61 remain deferred. #36 alone owns **physical/environment** evidence; all software defects, disposable lab integration and CI failures stay in their development issues.
* Never bypass protected branches, merge without actual independent review, reuse unlicensed AGPL/GPL modules, replay CA/signing POSTs, weaken security defaults, relax zero-error or p99 gates, or deploy to live servers.
* Software closure: merged SHA + independent review + all required exact-head Windows/Linux and domain CI + deterministic and disposable integration evidence + operator configuration, rollback and unsupported-mode documentation.
* Physical release: independently reviewed signed config, isolated management/data planes, dual independent hosts, enterprise PKI/IdP/mail, public DNS, monitoring/alert delivery and CAB approval. Production NO-GO until #36 passes.

## Live inventory at snapshot

Open development issues and PRs are a historical snapshot only; refresh the current state with the commands below. #36 alone owns physical acceptance; CodeQL analysis success does not mean all code-scanning alerts are resolved.

## Evidence collection — run for EVERY proposed software closure

Prerequisites: clean checkout at exact PR head, .NET 10 SDK, OS-specific prerequisites and disposable test fixtures. Do not run acceptance against production.

```bash
git fetch origin
git rev-parse HEAD
git status --porcelain
dotnet --info
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
# Obtain all push runs for the exact main SHA (NOT only PR-filtered workflows):
REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"  # Resolve owner/repo from the checked-out remote
gh api "repos/$REPO/actions/runs?head_sha=$(git rev-parse origin/main)&event=push&per_page=100" --jq '.workflow_runs[] | [.id,.name,.head_sha,.status,.conclusion,.html_url] | @tsv'
# For each returned run, fetch ALL job pages and failures:
gh api "repos/$REPO/actions/runs/RUN_ID/jobs?per_page=100" --paginate --jq '.jobs[] | [.id,.name,.status,.conclusion,.html_url] | @tsv'
gh api "repos/$REPO/pulls/PR_NUMBER/reviews?per_page=100"
```

Expected: clean checkout, successful build/acceptance, exact SHA match, no failing/cancelled/pending required checks, independently submitted approval for the reviewed diff, and no unaddressed security finding. Capture raw logs, OS, fixture versions, commit and artifact SHA256. If any required job is missing, skipped unexpectedly, failed or review is absent, mark **BLOCKED** and continue another independent software issue.

## Issue-by-issue reproducible gates

| Issue | Prerequisites and executable acceptance | Required output/evidence | Pass/fail |
|---|---|---|---|
| #52 authoritative DNS | Two isolated DNS authority processes and disposable signed zone; `dotnet build engines/GslbDns/GslbDns.csproj -c Release`; `dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"`; `dig @127.0.0.1 -p PORT ZONE SOA +norecurse`, `dig ... NS`, `dig ... A +dnssec`, `dig ... +tcp`; add delegation/referral, NXDOMAIN/NODATA, EDNS/truncation, rollover and divergent-authority tests. | SOA serial monotonicity, authoritative flags/referrals, signed negative responses, BIND/Knot/dnspython validation, replayable packet corpus, two-node convergence timing and load/chaos logs; licensed GeoIP fixture provenance. | Fail on wrong zone cut, stale signed answer, unsafe fallback, unbounded amplification or missing multi-authority software test. Public delegation/DS with real resolvers belongs to #36. |
| #109 health authority | Two isolated GSLB nodes and independent signed observer processes; run GSLB acceptance above plus real mTLS agent/authority harness. Inject replay, epoch rollback, revoked certificate, drift, delayed acknowledgements, split quorum and partition; verify authority state persisted across restart. | Signed fixture IDs, trust pins, monotonically ordered epochs, bounded queue/lease, explicit unknown and transaction-readiness priority, DNS SERVFAIL or safe target exclusion under lost quorum, recovery only after fresh evidence. | Fail if stale/replayed/quorum-minority evidence admits a CA-sensitive target. Physical network partitions and real CA readiness belong to #36. |
| #34 L7 allocations | Pin runner/SDK, request mix and concurrency. Capture 3+ paired baseline/optimized `dotnet-trace collect --process-id PID --providers Microsoft-Windows-DotNETRuntime:0x1C000080018:5` runs and matched direct/proxy traffic; exercise streaming, affinity, POST no-retry, TLS and panic. | Per-run allocations/request with uncertainty, GC0/1/2, pause, WS, CPU, p95/p99, throughput and allocation stacks. | Fail if improvement not measurable or any correctness/performance gate regresses. Physical hardware capacity belongs to #36. |
| #37 ACME | Disposable ACME CA and staging domain under explicit control; test HTTP-01/DNS-01 allowlists, protected account key, renewal jitter/backoff, concurrent old/new listener overlap, restart, revoke, expiry and rollback. | Fake-CA transcript, certificate serials, key permissions, challenge isolation, negative unauthorized requests, Windows/Linux jobs, offline manual-chain procedure. | Fail if key exposed, challenge open by default, renewal causes outage, or rollback fails. Live public CA/domain belongs to #36. |
| #38 identity/audit | Disposable OIDC IdP/JWKS and independent HTTPS audit collector; test PKCE, issuer/audience/nonce, ACR/AMR, RP logout, replica revocation, break-glass, durable external receipts and mandatory mutation fail-closed during collector outage. | Correlated actor/action receipts for ALL admin/security mutations, tamper/reorder/deletion/replay/disk-full tests, multi-replica session rejection, privacy/retention, Windows/Linux CI. | Fail if unaudited privileged mutation succeeds, forged/downgraded MFA is accepted or revoked session remains active. Enterprise IdP/WORM/passkey acceptance belongs to #36. |
| #48 platform keys | Windows service and Linux systemd disposable instances with protected key rings. Test restart, rotation, lost wrapper, tamper, rollback, shared-fleet cookie continuity, backup/restore and Windows DPAPI scope. | File ACL/mode, encrypted-at-rest inspection, negative missing-key startup, authenticated restart evidence and OS support matrix. | Fail on plaintext persistent fallback, unsafe owner/mode, lost-session incompatibility or silent key rollback. Real enterprise KMS/HSM belongs to #36. |
| #49 GitOps/Kubernetes | Disposable Git signer, Terraform state backend and kind/Kubernetes cluster; schema validation, dry-run/diff, signed revision, apply/import/drift/destroy, GatewayClass/Gateway/HTTPRoute/TLSRoute supported-status and ReferenceGrant negative tests. | Plan/apply/destroy logs, CRD status conditions, conflict resolution, convergence/rollback, redacted state, Windows/Linux CI. | Fail on unauthorized cross-namespace reference, plaintext secret, untracked drift or falsely supported feature. Real customer cluster belongs to #36. |
| #51 WAF | Pin ruleset and labeled benign/attack fixtures (JSON, XML, CA payloads, Unicode, cookies, large upload). Run shadow and blocking policies with per-route expiring exceptions, then matched direct/proxy/WAF traffic. | Confusion matrices FP/FN by category/route, p95/p99, throughput, allocations, CPU, rollback/audit and privacy logs; Windows/Linux CI. | Fail on uncontrolled bypass, missing ground truth, unreviewed rule update, sensitive payload leakage or relaxed gate. Site WAF tuning belongs to #36. |
| #53 L4 | Disposable real TCP/UDP backends on Windows/Linux. Test fragmented stream, half-close, UDP affinity/expiry, backend refusal/loss, drain, SIGTERM, startup bind failure, bounded admission and non-replay of opaque transactions. | Exact-head socket logs and repeatable no-duplicate counts; explicit unsupported TLS/SNI/UDP semantics and configuration/rollback. | Fail on replay after forwarding, process leak, listener partial-start or missing OS test. Physical WAN/soak belongs to #36. |
| #100/#101 closure audit | Retrieve closed issue body/comments, merged PR and exact-head checks; rerun relevant per-backend admission, durable peer snapshot/delta, partition and recovery tests. | Issue-to-commit-to-test traceability with documented constraints. | Reopen a development issue if any original software requirement is still absent. |

## #36 consolidated physical run order (Codex/site team only)

1. **Entry:** frozen signed release manifest (artifact SHA256, SBOM, rollback), all development gates above green, independent reviewer evidence, CAB change window, two physically separate hosts, separate management mTLS IP and data VIP/ECMP.
2. **Identity/PKI:** disposable-to-enterprise transition approved; validate live IdP/MFA/logout, external WORM retention, CA/CRL/OCSP/HSM, ACME public delegation/DS and mail delivery with real operator acknowledgements. Preserve key custody.
3. **Topology:** verify both hosts' signed config SHA, signer, revision, rollback rejection and convergence. Record pre/post route, listener and firewall snapshots. Test graceful drain, kill, blackhole, host loss, partition, failback and rotation. Count absolute errors and outage milliseconds, not only percentages.
4. **Capacity:** confirm real peak from switch/ISP telemetry. If peak is **500 Mbps**, test **each node ALONE** at >= **750 Mbps response-body** AND >= **1.5x measured real peak RPS**, continuously **60 minutes per node**, with **zero errors** and unchanged per-minute p99, NIC drop and logging-loss gates. Run matching direct-backend reference; capture p50/p95/p99, throughput, CPU, RAM, GC, retransmits, queue depth, NIC errors and exact traffic mix. If observed peak differs, record evidence and recompute without silently lowering the accepted 1.5x rule.
5. **Observability:** independently confirm live alerts for gateway down, 5xx, p99, unhealthy destinations, cert expiry and audit/log drops; verify alert delivery, dashboard access, retention and recovery.
6. **Signoff:** record timestamps, environment, command output, raw artifacts and hashes, failures/remediation, independent security/ops reviewer and CAB approval. Any software defect reopens its development issue; no production GO on a partial pass.

## Chronological run ledger template

Append one entry per execution (including no-change runs): observation UTC/IST; baseline and final main SHA; every observed commit/file diff and PR head/merge/close; all exact-head workflow and job transitions with URLs and failure remediation; issue state changes; test command, exit code and artifacts; security alerts; release file SHA256; outstanding **software** work versus genuine **external** dependencies. Use **UNKNOWN** for unseen transitions, never infer continuous observation from two snapshots.
