# GatewayCore — Codex operating instructions

**Read [CODEX_HANDOFF.md](CODEX_HANDOFF.md) before changing source.** That document contains the verified 2026-11-16 project snapshot, all then-current branches, PR history, open issues, exact source links, test commands and release blockers. Refresh live GitHub state; it is not a continuously updated status feed.

## Owner direction — licensing phase (2026-11-21)

- GatewayCore is intended as a **proprietary, owner-controlled product**, not an open-source product offering. Do not describe the entire repository as currently AGPL licensed simply because historical revisions were.
- Do **not** implement a license server, activation gate, tiering, subscription enforcement or commercial pricing now; defer that phase until the remaining software issues are completed.
- GatewayCore's C# NSEC3 implementation follows RFC 5155. The current checkout has no root `LICENSE`; earlier repository revisions included project-wide AGPL terms, so review that history before making distribution claims. See `PROJECT_LICENSE_STATUS.md`.
- Keep code changes and independent reviews moving concurrently. Close individual software issues only with exact-head acceptance evidence; #36 remains the physical/operational release gate.

## Project and release boundary

- GatewayCore is a **single-organization, on-premises .NET 10 + YARP L7 gateway/control plane** with optional, separate experimental DNS/GSLB, L4 and WAF integrations. Preserve the existing application, UI workflows, authorization and compatibility.
- **Controlled development/test GO; production NO-GO.** CI, local simulations, cloud Actions VMs and example configs are not physical VRRP/ECMP/PKI/capacity acceptance. Never describe a feature as production-ready based solely on compiling or passing CI.
- Keep the data and management planes separated. Do not expose the lab DNS service to the Internet or auto-delegate production zones.
- Never auto-replay non-idempotent signing/transaction requests; YARP/HTTP failover does not imply database or CA state consistency.

## Source and branch policy

- Begin work on the latest `origin/main`; use a new focused `codex/<issue-or-feature>` branch and a reviewed PR. Do not force-push or bypass branch protections.
- At handoff, GSLB latency routing was on **draft PR #108**, not merged. Check current PR status and exact-head CI before making decisions.
- **Do not merge historical branches wholesale.** The original 73-branch audit is in `control-center/docs/BRANCH_73_HAPROXY_AUDIT.md`; the newer complete 88-branch inventory is in `CODEX_HANDOFF.md`. Old branch tips often diverge because of squash merges.
- Implement GatewayCore-specific .NET behavior against product requirements and applicable standards. Do not bulk-merge historical branches.
- Maintain neutral GatewayCore branding. Do not hardcode a customer, employer, or internal company name into source, UI, environment variables or deliverables.

## Engineering standard

1. Read actual implementation and call sites first. State baseline behavior, assumptions, desired difference and tests. Prefer the smallest complete change with callers, tests, docs and UI/status updates when applicable.
2. Default existing policies/settings to previous behavior. New GSLB/L7 policies are opt-in with bounded configuration and startup validation.
3. Preserve two-person approval, RBAC, CSRF, identity/session isolation and secure state backup. Never overwrite/migrate/delete old OS Data Protection key material, accounts or production routes without explicitly approved and tested migration/rollback.
4. No fake-green tests: never disable CI, hide skipped checks, reduce p99/throughput/latency criteria, or claim a run passed until the actual exact-head GitHub result is verified.
5. On GSLB changes run `dotnet build engines/GslbDns/GslbDns.csproj -c Release` and `dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"` in the repo root; confirm Windows and Linux GitHub Actions. Also run relevant control-center source, L7, security and load gates when applicable.
6. Never commit real email/passwords, OTPs, HSM keys, client data, secrets or private topology. CI uses disposable lab fixtures only; do not touch actual customer servers from GitHub-hosted runners.
7. Report each completed step with issue/PR number, exact git SHA, test results and *remaining* NO-GO evidence. Do not mark P0 #36/#52/#109 completed merely after a component acceptance test.

## Pending top-level work

- P0 #36: independent physical two-host signed-config gateway HA behind VRRP/ECMP, real fault and capacity drills.
- P0 #52: GSLB authoritative DNS correctness, delegation/DNSSEC/key/serial, public resolver interoperability and complete DNS qualification.
- P0 #109: mutually authenticated distributed health agent evidence, signed freshness/authority/quorum, partition fencing, secure state and cautious predictive-health signals.
- P1 #100/#101: HAProxy-style per-backend queues and bounded peer sync beyond telemetry; #48 secure Linux key recovery; #50 OpenTelemetry/Grafana. Other open issues are enumerated in the handoff.

## Physical performance and signoff

Verify the site's reported 500 **Mbps vs MB/s** from primary network evidence. If the real peak is 500 Mbps and approved headroom is 50%, each independent gateway **alone** must sustain at least **750 Mbps response-body** plus 1.5x measured peak RPS over its own full 60-minute run, zero errors and strict per-minute p99/NIC/logging gates. Follow `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md`, `ops/automation/ONPREM_RUN_ORDER.md` and `control-center/docs/ONPREM_PRODUCTION_GO_GATES.md`. Actual physical acceptance has **not** occurred.

Use `CODEX_HANDOFF.md` for additional detail. Update that handoff when a significant PR merges, issue closes, branch state changes or the real production release decision changes.


## Consolidated software/physical evidence protocol (2026-11-22 proposal)

For each open development issue (#34, #48, #50, #51 at this checkpoint), preserve the canonical issue's exact acceptance criteria. Record issue/criterion, source PR and reviewed head, merged SHA, Windows/Ubuntu exact-head run/job URLs, prerequisites, commands, expected/actual outputs, negative tests, artifact SHA-256, rollback and independent review. A green workflow does not close a criterion unless its actual assertions cover it. Closed issues #37/#38/#52/#100/#101/#109 may be reopened if verified source defects remain; do not silently transfer code gaps to #36.

For post-merge CI, query GitHub Actions REST `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<main-sha>&event=push&per_page=100` and paginate; inspect each run's `head_sha`, `event`, `status`, `conclusion`, and `GET /repos/VY-Groups/yarp-lb/actions/runs/<run-id>/jobs?per_page=100`. PR-filtered workflow runs do **not** prove push CI. Missing or failed required checks mean NOT ACCEPTED.

#34 requires at least three matched paired profiles, allocation stacks, bytes/request and uncertainty, GC/working set, p95/p99, throughput and protocol/safety characterization on Windows and Ubuntu. #48 requires encrypted Linux and Windows DPAPI restart, tamper, rotation, key recovery and fleet backup/DR. #50 requires real disposable Collector/Grafana, exporter outage/backpressure, bounded privacy/cardinality, metrics and alerts plus measured overhead. #51 requires pinned WAF rules, scoped expiry/audit, benign and malicious corpus, per-route FP/FN matrices, rollback and matched direct/proxy/WAF load. Do not mark these as user-side environment tasks while implementation or CI is missing.

For #36, freeze artifact hash and signed config revision first. Confirm measured peak Mbps versus MB/s and peak RPS from site evidence. If peak is 500 Mbps with approved 50% headroom, **each independent gateway alone** must sustain >=750 Mbps response-body and >=1.5x peak RPS in **each** of 60 consecutive one-minute windows, with zero HTTP/transport errors and unchanged preapproved p99/NIC/GC/logging gates. Save exact generator commands, per-minute raw results, failure injection commands/times, absolute error counts, loss intervals, no replay of non-idempotent POST, VIP/ECMP transitions, independent host evidence, public DNS/DS/serial/key rollover, enterprise CA/PKI/IdP/mail, alert delivery and CAB signoff. Missing evidence is NOT RUN, never PASS. Production remains NO-GO until every applicable gate passes.
