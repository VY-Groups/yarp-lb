# GatewayCore — Codex operating instructions

**Read [CODEX_HANDOFF.md](CODEX_HANDOFF.md) before changing source.** That document contains the verified 2026-11-16 project snapshot, all then-current branches, PR history, open issues, exact source links, test commands and release blockers. Refresh live GitHub state; it is not a continuously updated status feed.

## Owner direction — licensing phase (2026-11-21)

- GatewayCore is intended as a **proprietary, owner-controlled product**, not an open-source product offering. Do not describe the entire repository as currently AGPL licensed simply because historical revisions were.
- Do **not** implement a license server, activation gate, tiering, subscription enforcement or commercial pricing now; defer that phase until the remaining software issues are completed.
- The owner explicitly confirms **OpenGSLB was a technical reference only**; the separate C# NSEC3 implementation follows RFC 5155. **Do not describe GatewayCore code as originating from the reference project** without verified provenance evidence. The current checkout has no root `LICENSE`; older Git revisions and existing C# SPDX/copyright markings make licensing status a **review item**, not a finding. See `THIRD_PARTY_NOTICES.md`.
- Preserve legacy source annotations and Git history while an independent provenance/licensing assessment is pending. Do not infer licensing obligations from matching an RFC algorithm, silently change source legal markers, or claim closed-source release clearance without review. Continue software development without adding a customer licensing module yet.
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
- `gslb` is an **OpenGSLB Go AGPL-3.0-or-later / commercial-license reference**. `ha-praxy` is a **GPL HAProxy C reference**. Do not import/copy modules into GatewayCore without appropriate licensing/legal approval. Study externally observable requirements and implement independent .NET behavior and tests.
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
