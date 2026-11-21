# GatewayCore — Codex handoff, verified repository snapshot

## Ownership/licensing direction (2026-11-21; current owner instruction)

The intended product is proprietary, owner-controlled and commercially licensed in a **later phase after software issues close**. No license activation/billing/tiering module is to be developed now. The root `LICENSE` file is absent at this snapshot, but prior revisions contained project-wide AGPL grants, and `engines/GslbDns/DnssecZoneSigner.cs` contains a separately attributed OpenGSLB **AGPL-derived** NSEC3 implementation. Keep exact upstream attribution and clear its distribution/network-service license compatibility before any commercial/closed-source release. Current source must not be described as fully license-cleared. Update `README.md`, `THIRD_PARTY_NOTICES.md` and `AGENTS.md` accordingly; historical text below remains historical evidence rather than a current licensing declaration.


## Continuation snapshot — security review and release status (2026-11-21)

This is the latest verified continuation state; older same-day snapshots below
are historical when their branch, issue, or CI state differs.

- `main` is `06f3d73c480b0e4da4150f0a0e39f3cffcb35eaa`, including PRs #321,
  #323–#332. PR #327's Windows/Linux account-key, ACME and ten-run HA checks,
  PR #328's CodeQL inventory and actionlint checks, PR #329's documentation
  checks, and PR #330's Windows/Linux DNS, L7, HA and CodeQL checks passed on
  their exact heads before merge. PR #332's Windows/Linux L4 socket acceptance,
  CodeQL, L7, HA, and load checks passed before merge. The post-merge workflows
  for this commit (audit collector, L7, and CodeQL) all passed.
- Ten issues remain open: #34, #36, #37, #38, #48, #49, #51, #52, #53, and
  #109. PR #331's updated head passed Windows/Linux collector acceptance, all
  CodeQL language analyses, and the full shared L7/HA/load matrix; it merged at
  this `main` commit. PR #333 is the only open PR, adding the explicit L4
  capability/configuration matrix required by #53; exact-head checks are in
  progress.
- PR #327 addresses account-key persistence only; it does not complete ACME
  issuance and zero-downtime renewal. #330 addresses authority publisher
  shutdown only; it does not close the broader #109 health-authority scope.
  #53 remains open until its explicit capability matrix PR (#333) is reviewed
  and its checks pass; physical host/soak acceptance is tracked in #36.
- The post-merge CodeQL run passed and the GitHub code-scanning API currently
  reports no open alerts. This does not replace a future scan after source
  changes. No findings are dismissed or suppressed.
- Latest release is `v0.1.0-test.12` (2026-11-14). A verified release with
  SHA-256 checksums, offline install, upgrade, and rollback evidence has not
  been published. Production remains **NO-GO**; annual 99.9% availability is
  unmeasured.


## Current continuation update — L4 acceptance and open security work (2026-11-20)

This section supersedes older “current state” statements below where they
conflict. Live GitHub was refreshed after PR #321 merged:

- `main` is `7f5afa9f7184987522f79eb959c5acba1a43b751` (squash merge of PR #321).
  At this snapshot there are **10 open issues**: #34, #36, #37, #38, #48, #49,
  #51, #52, #53 and #109. PR #321 is closed by merge; PRs #318–#320 and #322
  were closed as superseded. PRs #323 and #324 remain open.
- PR #321 adds L4 process-failure containment and real-socket acceptance for
  refused backend connects, all-drained TCP, no replay after TCP reset and UDP
  response loss, partial listener bind failure, and bounded Linux SIGTERM
  drain/cancellation. Exact-head Windows/Linux Actions passed; local Windows and
  Ubuntu WSL real-process acceptance also passed. Post-merge L4 Actions passed
  on this exact `main`; post-merge L7 and CodeQL were still running at update
  time.
- **#53 remains OPEN.** The Linux shutdown test does not cover Windows
  console/service stop; the required Windows graceful-stop test remains
  outstanding. Physical WAN/loss/soak/capacity acceptance is tracked only in
  #36. No L4 production certification is implied.
- PR #323 corrects stale DNS capability documentation about configured child
  referrals and opt-in routing. Its prior-head CI had one Windows authority
  HTTP timeout; rerun passed. The branch is being refreshed on current `main`
  and requires fresh exact-head checks before merge.
- PR #324 addresses selected CodeQL TLS/logging/response-splitting findings.
  It is still open and requires exact-head CI/review. CodeQL alerts #1–#6
  (disposable test-secret file writes) and #14 (pinned client-certificate
  authentication path) are not claimed fixed; review/remediation remains open.
- The latest listed release remains `v0.1.0-test.12` from 2026-11-14, not a
  verified current release. No new verified release with current artifacts,
  SHA-256 checksums, offline installation, upgrade and rollback evidence has
  been published. Production remains **NO-GO** and annual 99.9% availability is
  unmeasured. #36 remains the sole physical/environment acceptance tracker.

## Current continuation update — physical GSLB acceptance (2026-11-20)

This update supersedes the earlier same-date snapshot below for physical
acceptance. The live main ref is 47fbc0403d9bde5f7bcff62b1f55fd7730469623,
including merged PR #285. The six post-merge workflows reported for that exact
main commit passed. The live open issue list is #34, #36, #37, #48, #49, #51,
#52, #53, #100, #101 and #109.

- Two physical EC2 acceptance phases ran against GatewayCore binaries built
  from this main commit. The observer-quorum phase used two DNS authorities in
  Mumbai and Osaka plus three separately enrolled signed mTLS observers on
  three Amazon Linux 2023 hosts, assigned three configured vantage groups.
  Actual geographic and network-path diversity was not independently verified.
- In the observer phase, both authorities returned authoritative NOERROR/A
  over UDP and TCP with three fresh reports. One expired observer was
  tolerated; after a second distinct configured group expired, both returned
  authoritative SERVFAIL with no answers. Fresh reports restored service.
- In the AuthorityFence phase, two authorities exchanged mutually
  authenticated, signed 2-of-2 snapshots and both returned NOERROR/A. Reciprocal
  temporary host-route blackholes for each peer's public /32 caused both to
  return SERVFAIL after the configured 8-second lease. Removing the routes
  restored NOERROR only after fresh signed snapshots. The Osaka authority was
  also restarted while the peer routes were blocked, retaining its protected
  epoch/replay state; both authorities stayed SERVFAIL until routes were
  restored and fresh snapshots arrived.
- Temporary peer /32 blackhole routes were removed and normal VPC gateway
  routes restored. All temporary binaries, configs, certs, state, watchdogs and
  processes were removed. Apache remained active and returned HTTP 200 on all
  three hosts; ports 53 and 15444 no longer listened. No AWS security-group,
  Apache or system-service configuration was changed. Full scope and limits:
  ops/acceptance/gslb-physical-observer-quorum-20261120.md.
- This advances #109's physical quorum, authority partition and restart
  evidence, but does not complete it. Actual geography/path independence was
  not proven; DNSSEC/public delegation, malicious-frame fuzzing, one-hour soak,
  500 Mbps capacity, VRRP/ECMP and annual availability remain untested here.
  Keep #109 open. Production remains NO-GO and annual 99.9% is unmeasured.
- PR #285 is merged but issue #38 remains open; do not infer complete federated
  logout or distributed identity revocation from that increment.

## Previous continuation update (2026-11-20)

This update supersedes the 2026-11-19 continuation snapshot below. Live GitHub
and exact post-merge CI were checked on 2026-11-20:

- `main` is `c0b3668984547ed6de8927516ebceccdae10f6e6` (squash merge of PR #282).
  All **17/17** GitHub Actions checks on this exact `main` commit passed. There
  were **zero open PRs** and **12 open issues** immediately after #282 merged,
  before this handoff PR was created: #34, #36,
  #37, #38, #48, #49, #51, #52, #53, #100, #101 and #109.
- PR #282 fixed proxy-span lifecycle completion (`Activity.Stop()` after final
  tags/status) and passed route/cluster/destination dimensions into the lab
  metric. Its paired-profile harness now applies equivalent lifecycle and
  dimension instrumentation to the exact base and candidate checkouts, with
  fail-closed source-shape checks. All 33 PR checks passed on head
  `0eef88f2114f206d10be056cb02ab9f6a847674c`; the run had three alternating
  75-VU paired samples, validated OTLP trace/metric markers on both revisions,
  and emitted bounded GC traces. Mean candidate-minus-baseline allocation was
  **+2.171 B/request**, with 95% CI **−28.778 to +33.12 B/request**. Since the
  interval includes zero, this establishes no allocation improvement. Issue
  #34 remains open.
- A three-EC2 Amazon Linux 2023 test exercised the #109 two-authority mTLS
  fencing subset using Mumbai and Osaka authorities plus a third lab host.
  Both authorities answered authoritative NOERROR over UDP/TCP at baseline;
  during a timed reciprocal host-route `/32` partition, both returned
  authoritative SERVFAIL with no answers; after route recovery, both returned
  NOERROR over UDP/TCP. Test processes, routes, timers and temporary files were
  removed; Apache remained running on all three hosts. This was a host-route
  partition, not a switch/security-group or VRRP/ECMP test. It does
  not complete #109's multi-vantage, observer quorum, adversarial, scale or
  soak acceptance, so #109 remains open.
- PRs #258 and #260–#264 are merged. PR #265 is closed **without merge**; do
  not assume its OIDC back-channel logout/session-revocation code is present in
  `main` unless independently located and verified. Issue #38 remains open.
- Issue #50 is currently closed as completed. Its CI stack verifies Collector,
  Prometheus and Grafana integration; this is not evidence of a customer's
  deployed retention/alert route and must not be used to claim production
  monitoring or availability.
- Production remains **NO-GO**. Annual 99.9% availability is unmeasured. Issue
  #36 still lacks physical VRRP/ECMP acceptance; #52 lacks public delegation/DS
  and full key/GeoIP operations; #109 has only the bounded physical subset
  above. Other open issues remain subject to their own acceptance criteria.

## Current continuation update (2026-11-19)

This update supersedes the historical 2026-11-16 snapshot below where they
conflict. Live GitHub was checked after PR #206 merged on 2026-11-19:

- Product-code baseline: `25cb9f5f0838225110810051b464ad8178fe7c93`. All six
  Actions workflows triggered by this merge completed successfully. At the
  check time there were **zero open PRs** and **13 open issues**: #34, #36,
  #37, #38, #48, #49, #50, #51, #52, #53, #100, #101 and #109.
- Recent merged increments include #184 (opt-in HTTP/3), #188 (two-authority
  GSLB fencing), #189 (manual DNSSEC key overlap), #190 (application pools and
  DR routing), #198 (paired allocation profiling), #199 (failover alert), #201
  (opt-in NSEC3), #202 (YARP per-request INFO log filtering), #204 (low-priority
  log-drop metric/dashboard), #205 (typed peer-state schema and expiry), and
  #206 (HTTP/2 multiplexed admission acceptance). These do not blanket-close
  their associated issues.
- PR #108 is **closed, not merged**; its observed-latency routing is not part of
  `main` unless separately implemented elsewhere.
- PR #202 passed all exact-head checks, including three paired 75-VU profile
  rounds and allocation traces (Actions run `44488122878`). Extra allocation
  fell by 1,123.443 bytes per proxied request (95% CI −1,142.481 to −1,104.405);
  rounds had zero request errors, with no statistically clear latency or
  throughput regression. Candidate extra allocation remained about 7,664
  bytes/request, so #34 remains open.
- PR #204 passed 35/35 exact-head checks; `/gateway/metrics` and both Grafana
  dashboards now expose low-priority drops. #50 remains open for deployed
  retention/alert routing, full telemetry, production-path overhead and
  deployment evidence.
- PR #205 passed exact-head Windows/Linux checks; its expiry path clears the
  monotonic freshness timestamp but preserves epoch/minute/sequence replay
  high-water marks. WSL Ubuntu `LoadBalancingCoreTests` also passed. #101 remains
  open for deltas/backfill, queues, operator metrics/UI, partition/restart
  coverage and the physical 60-minute soak.
- PR #206 passed 30/30 exact-head checks. The real-process E2E exercises TLS
  HTTP/2 multiplexing, bounded local overload rejection, FIFO permit release and
  response-body lease lifetime. #100 remains open for other protocol/traffic
  characterization and physical capacity acceptance.
- A 60-minute synthetic GitHub-hosted workload passed previously. It is not
  #36's required on-prem VRRP/ECMP test with one-hour solo capacity runs on each
  surviving physical gateway, real faults, zero operational loss, live alerts
  and sign-off. #109 also lacks completed independent-vantage partition and
  physical soak acceptance.
- NSEC3 and direct-IP EC2 DNS checks are partial evidence for #52. Public parent
  delegation/DS publication and recursive-resolver validation remain open.
- **Release remains controlled-test GO / production NO-GO. Annual 99.9%
  availability is unmeasured.** Actions and short cloud/EC2 tests do not establish
  an annual SLO or production certification.

**Historical snapshot date:** 2026-11-16 (UTC; see the live update above)
**Repository:** this checkout’s configured `origin` remote (verify with `git remote -v`)
**Product:** GatewayCore — .NET 10 / YARP ADC-style single-organization on-premises L7 gateway and management UI, with separate experimental L4, WAF integration, and GSLB/DNS engines.  
**Canonical baseline at handoff:** `main` = `cdee959d8c5f66a5bb8edf9b432de48bcd27ca1a` (PR #107).  
**Release decision:** **GO for isolated development and controlled test/staging; NO-GO for production.**  
**Handoff scope:** Reconstructed from GitHub source/docs/issues/PR history and workflow state. It is a precise *snapshot*, **not** a claim that every older source file or real customer workflow was independently executed. Do not turn feature tables or tests into production certifications.

## 0. Read this first — instructions for Codex

You are continuing this repository, **not creating a fresh project**. All source changes must be committed to GitHub branches and reviewed through PRs. Keep behavior-compatible defaults, customer data safety, and release gating. Small complete changes with callers + tests + docs are preferred to broad rewrites. Avoid "vibe coding": inspect real files, establish the failure mode, write deterministic regression tests where possible, run/build on supported OSes, and report exact hashes/checks and remaining unknowns.

**Project requirements:**
- **Single-tenant / one organization / on premises** is v1. No SaaS multi-tenant isolation promise; #39 is P2.
- **CA/PKI workloads are optional customer profiles**, not a product-wide default. No corporate/customer name hard-coded in identifiers, paths or branding.
- **Safety:** NEVER auto-replay non-idempotent CA signing, OCSP POST, payment or other transactional requests. Distinguish HTTP failover from database replication/consistency.
- **Independent change approval:** requester must not self-approve live route/security changes; audit, RBAC, CSRF and rollback remain in place.
- **Do not modify, reset, overwrite, decrypt, delete or migrate existing customer configuration/key rings/users** without an approved migration plan. The renamed GatewayCore Data Protection purposes are incompatible with older branded state without explicit migration.
- **Licensing:** `gslb` contains OpenGSLB Go source under AGPL-3.0-or-later **OR commercial license**. `ha-praxy` contains GPL-licensed HAProxy C source. **Do not merge either branch or copy a few modules into proprietary GatewayCore casually**: a partial copy still carries license obligations. Review functional requirements and write independent .NET implementations, or obtain licensed permission and legal review.
- **No credentials in code, tests, logs, issues, commits or artifacts**. Use disposable local fixtures with fake credentials and trusted development certs. Do not contact private customer servers from GitHub Actions.
- Test-only changes and green CI are not proof of physical HA, public authoritative DNS, an acceptable F5/NetScaler feature match, or SLA.
- Never disable a required workflow, weaken a timeout/threshold, or label a skipped test as PASS just to merge.

## 1. Immediate current state — what is actually pending

At this snapshot, `main` contains all merged work through PR #107. **PR #108 is still OPEN and DRAFT, not merged**:
- PR: ../../pull/108
- Branch: `feature/gslb-observed-latency-policy-20261116`
- Head: `471bb8356af4a2a3e44e527700d3b723795f5390`
- Last observed **11/11 triggered GitHub check runs succeeded** at this exact head, after an earlier Windows/Ubuntu GSLB acceptance failure was corrected. The earlier failure was that the test asserted a faster-site winner before the 3-measurement sample floor had completed; tests now wait for enough real probe cycles.
- PR #108 adds opt-in local DNS-node-to-probe latency sampling with bounded EMA, freshness/clock-rollback checks, a minimum sample count, and weighted fallback when data are missing or too close. **This is not end-user RTT, a predictive mesh, regional latency SLAs or globally synchronized health.**
- **Codex next action:** fetch and review the complete PR diff, test on the exact latest head, check branches/conflicts and required CI, then decide merge. Keep the draft if unresolved. Do not cite it as part of current `main` until merged.

The 87-branch count reported before this handoff branch was created has now become **88 branch refs including the handoff documentation branch**. The earlier 73-branch audit is historical, not the current live branch inventory.

## 2. Product architecture and operational boundary

### L7 HTTP/HTTPS data plane and Control Center
- `control-center/`: ASP.NET Core .NET 10 application; YARP reverse proxy; static browser app in `control-center/wwwroot/`; route/cluster/destination editing and real gateway readiness/health.
- Management UI offers organization bootstrap; Admin/Operator/Viewer roles; sign-in, mail/OTP, LDAPS integrations; route drafts, two-person approval, freeze, backup/restore, config revisions and local audit. Browser/API and security regression tests exist. **Real enterprise IdP, FIDO2, WORM audit and live AD/SMTP signoff remain missing.**
- L7 routing: native YARP policies, independently implemented weighted random and source-IP rendezvous, optional `PrimaryBackup`, active/passive checks, rise/fall, slow start, draining, passive-ejection bounds, autonomous recovery observation. Keep old default policies unchanged; new policies opt-in.
- Local concurrency gate, optional bounded queue, per-peer fixed-window IP limiter and experimental signed two-node counter telemetry exist. **They do not equal per-backend HAProxy queues/stick tables or strict cross-node quotas.**
- Traffic plane and management plane must remain separated, with explicit narrow listening addresses and security controls. Admin APIs must not be reachable through public routing accidentally.

### Optional independent engines and integrations
- `engines/GslbDns/`: independent experimental **non-recursive** DNS/GSLB server; NOT the YARP HTTP data plane and NOT UI-deployed/managed. Manual JSON config, Windows/Linux real-socket acceptance.
- `engines/L4/`: separate experimental TCP/UDP proxy process, not YARP middleware; lab socket tests exist; no full production management, UDP health or physical scale qualification.
- `integrations/WafCrs/`: experimental external Nginx + ModSecurity OWASP CRS test harness (benign, XSS/SQLi/path traversal/body limit); not a complete governed production WAF.
- `control-center/GatewayAgent/`: separate agent project; source acceptance does not prove real physical fleet enrollment. Production signed config rollout/recovery remains outstanding.
- `control-center/ops/`, `ops/`: systemd/keepalived, Prometheus, capacity, TLS, release, and acceptance scripts. Scripts and templates do not imply real infrastructure was touched.
- `tests/` and `.github/workflows/`: disposable cross-platform L7/L4/GSLB/WAF, browser/API, SSL, mail, security, HA and capacity gates.

### GSLB specifically — currently merged vs missing

**Merged into main (lab/source + triggered CI, NOT production-certified):**
- Independent DNS UDP and TCP with A/AAAA, optional NS/SOA and in-bailiwick A glue, EDNS(0), negative answers, no recursion.
- IPv4/IPv6 family-specific healthy response selection, original weighted IPv4 distribution.
- Optional ordered `Failover` site priority and automatic return-to-primary after healthy rise threshold; configurable bounded health rise/fall.
- Direct HTTP(S) 2xx health checks that do NOT follow misleading redirects; opt-in TCP-connect probes (connection != application readiness).
- Bounded health sweep parallelism, non-overlapping probe batches, bounded per-source UDP rate limiting, UDP truncation and TCP retry.
- Optional operator-defined **private resolver-IP CIDR** longest-prefix mapping to backend region, with healthy fallback. This is NOT licensed GeoIP and does not use EDNS Client Subnet to infer an end user's location.
- Strict all-down option returning SERVFAIL, while older availability-first fallback remains the default for legacy configs.

**PR #108 proposed, not merged:** `ObservedLatency` per-zone routing, with local probe elapsed-time EMA, freshness/sample floor and conservative weighted fallback.

**Not implemented / no complete release evidence:** public authoritative DNS conformance incl. delegation/zone cuts and RFC corner cases; DNSSEC signing, key lifecycle and DS/serial coordination; secure dual-authoritative-node configuration; validated external health quorum; authentication/replay-fenced encrypted agent mesh; predictive signals; weighted priority *groups/chains*; licensed GeoIP/ASN; vetted ECS privacy/cache semantics; dynamic RBAC DNS CRUD/hot reload; management UI control of the DNS process; live authoritative interop, scale/fuzz, split-brain and physical DC/DR drills. Reference architecture is the *user-supplied* OpenGSLB branch/image, not a feature certification.

**Independent-node design direction:** Health authority must be explicit (approved quarantine/maintenance, validated application readiness, signed fresh agent claims, unknown); predictive/ML telemetry begins as advisory only. No stale/unsigned agent gossip may promote an unhealthy signing backend. DNS caching limits how quickly a changed answer affects existing clients. Full plan: issue #109 and issue #52.

### Historical implementations already represented by merged PRs
- Source and runtime improvements to active/passive YARP health, bounded overload, safe failover, slow start/drain, signed peer HMAC timestamps/boot epochs/sequence and telemetry expiration, experimental Redis atomic rate quota with TLS, two-gateway disposable HA.
- Windows UI/UX (navigation, session isolation, drafts), real Chromium/API integration, test installers/releases, Mail/OTP provider presets (Gmail/Microsoft OAuth2, Zoho India and others), security/CSRF provider gates, and neutral GatewayCore product branding.
- Extended signed config/key protection, WAF/L4/GSLB labs, HAProxy comparison/capacity harness, on-prem release runbooks and evidence ledgers. **Some items remain partial despite source being present.**

## 3. GitHub-integrated recent implementation chronology

The following rows come from merged PR metadata, not guessed from branch names. Older implementation work predates the snapshot; consult GitHub PR history for earlier commits.

| PR | Merged deliverable | Status/date |
| --- | --- | --- |
| [#70](../../pull/70) | docs: refresh root README for GatewayCore Windows test.10 and integration acceptance | Merged 2026-11-14 |
| [#71](../../pull/71) | Add Gmail/Microsoft OAuth2 SMTP, multi-provider setup and enforced security CI | Merged 2026-11-14 |
| [#72](../../pull/72) | Publish Windows test.11 with multi-provider OAuth2 and security gate | Merged 2026-11-14 |
| [#74](../../pull/74) | Add isolated HAProxy reference for GatewayCore L7 comparison | Merged 2026-11-15 |
| [#75](../../pull/75) | Bound YARP proxy concurrency and add passive failure hysteresis | Merged 2026-11-15 |
| [#76](../../pull/76) | Observe active YARP health independently of client traffic for recovery warmup | Merged 2026-11-15 |
| [#78](../../pull/78) | Add opt-in YARP RiseFall active health hysteresis (rebased after recovery observer) | Merged 2026-11-15 |
| [#79](../../pull/79) | Fix recurring EC2 CI failure when live backend variables are absent | Merged 2026-11-15 |
| [#80](../../pull/80) | Fix passive-ejection false recovery in idle YARP health observer | Merged 2026-11-15 |
| [#81](../../pull/81) | Experimental shared Redis atomic peer rate quota with fail-closed partitions | Merged 2026-11-15 |
| [#82](../../pull/82) | E2E: two shipping GatewayCore instances sharing authenticated TLS Redis quota | Merged 2026-11-15 |
| [#83](../../pull/83) | Add opt-in signed HTTPS peer counter synchronization (no quota double-spend) | Merged 2026-11-15 |
| [#84](../../pull/84) | Test GatewayCore website and synthetic HTTP bandwidth on two distinct Ubuntu Actions VMs | Merged 2026-11-15 |
| [#85](../../pull/85) | Manual two independent Ubuntu VMs with encrypted cross-host HAProxy ingress failover | Merged 2026-11-15 |
| [#86](../../pull/86) | Security: reject extreme peer-sync timestamps without arithmetic overflow | Merged 2026-11-15 |
| [#87](../../pull/87) | Fix peer sync 256KiB frame limit and add authenticated operational diagnostics | Merged 2026-11-15 |
| [#88](../../pull/88) | Rebuild GatewayCore login and operator UI shell with grouped navigation and peer diagnostics | Merged 2026-11-15 |
| [#89](../../pull/89) | Peer recovery: signed process boot epoch and safe restart resynchronization | Merged 2026-11-15 |
| [#90](../../pull/90) | Enterprise operator UX: isolate sessions, guard draft logout and display real backend readiness | Merged 2026-11-15 |
| [#91](../../pull/91) | Enterprise customer UAT checklist for login-to-operations, mobile UX, peer recovery and 500Mbps | Merged 2026-11-15 |
| [#92](../../pull/92) | Polish customer launch branding: consistent GatewayCore identity throughout management UI | Merged 2026-11-15 |
| [#93](../../pull/93) | Stop obsolete EC2 nightly CI and unblock safe replacement test targets | Merged 2026-11-15 |
| [#94](../../pull/94) | HA 10x CI: verify every Windows artifact and report worst observed failover | Merged 2026-11-15 |
| [#95](../../pull/95) | Add opt-in HAProxy-style primary/backup routing with UI and real L7 failover acceptance | Merged 2026-11-16 |
| [#96](../../pull/96) | Audit all 73 legacy branches and map safe HAProxy 3.4 roadmap | Merged 2026-11-16 |
| [#97](../../pull/97) | Correct operator capability inventory after PrimaryBackup CI verification | Merged 2026-11-16 |
| [#98](../../pull/98) | GSLB: authoritative NS/SOA, bounded UDP/EDNS0 and TCP fallback (lab) | Merged 2026-11-16 |
| [#99](../../pull/99) | Bound peer telemetry freshness and prevent stale counter resurrection | Merged 2026-11-16 |
| [#102](../../pull/102) | GSLB: independent active/standby DNS failover and rise/fall health thresholds | Merged 2026-11-16 |
| [#103](../../pull/103) | GSLB: opt-in TCP backend health and direct HTTP readiness without redirects | Merged 2026-11-16 |
| [#104](../../pull/104) | GSLB: health-aware IPv6 AAAA and family-correct DNS behavior | Merged 2026-11-16 |
| [#105](../../pull/105) | GSLB: bounded parallel DNS health sweeps with non-overlapping cycles | Merged 2026-11-16 |
| [#106](../../pull/106) | GSLB: opt-in private CIDR-to-region selection with health-aware DR fallback | Merged 2026-11-16 |
| [#107](../../pull/107) | docs: publish precise experimental GSLB capability and licensing boundaries | Merged 2026-11-16 |

**PR #108 is not in this table because it is draft/open.** A green check is not authorization to merge without reviewing the exact branch and preserving branch protections.

## 4. Open GitHub backlog — do not mark these resolved

The snapshot contains **16 open issues**. Priority is the existing GitHub label; a completed subfeature does not close the whole issue.

| Issue | Priority | Work | State |
| --- | --- | --- | --- |
| [#109](../../issues/109) | P0 | P0 GSLB: authenticated multi-vantage health agents, signed snapshots, validation authority and partition fencing | Open |
| [#101](../../issues/101) | P1 | P1 bounded peer-state registry: TTL, restart teaching, deltas and partition recovery | Open |
| [#100](../../issues/100) | P1 | P1 HAProxy-style per-backend admission: max connections, bounded queue, drain and overload | Open |
| [#61](../../issues/61) | P2 | Post-v1: Redis Sentinel shared-state integration, fencing and partition safety | Open |
| [#53](../../issues/53) | P1 | P1 L4: real TCP/UDP load balancer functionality and sustained soak testing | Open |
| [#52](../../issues/52) | P0 | P0 GSLB: authoritative DNS NS/SOA, TCP fallback, EDNS0 and geo-routing completeness | Open |
| [#51](../../issues/51) | P1 | P1 WAF: false-positive/false-negative tuning, OWASP coverage and load benchmarks | Open |
| [#50](../../issues/50) | P1 | P1 observability: OpenTelemetry traces/metrics/logs and Grafana dashboards | Open |
| [#49](../../issues/49) | P1 | P1 GitOps: declarative gateway config, Terraform provider/module and Kubernetes Gateway API | Open |
| [#48](../../issues/48) | P1 | P1 platforms: Windows DPAPI support matrix and secure Linux Data Protection key persistence | Open |
| [#39](../../issues/39) | P2 | P2 future multi-tenant SaaS: tenant isolation across Control Center, gateway config and logs | Open |
| [#38](../../issues/38) | P1 | P1 identity: OIDC SSO, FIDO2/MFA enforcement and tamper-evident immutable external audit | Open |
| [#37](../../issues/37) | P1 | P1 TLS: ACME HTTP-01/DNS-01 certificate issuance, renewal and safe zero-downtime rotation | Open |
| [#36](../../issues/36) | P0 | P0 v1 HA: two independent signed-config gateways behind VRRP VIP/ECMP (no Redis) | Open |
| [#35](../../issues/35) | P1 | P1: production PKI mTLS trust, CRL/OCSP failure behavior, and fleet-wide certificate rotation | Open |
| [#34](../../issues/34) | P1 | P1: reduce remaining ~8.6 KiB allocated per proxied request (real YARP hot-path profiling) | Open |

**Suggested work order after PR #108 review:**
1. P0 **#52 DNS correctness and multi-NS conformance**: independent dig/kdig/resolver, DNSSEC decision, correct delegation/serial/negative caching, malformed input/fuzz and anti-amplification before public DNS exposure.
2. P0 **#109 signed, mTLS-authenticated health agents**: versioned schema, restrictive agent enrollment, external proof/quorum, freshness, authority precedence, out-of-order/partition/epoch handling and **advisory-only predictions**. Separate two-node DNS authority from gossip liveness.
3. P0 **#36 actual two-host production HA**: independent power/NIC/failure domains, VIP/VRRP or ECMP, matching signed config, physical drain/kill/partition, no transaction replay. **Redis is not P0 v1; see #61**.
4. P1 **#100** true per-destination backpressure/queues, **#101** full bounded multi-table peer state parity, **#48** key lifecycle/restore, **#50** OpenTelemetry+Grafana, **#35/#37/#38** PKI/ACME/SSO and external audit.
5. Finish P1 **#53 L4**, **#51 WAF**, **#49 GitOps**, **#34 hot-path allocations** only with independent acceptance. Maintain #39 SaaS as P2, not implicit v1 functionality.

Before choosing a change, open its issue body and read the required acceptance criteria. Never close #36, #52, #109 based only on standalone CI.

## 5. Git branching — how Codex must work

**Canonical truth:** always start new work from latest `origin/main`. Most old feature branches are diverged **squash-merge snapshots**, not missing functionality. Their Git "ahead" count does not prove the code is absent from `main`. See `control-center/docs/BRANCH_73_HAPROXY_AUDIT.md` for the original 73 branch-by-branch assessment.

- `main`: shipping development baseline. Preserve; no destructive reset.
- `feature/gslb-observed-latency-policy-20261116`: ongoing draft PR #108; checkout only to inspect/fix that PR.
- `gslb`: **read-only architecture reference** OpenGSLB Go v1.1.10, commit `48f020c3f0d7d3d353485c9a0d701061a3014c08`, AGPL-3.0-or-later or separate commercial terms; NEVER mass merge/copy code into commercial GatewayCore.
- `ha-praxy`: **read-only reference** HAProxy C code, commit `16f808d9c7befbe87c5ad9cd04029ed00036bb79`, GPL; NEVER mass merge or claim native peer-wire parity.
- `ci/*`, `test/*`, `docs/*`, `fix/*`, `release/*` and most `feature/*`: historical source/test snapshots; inspect diffs carefully, backport only missing validated behavior via fresh independently tested PR.

### Start a new Codex task (safe commands)

~~~sh
git clone <approved-origin-url>.git
cd yarp-lb
git fetch origin --prune --tags
git switch main
git pull --ff-only origin main
git status --short
git rev-parse HEAD
cat AGENTS.md
cat CODEX_HANDOFF.md

# Read a specific issue and check the current code before deciding to implement
gh issue view 52
git grep -n 'DnsWireProtocol' -- engines/GslbDns tests/GslbAcceptance
git switch -c codex/issue52-dns-correctness
# Work in small, reviewable commits, then:
git push -u origin codex/issue52-dns-correctness
gh pr create --draft --base main --head codex/issue52-dns-correctness
~~~ 

For the existing draft PR:

~~~sh
gh pr view 108
gh pr checks 108
gh pr diff 108
gh pr checkout 108
# Review implementation and exact-head tests. Do not blindly auto-merge.
~~~

For a historical snapshot, use read-only comparisons first:

~~~sh
git fetch origin --prune
git diff --stat origin/main..origin/feature/experimental-gslb-authoritative-dns
git log --oneline --left-right origin/main...origin/feature/experimental-gslb-authoritative-dns
# Do not interpret 'ahead' as missing functionality; main used squash merges.
# NEVER: git merge origin/gslb
# NEVER: git merge origin/ha-praxy
~~~

Never force-push `main`, mass-cherry-pick old branches, replace newer `Program.cs` from an archive, disable CI or reduce existing release thresholds. Branch names are not evidence; exact content, license, tests, and PR history are.

### Full live branch ref inventory (88 branches including this documentation branch)

**As of handoff branch creation.** All listed SHA prefixes are branch **tips**, not merge commits; a branch tagged "historical" may still contain unreviewed deltas and is not approved for automatic merge.

| Branch | Tip SHA prefix | Disposition |
| --- | --- | --- |
| `ci/combined-pr31-pr32-all-gates-20261114` | `72d7dbc5f65d` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `ci/l7-acceptance` | `786b26dc60d6` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `ci/soak-onehour-0.1` | `f471bb4189df` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `ci/soak-onehour-issue17-shared` | `d2b135f760e9` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `ci/verify-merged-ec2-pr32-all-gates-20261114` | `239f586e45b3` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `ci/windows-ha-ten-run-followup-20261114` | `e5076fdbb256` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `docs/branch-73-source-audit-20261116` | `bea946ffee40` | HISTORICAL: merged PR #96 via normal GitHub workflow; do not remerge |
| `docs/codex-handoff-20261116` | `cdee959d8c5f` | HANDOFF DOCS: current PR work |
| `docs/enterprise-operator-uat-20261115` | `37f88230769c` | HISTORICAL: merged PR #91 via normal GitHub workflow; do not remerge |
| `docs/gslb-experimental-capabilities-readme-20261116` | `f1bd3eaee7d5` | HISTORICAL: merged PR #107 via normal GitHub workflow; do not remerge |
| `docs/root-readme-test10-acceptance-20261114` | `1d0516018691` | HISTORICAL: merged PR #70 via normal GitHub workflow; do not remerge |
| `feat/mail-provider-oauth-and-security-gates-20261114` | `e02bf1762bad` | HISTORICAL: merged PR #71 via normal GitHub workflow; do not remerge |
| `feature/active-health-rise-fall-20261115` | `05d162776fe6` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/active-health-rise-fall-rebased-20261115` | `5f051dbf289f` | HISTORICAL: merged PR #78 via normal GitHub workflow; do not remerge |
| `feature/agent-client-auth-negative-tests-20261114` | `7d4281edf6e9` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/autonomous-yarp-recovery-watch-20261115` | `2ddab48e202a` | HISTORICAL: merged PR #76 via normal GitHub workflow; do not remerge |
| `feature/bounded-traffic-recovery-20261115` | `a668a77c3117` | HISTORICAL: merged PR #75 via normal GitHub workflow; do not remerge |
| `feature/ci-failover-load-runtime-profiling` | `d684b429986b` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/ci-security-tls-benchmark-0.1` | `f4f1dcc9c421` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/control-center-0.1-full-source` | `2a3a0aa529ff` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/ec2-functional-control-center-actions-20261114` | `69b879428197` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/ec2-real-control-center-rebased-20261114` | `bde24de30046` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/enterprise-ui-shell-login-navigation-20261115` | `33765b432a98` | HISTORICAL: merged PR #88 via normal GitHub workflow; do not remerge |
| `feature/experimental-distributed-quota-20261115` | `07907e8e1e84` | HISTORICAL: merged PR #81 via normal GitHub workflow; do not remerge |
| `feature/experimental-gslb-authoritative-dns` | `a1216f928ce2` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/experimental-l4-tcp-udp-engine` | `a848be77d10d` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/gslb-authoritative-dns-tcp-edns-20261116` | `efccb84b98d4` | HISTORICAL: merged PR #98 via normal GitHub workflow; do not remerge |
| `feature/gslb-bounded-probe-concurrency-20261116` | `520d1ee76795` | HISTORICAL: merged PR #105 via normal GitHub workflow; do not remerge |
| `feature/gslb-dualstack-aaaa-20261116` | `91a1c1c732c9` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/gslb-dualstack-aaaa-v2-20261116` | `a8eed7ef77c1` | HISTORICAL: merged PR #104 via normal GitHub workflow; do not remerge |
| `feature/gslb-health-hysteresis-failover-20261116` | `663ba63936b1` | HISTORICAL: merged PR #102 via normal GitHub workflow; do not remerge |
| `feature/gslb-observed-latency-policy-20261116` | `471bb8356af4` | ACTIVE: draft PR #108; review/CI, then decide |
| `feature/gslb-private-cidr-region-routing-20261116` | `bb913bf4b5ae` | HISTORICAL: merged PR #106 via normal GitHub workflow; do not remerge |
| `feature/gslb-safe-all-down-fallback-20261114` | `0603a4c2b61f` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/gslb-tcp-health-redirect-safety-20261116` | `be10d127302b` | HISTORICAL: merged PR #103 via normal GitHub workflow; do not remerge |
| `feature/ha-passive-health-graceful-drain` | `dba0cbd6036f` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/haproxy-reference-baseline-20261115` | `192f96d46123` | HISTORICAL: merged PR #74 via normal GitHub workflow; do not remerge |
| `feature/issue17-console-backpressure-fix-20261114` | `6eb0bdc6c682` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue17-hang-watchdog-20261114` | `25bb740c9dff` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue17-observable-onehour-20261114` | `2e5123927686` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue23-bounded-ejection-safe-failover-20261114` | `0c090be0e373` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue23-safe-ejection-rebased-20261114` | `7a72ab2d0ca7` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue24-allocation-characterization-20261114` | `b29bc20d3c3c` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue26-lab-ca-certificate-rotation-20261114` | `57800684db2a` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/issue40-ha-process-heartbeats-20261114` | `f05ef1e54669` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/l4-health-drain-idle-proxy-v1-20261114` | `e5259aca9012` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/l7-drain-warmup-telemetry` | `86e4521f0dfe` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/linux-secure-dp-onprem-20261114` | `4b8fe541fc4a` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/linux-secure-dp-rebased-20261114` | `6f14c3486af8` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/linux-sigterm-graceful-acceptance` | `15bf5e9fb0fc` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/optin-haproxy-primary-backup-20261116` | `1a9fb350890b` | HISTORICAL: merged PR #95 via normal GitHub workflow; do not remerge |
| `feature/owasp-crs-waf-ci-integration` | `312cf60319c8` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/peer-state-hmac-20261115` | `7570a16f2cdd` | HISTORICAL: merged PR #83 via normal GitHub workflow; do not remerge |
| `feature/peer-telemetry-freshness-expiry-20261116` | `4d2bad23591d` | HISTORICAL: merged PR #99 via normal GitHub workflow; do not remerge |
| `feature/product-nonblocking-log-observability-20261114` | `f750842579b8` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/secure-engine-staging-20261114` | `2fe70767511e` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/shared-gateway-logger-soak-20261114` | `71f7c2919e78` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/soak-failfast-sustained-slo-20261114` | `e43ce1d760eb` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/soak-p99-timeline-analysis` | `40c6e8dc7795` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/tailnet-two-runner-failover-20261115` | `f4d4c501207d` | HISTORICAL: merged PR #85 via normal GitHub workflow; do not remerge |
| `feature/two-ubuntu-capacity-evidence-20261115` | `c969c88b395b` | HISTORICAL: merged PR #84 via normal GitHub workflow; do not remerge |
| `feature/waf-corpus-detection-body-20261114` | `b349e4c1bbb7` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `feature/0.1-laptop-development-kit` | `5be8f2956763` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `fix/capability-inventory-primary-backup-20261116` | `756767ad3b6d` | HISTORICAL: merged PR #97 via normal GitHub workflow; do not remerge |
| `fix/customer-ui-brand-consistency-20261115` | `66d253054d27` | HISTORICAL: merged PR #92 via normal GitHub workflow; do not remerge |
| `fix/ec2-ci-prerequisite-gating-20261115` | `e20f59f004f4` | HISTORICAL: merged PR #79 via normal GitHub workflow; do not remerge |
| `fix/health-admission-passive-observer-20261115` | `00bea1fc2e94` | HISTORICAL: merged PR #80 via normal GitHub workflow; do not remerge |
| `fix/issue40-harness-threadpool-bounded-20261114` | `d6e4257cf4b1` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `fix/operator-session-hygiene-readiness-20261115` | `87de560fd72b` | HISTORICAL: merged PR #90 via normal GitHub workflow; do not remerge |
| `fix/peer-epoch-resync-20261115` | `3f93d71fbd75` | HISTORICAL: merged PR #89 via normal GitHub workflow; do not remerge |
| `fix/peer-snapshot-bounds-ops-20261115` | `eb5ca5ebe07b` | HISTORICAL: merged PR #87 via normal GitHub workflow; do not remerge |
| `fix/peer-time-bound-overflow-20261115` | `04e77fa3428d` | HISTORICAL: merged PR #86 via normal GitHub workflow; do not remerge |
| `fix/retired-ec2-schedule-ci-20261116` | `a6369f33fae1` | HISTORICAL: merged PR #93 via normal GitHub workflow; do not remerge |
| `fix/windows-ha-ten-artifact-evidence-20261116` | `0b1111913f7a` | HISTORICAL: merged PR #94 via normal GitHub workflow; do not remerge |
| `fix/zoho-preset-real-browser-20261114` | `ace395fd7dca` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `gslb` | `48f020c3f0d7` | REFERENCE: OpenGSLB AGPL/commercial; NO MERGE |
| `ha-praxy` | `16f808d9c7be` | REFERENCE: HAProxy GPL C; NO MERGE |
| `main` | `cdee959d8c5f` | CANONICAL—base all new work here |
| `ops/onprem-production-gates-20261114` | `f54607832b08` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `refactor/neutral-gateway-branding-20261114` | `4e1be032b32a` | PRESERVED SNAPSHOT; compare to main, no wholesale merge |
| `release/windows-e2e-tested-test8-20261114` | `5319a3582bd3` | HISTORICAL TEST/RELEASE BRANCH; tag/artifact verification needed |
| `release/windows-mail-provider-test11-20261114` | `28591eca5ff0` | HISTORICAL: merged PR #72 via normal GitHub workflow; do not remerge |
| `release/windows-mail-provider-test12-20261114` | `14f8a6232ed4` | HISTORICAL TEST/RELEASE BRANCH; tag/artifact verification needed |
| `release/windows-mailkit-zoho-india-test9-20261114` | `562bcf8027ac` | HISTORICAL TEST/RELEASE BRANCH; tag/artifact verification needed |
| `release/windows-zoho-preset-test10-20261114` | `e73acdc52f33` | HISTORICAL TEST/RELEASE BRANCH; tag/artifact verification needed |
| `test/external-integration-acceptance-20261114` | `b14248a00262` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `test/real-end-to-end-acceptance-20261114` | `e356280a8479` | HISTORICAL CI/LAB; do not resurrect obsolete workflows |
| `test/shared-quota-two-gateways-tls-20261115` | `7c7cad192f9c` | HISTORICAL: merged PR #82 via normal GitHub workflow; do not remerge |

## 6. CI, build and local verification commands

**Always link evidence to the exact commit SHA** and enumerate *all required* workflows for the affected scope. `.github/workflows/gslb-acceptance.yml` runs the standalone DNS acceptance matrix on `windows-2022` and `ubuntu-24.04`. Other applicable workflows include control-center source/TS tests, real L7 failover, Windows HA repetitions, standalone L4/WAF, security, real browser API, synthetic load and capacity contracts. They are different gates, not interchangeable.

GSLB quick local/test runner (requires .NET 10 SDK and disposable listeners only):

~~~sh
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
~~~

Control Center source verification from repo root (see complete CI file for node tests and more projects):

~~~sh
dotnet build control-center/GatewayCoreYarp.csproj -c Release
dotnet build control-center/GatewayAgent/GatewayCoreGatewayAgent.csproj -c Release
dotnet run --project control-center/tests/LoadBalancingCoreTests/LoadBalancingCoreTests.csproj -c Release
python3 -m unittest discover -s tests/CI/branding -p 'test_*.py' -v
~~~

The GSLB stand-alone JSON service is started only with an **explicit disposable config** as described in `engines/GslbDns/README.md`. Do not expose test DNS to the Internet or delegate production zones.

Before merging, verify:
1. Exact PR head and current base; diff, review and conflict status.
2. Same-head Windows AND Linux jobs, security + load + L7 tests triggered by the changed paths, and any repo-required checks. If any is pending/failing, do not merge.
3. Error-path, cancellation, timeouts, half-open, health churn, recovery and malicious-input tests; defaults unchanged unless explicitly approved.
4. Change docs, UI/capability inventory where needed. Restore safe draft/approval behavior.
5. Squash merge only after review and checks; then verify fresh `main` checks and avoid closing production issues prematurely.
6. If CI fails, inspect job logs and fix root cause; rerun on a **new** exact commit. An old successful head does not validate new source.

**As of this snapshot:** PR #108 exact head `471bb8356af4a2a3e44e527700d3b723795f5390` had **11/11 successful triggered checks**, zero failed among those reported. Its GitHub state remained **draft/open**. The prior Windows and Ubuntu DNS acceptance failures had been fixed and rerun successfully; the record is in #108 and Actions logs.

### Windows test build, identity and old state
- The repository README describes `v0.1.0-test.11` as the “latest Windows test build,” but the GitHub release listing also has published prerelease **`v0.1.0-test.12`** (verify exact release artifact, tag, checksum and migration instructions before updating README or deploying). **Neither is production-certified**.
- Current test quick launch in `README.md`: `.\Start-GatewayCore-Test.ps1 -IisBackendUrl "http://127.0.0.1:80/"`, then `curl.exe -i http://127.0.0.1:8080/gateway/health` and `curl.exe -i http://127.0.0.1:8080/proxy/`; UI on `http://127.0.0.1:8080/dashboard`. Only isolated approved test origins.
- Strong warning: neutral-brand rename changed cookie purposes, OS paths and Data Protection purposes. Preserve/backup old state; do not assume `test.12` updates old encrypted installs transparently.

## 7. Physical on-prem production gates — currently NOT PASSED

The site operator previously reported up to **500 Mbps**, meaning 0.5 Gbps *if confirmed as megabits*. The 50% headroom gate is then **750 Mbps HTTP response-body throughput for EACH surviving physical gateway alone**, plus >= 1.5 times real measured peak requests/second. If the original measurement was **500 MB/s**, the target changes to **6 Gbps**; obtain original evidence before testing. NIC-rated bandwidth is not measured throughput.

Mandatory acceptance:
- Capture real traffic mix, body size distribution, TLS share, p99 limit, concurrency, new connections/s, CPU/RAM/NIC, generator IDs and switch graph.
- Confirm generator and backend baseline. Compare same traffic with HAProxy on the same host class and TLS/keep-alive/ALPN.
- Run **two separate full one-hour solo-node runs** (one per physical gateway) at approved body-Gbps and RPS floor; zero HTTP/transport errors, per-minute p99 below approved cap, no packet drops/GC or logging loss, raw signed evidence.
- Two independent hosts/power/NIC fault domains; signed config same revision; real VIP/VRRP/ECMP, graceful drain, SIGKILL, host fault, network partition, failback, no duplicate CA operations, audited rollback.
- Real PKI/OCSP/CRL, key recovery, AD/LDAPS, SMTP delivery, OIDC/FIDO2, immutable audit and operational alert delivery; test actual browsers/mobile UI and real users.
- A previous GitHub-hosted synthetic 1 MiB, 20-second throughput canary and a 1-hour k6 soak exist; the 1-hour soak reported dropped low-priority logs. **Do not relabel either as site production success.** No CI runner has performed the physical release drill.

Source-of-truth procedures:
- `control-center/docs/ONPREM_PRODUCTION_GO_GATES.md`
- `ops/automation/ONPREM_RUN_ORDER.md`
- `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md`
- `control-center/docs/ENTERPRISE_OPERATOR_UAT.md`
- `ops/capacity/report.py` and `ops/capacity/limits.py`

## 8. Known documentation inconsistencies / do not trust stale snapshots as code

These are **not authorization to rewrite history**; they are issues Codex should verify against the exact current source:
- Historical `control-center/docs/ENGINE_GATES.md` and `control-center/docs/PLATFORM_PARITY_PLAN.md` contain older claims such as no standalone GSLB TCP/AAAA or no working L4; later PRs have added lab functionality. Update status tables after proving current behavior and keeping the production caveats.
- `engines/GslbDns/GSLB_CAPABILITY_PARITY.md` is a source snapshot and may say latency is not implemented even after PR #108 merges. Keep it accurate when its actual merge happens.
- Root `README.md` says test.11 is latest, but the release API shows test.12 published. Verify tag/release artifacts/checksums and update without claiming production installation or in-place state migration.
- `control-center/docs/BRANCH_73_HAPROXY_AUDIT.md` records 73 branches at **its audit timestamp**, not the live 88-branch inventory below.
- Historical PRs/docs may discuss Redis or a specific draft PR as a former P0; **current P0 v1 is independent signed-config gateways + real VIP/ECMP without Redis**. Sentinel is post-v1 #61.

## 9. Codex done-definition and response format

For every Codex task, produce: (a) short issue-linked scope and current `main` SHA; (b) exact inspected files and baseline behavior; (c) bounded source/tests/docs changes in a PR branch; (d) exact test commands/results with SHA and workflow links; (e) review/merge status without inventing success; (f) residual risks, live customer tests still unverified, and truthful GO/NO-GO. Update docs and capability statuses only after evidence. Do not promise background changes; commit and report what is actually finished.

**Do not attempt to "complete all OpenGSLB/F5 features" as one PR.** Preserve GatewayCore ownership and licenses while independently implementing each feature, its security/operations controls, and falsifiable acceptance tests.

## 10. Priority documentation and code paths for investigation

| Read in this order | Why |
| --- | --- |
| `AGENTS.md` (root) | Codex-specific non-negotiable safety and workflow instructions |
| `README.md` | Product shape, test release, project layout and truth boundaries |
| `engines/GslbDns/README.md` | Lab DNS config and precise supported DNS behavior |
| `engines/GslbDns/OPENGSLB_REFERENCE_REVIEW.md` | OpenGSLB source/license and independent feature mapping |
| `engines/GslbDns/GSLB_CAPABILITY_PARITY.md` | Desired enterprise feature-parity plan; snapshot, not runtime certification |
| `control-center/docs/BRANCH_73_HAPROXY_AUDIT.md` | Historical branches and why bulk merges are unsafe |
| `control-center/docs/ONPREM_PRODUCTION_GO_GATES.md` | Real release acceptance and NO-GO reasons |
| `control-center/docs/PEER_COUNTER_SYNC.md` | Signed counter telemetry vs real stick-table parity |
| `control-center/docs/PRIMARY_BACKUP_ROUTING.md` | YARP opt-in L7 primary/backup behavior |
| `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md` | Strict per-node 500 Mbps peak+headroom procedure |
| `.github/workflows/gslb-acceptance.yml` | Actual Windows/Linux standalone DNS build and tests |
| `.github/workflows/control-center-ci.yml` | Main application build, TS, signed fleet, keys and security |
| `tests/GslbAcceptance/Program.cs` | Real DNS socket acceptance and edge conditions |
| `control-center/wwwroot/` | Frontend: keep functional UX and safe role-scoped navigation |
| `engines/L4/README.md` and `integrations/WafCrs/README.md` | Separate experimental L4/WAF architecture and limits |

**Handoff snapshot end. Refresh live GitHub state before every code change.**

## Continuation — management readiness (2026-11-16)

Main remains `82c7b863e3674bb7c0a4ba368f4c11b3c7636152`.
[PR #111](../../pull/111) and [PR #112](../../pull/112) are open for
independent review after 9/9 reported exact-head checks each. Neither is
merged; [PR #108](../../pull/108) remains draft with policy-test gaps.

[PR #113](../../pull/113), `codex/management-readiness-isolation`, adds an
authenticated management readiness observation without relaxing data-listener
isolation. Dashboard requests have a five-second deadline, no-store caching,
explicit boolean validation, cancellation and old-session/result fencing.
The test-only commit `95ef33227c3e88cf5849aeb154ecf0cb538232fd` failed 7/8
new browser regressions against unchanged source. The local full UI suite
subsequently passed 14/14; Release application build passed with four existing
warnings. Real HTTP and browser acceptance must be verified at the final head.
CI also reproduced a branding regression introduced by absolute organization
URLs in this handoff; these are now relative links and repo-local CLI examples.
The branding check remains unchanged.

Mandatory ECC 2.2.3 TDD/security/verification guidance is in use. The user has
Windows Server 2022 and Ubuntu test machines but has explicitly requested
GitHub Actions-only testing and cannot provide access. Physical-host acceptance
remains NOT PERFORMED. Treat 99.9% as an annual rolling availability target
(365 days; 8h 45m 36s error budget), never as a correctness guarantee. Its
production SLI remains unmeasured. Source parity, DNSSEC,
signed agent authority/quorum/partition fencing, GeoIP/ECS, calibrated prediction
and remaining P0/P1 operational evidence remain incomplete. Production NO-GO.

## Continuation — annual objective, GSLB observability and quarantine (2026-11-17)

Current `main` is `33d97084f2b4ae4942ec00bb32cfd6cd4b1b0e40`.

On `main`, PR #121 merged
opt-in loopback-only GSLB metrics, bounded Prometheus alerts, synthetic alert
fixtures and an importable Grafana dashboard. Its exact-head Windows/Linux,
Prometheus, application and integration Actions passed. This was a Codex
code-review and CI merge; GitHub had no independent review recorded and no
branch protection requirement was configured.

PR #122 also merged the static per-site `AdministrativelyQuarantined` veto.
Windows/Linux DNS acceptance confirmed that quarantine overrides healthy
probes and signed reports and that availability-first fallback does not route
to an all-quarantined pool. The configuration is loaded at process startup;
there is no live management API.

PR #123 merged bounded child-zone referral handling: delegated cuts return
Authority NS records with AA clear, only in-bailiwick glue, referrals for child
names, and a parent negative SOA for absent DS at unsigned cuts. Exact-head
Windows/Linux GSLB acceptance and BIND/Knot interoperability passed; main GSLB
and L7 Actions also passed on `abbe1751...`. DNSSEC, automatic serial changes,
licensed GeoIP/ASN and complete authoritative DNS conformance remain open.

The 99.9% objective is rolling 365 days (8h 45m 36s maximum error budget), not
30 days. `control-center/docs/AVAILABILITY_SLO.md` records a provisional
independent-failure model and monitoring contract. Those modeled numbers are
assumptions, not observed production availability; the SLI remains unknown
until an externally monitored service and sufficient annual probe coverage
exist. Do not report the objective as achieved or production GO.

PR #124 merged the two-authority observer-feed partition acceptance case. It
uses isolated report replay state, verifies the affected DNS authority
fail-closes after the 8-second TTL while the other continues serving, and
requires fresh quorum before recovery. Windows and Linux exact-head GSLB
acceptance, BIND/Knot DNS interoperability, and all L7/HA/load Actions passed;
merged-main GSLB and L7 Actions also passed on `8c09867...`. This tests
observer-to-authority partition behavior only, not node-to-node consensus or
fencing. GitHub had no independent reviewer recorded.

PR #125 merged an eight-case malformed DNS/EDNS UDP corpus. Local Windows and
exact-head Windows/Linux GSLB acceptance confirmed malformed packets received
no reply and a valid query still worked afterward; all PR-head Windows/Linux
DNS and L7/HA/load Actions passed. Main GSLB/L7 Actions for `473ffe9...` also
passed.

PR #126 merged the malformed DNS/EDNS corpus over UDP and TCP. Windows and
Linux exact-head DNS tests confirmed malformed UDP frames get no response,
malformed TCP frames close without a DNS response (including Windows RST),
and valid queries still work. Main GSLB/L7 Actions passed on `8d6e092...`.

PR #127 merged the RFC 1982 SOA serial advance guard for changed existing
authoritative zones during signed GatewayAgent staging. Its Windows/Linux
application builds, Windows/Linux GSLB and L7 acceptance, Windows HA 10-run
gate, real HTTP integrations, Docker, Control Center and security Actions all
passed at exact head `472156be...`; merge commit is `da6feee...`. The guard
requires a manual serial bump. It does not generate serials, cover zone
creation/deletion, direct file edits, or restart DNS.

PR #128 merged bounded Prometheus gauges for current signed report
verdict/freshness counts (healthy/unhealthy/unknown/stale-or-missing), without
agent/site/backend labels, and added a Grafana panel. Windows/Linux exact-head
GSLB, L7, full builds, metrics contract, security and 10/10 HA checks passed.
The dedicated real mTLS, three-observer/two-authority acceptance also passed
locally and in Linux CI, including negative withdrawal, expiry, quorum loss,
recovery, partition behavior and privacy. Merge commit is `33d9708...`. These
are local evidence counts per configured reporter slot; they are not an
operator trust-management API or node-to-node consensus.

Current branch `codex/issue52-dnssec-unsupported-wire-contract` adds
cross-platform DNS acceptance for DO=1 queries of DS, RRSIG and DNSKEY, proving
that the explicitly unsupported DNSSEC policy returns unsigned NODATA without
AD or fabricated signatures and does not advertise DO in the response OPT. It
also sends 256 fixed-seed random UDP parser inputs and verifies the listener
survives and any replies remain ID-correlated and amplification-bounded. Full
local Windows GSLB acceptance passed; exact-head tests are pending.

A manually dispatched one-hour, 75-VU, 1-KiB HTTP soak on disposable GitHub
runners is running (Actions run ID `44074344501`). It is L7 runtime/memory
evidence, not GSLB consensus or annual uptime evidence.

At this snapshot, open P0 issues #36, #52 and #109 remain open. #109 still needs
cross-authority partition fencing/consensus, dynamic operator trust/evidence
management and independent multi-node partition acceptance. #52 still needs
DNSSEC, automatic serial lifecycle, licensed GeoIP/ASN data and broader
resolver/load/chaos acceptance, even if the current child-referral branch passes.
#36 still needs independent gateways behind
VRRP/ECMP and capacity/fault acceptance. Other P0/P1 issues also remain open;
refresh the live GitHub issue list before the next action. Availability SLO,
CI and static quarantine are not substitutes for these gates.

## Continuation — authenticated runtime metrics and test-environment requirements (2026-11-17)

PR #129 is merged at `356901897376bb549b6a936d0e6996cac9fc5874`. It verifies
the explicitly unsupported DNSSEC wire behavior and a deterministic malformed
UDP parser corpus; this does **not** implement DNSSEC signing. The live GitHub
issue query for #52 and #109 still returned OPEN, and there were no open PRs at
the time this continuation was written.

Branch `codex/issue109-gslb-runtime-evidence-ui` is preparing the next focused
PR. It adds a bounded, read-only GSLB metric parser and optional loopback scrape
on GatewayAgent, relays a fixed quorum/freshness snapshot over the existing
pinned mTLS connection, and displays that snapshot in the fleet page. Local
Release builds for GatewayAgent and Control Center passed with zero warnings;
the actual temporary-CA Kestrel mTLS integration passed, including rejection
of a malformed metrics contract; TypeScript compilation and 14 browser/UI
contract tests passed. Exact-head GitHub Actions are still required. The
metrics view is not a DNS query, authority agreement, durable report store or
production health check.

The one-hour 75-VU GitHub-hosted HTTP soak remains at
Actions run ID `44074344501`. At the latest query the run was still
`in_progress` and its job had no completion timestamp;
do not claim a completed soak until the workflow produces a final result and
artifact. Even if it passes, it is an L7 synthetic runner test, not annual
availability or physical gateway capacity acceptance.

The user's planned company test environment has more than ten mixed public and
private application servers behind a firewall. Required next product work
includes explicit HTTP and HTTPS upstream support, trustworthy client-IP
logging with UTC timestamps, operator dashboards/charts, and downloadable
customer reports. Client addresses must come from the socket peer or explicitly
configured trusted proxies; arbitrary forwarding headers are untrusted. DNSSEC
signing is a required capability and remains absent. These requirements are
not complete in this branch. Rolling annual 99.9% availability remains an
8h45m36s error budget objective whose production SLI is unmeasured; production
remains NO-GO pending DNSSEC, trust/quorum/fencing, real network/fault/capacity
acceptance, and an externally monitored annual period.

## Continuation — fleet metrics UI and access-log/report increment (2026-11-17)

PR #130 merged at `c43c9bfe29d7ae66ace24fcb2d9ac015b4375d44`. It adds a
bounded loopback GSLB metric scrape in GatewayAgent, relays a fixed quorum and
observer-freshness summary over pinned mTLS, and displays it in the Control
Center fleet page. The exact PR head passed all Actions, including full
Windows/Linux builds, UI/API, mTLS, HTTP, HA and load workflows. GitHub recorded
no independent review; this was a self-reviewed merge under the user's prior
authorization. It remains a per-node metric snapshot, not DNS validation,
cross-authority agreement or durable fleet telemetry. Issue #109 remains OPEN.

Branch `codex/issue50-access-logs-reports` is preparing a separate partial P1
observability PR from main `c43c9bf`. It adds structured per-request UTC access
events, uses the socket IP by default, accepts a single forwarded client IP
only when the immediate peer exactly matches `GATEWAY_TRUSTED_PROXY_IPS`, and
omits query strings, headers and bodies. It adds an authenticated metrics-page
latency histogram and Operator/Administrator JSON/CSV process-lifetime traffic
exports that intentionally contain no client IPs. Local Release build passed
with four pre-existing warnings; address-policy tests, UI compilation and 14
UI tests passed. HTTP/HTTPS destinations are already allowed by route
validation. This does not implement durable multi-node report retention or the
complete OpenTelemetry/Collector/Grafana acceptance for issue #50, which stays
OPEN. Exact-head Actions are pending.

The one-hour 75-VU HTTP run is tracked as Actions run ID `44074344501`; its
latest observed status was still in progress. Do not treat it as a completed
soak until its actual final result and artifacts are available. It is not
annual 99.9% availability or physical multi-gateway capacity evidence.

Current high-priority gaps remain: #36 physical independent gateway
VRRP/ECMP and capacity/fault acceptance; #52 DNSSEC signing/key lifecycle,
licensed GeoIP and complete authoritative acceptance; #109 distributed trust
quorum/fencing and independent partition acceptance; #50 central durable
OpenTelemetry, reports and monitoring. Rolling annual 99.9% has an
8h45m36s error budget but is still unmeasured; production remains NO-GO.

## Continuation — access evidence and opt-in DNSSEC signing (2026-11-17)

PR #131 merged at `a9d482bba2ff64a5c24f4c12abeaec02ff619622` from exact head
`f75e53a5bbfa35f8c7f9888ee16127e897388333`. All PR checks passed, including
Windows/Linux builds, real HTTP/HTTPS integrations, UI/API, HA and load checks.
The PR was self-reviewed under the user's prior authorization; GitHub showed no
independent review and main has no branch protection requiring one. Merged-main
Actions are running at this snapshot and must be checked before describing the
merge as fully verified on main.

The one-hour, 75-client, 1-KiB GitHub-hosted L7 soak completed successfully at
Actions run `44074344501`. It is synthetic runner evidence only; it does not
establish annual 99.9% availability, physical gateway capacity, or DNS
consensus.

Current branch `codex/issue52-dnssec-signing` is rebased on PR #131's main.
Source commit `836c6a8` adds opt-in per-zone
ECDSA P-256/SHA-256 (algorithm 13) signing from a separately provisioned PEM
key; DNSKEY/DS presentation, dynamic A/AAAA signatures, signed SOA/NS and NSEC
proofs for NODATA, NXDOMAIN, and unsigned child DS absence. Unsigned zones
retain their former no-fake-DNSSEC behavior. Windows Release build passed with
zero warnings; the full local GSLB acceptance suite passed; a separate
dnspython-based verifier validated DNSKEY, dynamic A over UDP/TCP, tamper
rejection, SOA/NSEC signatures and denial coverage. Exact-head Windows/Linux
GitHub Actions remain required after PR creation.

This is a bounded DNSSEC signing increment, not issue #52 completion. Parent
DS publication is manual, all authorities must be provisioned with the same
key/serial, and there is no automated KSK/ZSK/algorithm rollover, HSM/KMS,
child-zone signing or Windows ACL enforcement by the application. Public
resolver/parent-delegation interoperability, multi-authority signing and
failure/recovery acceptance remain open. #52 stays OPEN. #50 is also still
OPEN: PR #131 gives per-request logs, one local latency chart and process-life
JSON/CSV exports, but not central durable OTel/Grafana reports. #36 and #109
remain OPEN. Rolling annual availability remains unmeasured; production NO-GO.

## Continuation — merged DNSSEC verification and GeoIP/ECS routing (2026-11-17)

PR #132 merged at `b3740d2022762b3c50f28c956ba56fd9ab776fca`. Its merged-main
GSLB and L7 Actions runs `44087251727` and `44087251747` both completed with
`success` on that exact SHA. This confirms source CI, not public parent
delegation, DNSSEC rollover, multi-authority convergence or production DNS.

Current branch `codex/issue52-geoip-ecs` starts at that merge and adds opt-in
`RoutingPolicy="GeoIpEcs"` using operator-provided local MaxMind Country and/or
ASN MMDB files, explicit region maps, trusted-resolver ECS, a 45-day default
database freshness guard and privacy caps of IPv4 `/24` and IPv6 `/56`.
Database records more specific than the masked ECS network, conflicting
configured country/ASN routes, unknown/unmapped data, untrusted resolvers or
unhealthy regional targets do not steer or echo ECS. The existing weighted
policy remains the fallback. No client subnet is logged or retained. CI uses
only the small synthetic upstream test MMDB fixtures documented in
`tests/GslbAcceptance/testdata/README.md`; production data is not included.

Local Windows Release build passed with zero warnings and the full real-socket
GSLB acceptance suite passed, including country/ASN MMDB lookups, narrower
record fallback, ECS trust/privacy and DNS response behavior. Exact-head
Windows/Linux Actions and PR review are pending. This advances issue #52 but
does not close it: customer database licensing/update operations, real resolver
privacy/cache tests, independent parent delegation, multi-authority acceptance
and deployment operations remain open. #36 physical gateway acceptance, #109
distributed health trust/fencing and #50 durable centralized observability also
remain open. Annual 99.9% production availability remains unmeasured; production
NO-GO.

## Continuation — GeoIP merge and agent revocation acceptance (2026-11-17)

PR #133 merged at `84d099458095fe0db81a453c5a3c17a59b0f1c6c`. Exact-head
Windows/Ubuntu GSLB and L7/HA/load Actions were 9/9 successful. The post-merge
main GSLB and L7 Actions runs `44127248148` and `44127248295` both completed
successfully on that merge commit.

PR #133 adds opt-in MaxMind country/ASN GeoIP routing over allowlisted,
privacy-capped ECS, with explicit maps, freshness checking and safe weighted
fallback. It is a partial P0 #52 increment, not issue completion. Current
branch `codex/issue109-partition-fencing` starts at that merge and extends
Linux multi-process agent acceptance: with two client leaves revoked on one
DNS authority, the remaining single vantage stays below quorum and DNS stays
SERVFAIL; after removing the denylist and accepting fresh reports, that node
recovers. Existing tests already simulate two independent authorities and an
observer-feed partition. This remains GitHub-hosted simulation, not physical
network partition evidence or cross-node consensus. Exact-head Actions are
pending. #109, #36, #52 and #50 remain open; annual 99.9% availability is
unmeasured and production remains NO-GO.

## Continuation — two-region DNS evidence and OTLP access logging (2026-11-18)

PR #139 merged at `a4a2f0c189277b7ea34cee28fa2796ed4b8e46f4`. It fixes the
Collector acceptance workflow to build GatewayAgent before the full contract
suite; its merged-main Collector/Prometheus/Grafana run `44159280319` passed.

The user confirmed public IPv4 TCP and UDP port 53 is allowed on the Mumbai
(`15.252.99.51`) and Osaka (`15.152.85.231`) EC2 test hosts. A temporary
signed test zone was served by two independent DNS processes on those hosts.
Independent UDP/TCP queries verified DNSKEY and dynamic response signatures,
including negative answers. With Apache stopped in each region in turn, both
authorities returned only the other healthy destination, then returned both
destinations after recovery. Temporary DNS processes, private test key, files
and listeners were removed; both Apache services were restored and confirmed
active. This is short physical DNS failover/DNSSEC behavior evidence only. It
does not validate parent delegation/DS chain, key rollover, agent quorum or
cross-node fencing, VRRP/ECMP gateway HA, or annual availability.

PR #140 merged at `37aed719d3f4de3ae777cc601d562b4edb041425`. It adds opt-in
OTLP HTTP structured access logs with bounded SDK batching, UTC timestamp,
client IP/source, method, route, status and duration. URLs, headers, cookies
and bodies are omitted; trace client-address and URL redaction remains. The
loopback OTLP receiver and real Collector container acceptance verified the
logs and privacy checks. All 15 PR Actions runs passed on head
`b5c185fe738cf345dbe8342460fbb32337550bde`; the main-branch Collector run
`44198419113` also passed. GitHub recorded no independent reviewer; this merge
was self-reviewed under the user's prior authorization. The other post-merge
main checks were still running at handoff time.

Issue #52 had been marked closed while its full acceptance criteria remained
unmet, so it was reopened on 2026-11-17 with the remaining DNSSEC key lifecycle,
licensed GeoIP operations, zone-cut/interoperability, and multi-network/load/
chaos acceptance explicitly recorded. #50 remains open: durable centralized
retention, alert delivery, complete telemetry coverage, drop accounting,
performance overhead, parity and deployment evidence remain. #36 and #109 also
remain open for independent physical VRRP/ECMP capacity/fault testing and
complete authenticated health quorum/fencing respectively. Annual 99.9%
availability is still unmeasured; production remains NO-GO.


## Continuation — verified Alertmanager webhook delivery (2026-11-18)

PR #143 merged at `56c0f3d4dc0da2543138df16a7810654d6aa7e77`. It adds a
loopback-only Alertmanager service and bounded in-memory webhook receiver to
the disposable observability lab, plus an always-firing test-only Prometheus
rule. The exact-head CI confirmed Prometheus observed the firing alert and
Alertmanager delivered it to the receiver. Receiver contract tests, Compose
configuration, and the real Collector/Prometheus/Grafana/Alertmanager container
acceptance all passed at PR head `dfeb1f78a115b83c99aeab6eea71d17b2f597a2e`.
All reported PR checks passed, including Windows/Linux application, HA,
browser, and load acceptance. Post-merge main Actions were still running when
this entry was prepared.

This verifies test-stack alert delivery wiring only. The receiver is
non-durable and not a customer alert destination. Issue #50 remains OPEN for
the full metric inventory, drop/write-error accounting, absent-collector and
exporter-shutdown behavior, overhead measurement, production retention and
alert routes, and Windows/Linux parity. This does not prove production
monitoring or availability. Issues #36, #52 and #109 remain open for their
separate physical HA, public DNS/DNSSEC operations, and distributed trust/
fencing criteria. Production remains NO-GO; annual 99.9% availability remains
unmeasured.

## Continuation — live project status (2026-11-18)

**This section is the current operational snapshot and supersedes older “current state” statements above.** The earlier handoff sections remain a historical record; check live GitHub again before subsequent work.

- Canonical `main` at this update: `f792d797530e644ebd853e8e4f509f97d1757395`.
- Open feature PRs before this handoff refresh: **0**. The documentation refresh is being prepared in a focused PR.
- Open GitHub issues: **14**. #39 (future multi-tenant SaaS) and #61 (post-v1 Redis Sentinel) were closed as `NOT_PLANNED` for the declared single-organization on-prem v1 scope; neither feature is implemented or claimed.
- Release: controlled development/test only; **production NO-GO**. The annual 99.9% availability target is unmeasured and must not be inferred from CI or short fault tests.

### Recent merged increments

Exact-head Actions results are recorded on the PRs and listed below where applicable. Source-review work was performed during these tasks, but none of the merged PRs listed below had a GitHub review record at this snapshot; do not claim GitHub approval for those merges.

| PR | Merge commit | Verified contribution | Issue remains open because |
| --- | --- | --- | --- |
| [#147](../../pull/147) | `656929b899bada7d1d16837b82922c9b28001c66` | Async health-report/DNS private keys use no-follow, same-handle reads; Linux owner/mode/ancestor checks and Windows reparse-point protection. Exact-head Windows/Ubuntu GSLB and L7 runs 44352854173 / 44352854305. | #109 still needs validated authority/quorum, cross-authority fencing and multi-node partition acceptance; Windows ACLs remain deployment-managed. |
| [#142](../../pull/142) | `187b77d379cb2b3331dac38e7985551e1370d3e0` | One signed observer report fans out to 1–8 configured HTTPS authorities; independent replay stores and delivery isolation are tested with two local authorities. | #109 still needs cross-authority consensus/fencing, independent physical vantages and production partition acceptance. |
| [#149](../../pull/149) | `df6cad8e77ce8652994de93e138fa27162bdff4b` | Linux production-mode Data Protection key persistence and authentication-cookie continuity across a real process restart. Exact Actions passed Ubuntu and Windows. | #48 still needs representative Windows Server/Ubuntu/RHEL service, key recovery/rotation, tamper and fleet acceptance. |
| [#150](../../pull/150) | `984902dce7be66203be81e68c6c27065d39cf170` | Existing peer telemetry receipt TTL now uses monotonic elapsed time; rollback/expiry/replay tests passed and exact Actions passed. | #101 still lacks the typed bounded registry, durable delta/snapshot recovery, multi-peer/partition protocol, operations UI and physical soak. |
| [#151](../../pull/151) | `6d6d6559eb575e1dab981569b112e3156a7f120a` | Linux disposable-CA acceptance verifies production GatewayAgent rejects revoked and unavailable-CRL client certs before HTTP, with server-side chain-status evidence. | #35 still needs OCSP, broader chain cases, Windows, fleet rotation and enterprise/physical PKI acceptance. |
| [#140](../../pull/140) | `37aed719d3f4de3ae777cc601d562b4edb041425` | Opt-in structured OTLP access logs include UTC timestamp, client IP/source, method, route, status and duration; URL, headers, cookies and body are omitted. | #50 still needs full metric/drop contract, retention, alert delivery, overhead and deployment evidence. |
| [#143](../../pull/143) | `56c0f3d4dc0da2543138df16a7810654d6aa7e77` | Disposable loopback Alertmanager receiver and always-firing test rule prove Prometheus-to-Alertmanager webhook delivery in the container workflow. | #50 still needs production TLS/secrets, durable retention, customer routes, failover behavior, cross-platform deployment and overhead evidence. |
| [#148](../../pull/148) | `181f3eef7aa919a523c673c937f47cb53fa24774` | DNSSEC positive and negative answers are independently verified with dnspython, BIND and Knot clients over UDP/TCP. | #52 still needs parent delegation/DS, rollover operations, multi-authority convergence and public DNS qualification. |
| [#152](../../pull/152) | `85c4e3935b70f735b47983113c407598b9d1802a` | Unknown EDNS options are accepted safely and not echoed over UDP/TCP in GSLB acceptance. | #52 still needs full authoritative-zone/referral behavior, public resolver and multi-network/load qualification. |
| [#153](../../pull/153) | `d2ee934705837d09c5e261b191975901a16f72b0` | EDNS receive-size negotiation and UDP truncation/TCP retry are verified in acceptance. | #52 still needs delegation/DS, key lifecycle, licensed-data operations and public multi-authority qualification. |
| [#154](../../pull/154) | `18041189370f076e2260d4527ba87ceed0f1d944` | Windows signed-agent replay-state ACL and owner validation; exact policy assertions and regression tests protect state from unauthorized writers. | #109 still lacks cross-authority consensus/fencing and independent physical partition acceptance. |
| [#145](../../pull/145) | `374d75895a7e41cbe29b7fc3300e045912832384` | Opt-in per-destination in-flight/queue controls, cancellation/drain behavior, bounded telemetry cardinality, and applied-config-only monotonic policy reconciliation. Exact head `2b5679d0a68c3409a7d92e867a7b43919f7e6a47`; 37/37 Actions checks passed, including real Chromium and ten Windows HA repetitions. The preceding per-host 60-minute tests were loopback fixture-origin admission tests: Mumbai 39.575 req/s, Osaka 39.576 req/s, with zero test errors. | #100 still requires measured 500 Mbps-plus-headroom traffic, more protocol coverage and signed-config two-host physical acceptance. The EC2 soak did not measure site capacity or annual availability. |
| [#155](../../pull/155) | `b2fc026bd06186621c88c8afbabb0be5172a6cb1` | Existing opt-in P-256 DNSSEC signer reads the Linux key via the shared no-follow private-key loader. Run 44356773101 passed Windows+Ubuntu; Ubuntu ran DNSSEC crypto/BIND/Knot and unsafe-key tests. Windows signer Python acceptance passed locally; the existing Windows workflow did not run that Python step. | #52 still needs public delegation/DS lifecycle, key rollover/HSM operations, licensed-data operations and multi-authority qualification. |
| [#156](../../pull/156) | `92e4ba8f58a85543e565c9f9208c4092413b43ba` | Linux health-agent replay-state paths validate opened ancestors and reject unsafe writable/symlinked parents. Exact-head GSLB run 44359127825 and L7 run 44359127666 passed on Windows/Ubuntu; independent review found no blocker. | #109 still lacks cross-authority consensus/fencing and independent physical partition acceptance; Windows ACL enforcement remains deployment-managed. |
| [#158](../../pull/158) | `e251fc14d6897b643bace0d4a1feedcb9c6b4944` | OTLP span export removes raw URL/path/query/client-address tags and normalizes ASP.NET display names to safe method/route templates or method-only fallback. Real OTLP canary test and all 31 Actions checks passed; independent review found no blocker. | #50 still needs deployed Collector/alert delivery, retention, cross-node observability and production-overhead evidence. |
| [#157](../../pull/157) | `aebe451bd8568864b44c660dedab293b845858ea` | ECS partial-prefix host-bit validation and duplicate-option rejection; malformed ECS falls back to resolver-source routing and is not echoed. UDP/TCP acceptance covers IPv4 /25, IPv6 /57, duplicate options and canonical /25. Exact updated head `ab0bc9e5d1be7ccae8691a3d0f64104badee1a03`; 9/9 Actions checks passed and independent review found no blocker. | #52 still has DNS delegation, public resolver/cache/privacy, licensed GeoIP operations and multi-authority acceptance open. |
| [#159](../../pull/159) | `f93e55792ee7b326a2ac913ee782b9e174d7df26` | Bounded per-agent accepted-time/monotonic-age/freshness/rejection status through loopback-only DNS status and authenticated mTLS relay, rendered in the fleet UI. Exact head `b3ea5361ea43e08a45b8c19f21111775c58e1fa1`; 33 Actions checks passed on Windows/Ubuntu, including Chromium/UI and HA repeats; independent review found no blocker. | #109 still needs quorum/fencing, cross-authority consensus and independent multi-node partition evidence. The status view is not the authority protocol. |
| [#161](../../pull/161) | `1742fe3bb458a73be598bf810d51f1109919b50c` | Linux production GatewayAgent mTLS acceptance now also rejects expired (`NotTimeValid`) and unknown-CA (`PartialChain`) clients, logs the exact certificate status, and confirms valid-client recovery. Exact-head Actions passed, including Ubuntu/Windows builds and all Windows HA repeats. | #35 still needs OCSP, fleet-wide certificate rotation, Windows revocation runtime acceptance, and enterprise/physical PKI evidence. |
| [#162](../../pull/162) | `f792d797530e644ebd853e8e4f509f97d1757395` | WAF lab adds blocking-mode benign JSON, XML and ~31 KiB JSON upload cases through a private bounded backend that neither logs nor echoes bodies. WAF acceptance `44371139420` and all L7/HA/load checks passed. | #51 still needs representative OWASP false-positive/false-negative rates, pinned ruleset lifecycle/rollback, matched performance benchmarks and deployment evidence. |

PR #118 is also merged (merge commit `b7f8c0e0ddcfeb82b684aecce7eb92eb46a94fc2`): opt-in ECS routing behind trusted-resolver allowlists, IPv4 `/24` and IPv6 `/56` privacy caps, and configured MaxMind MMDB country/ASN lookups with deterministic fallback. This does **not** establish a licensed production database distribution, public resolver behavior, DNSSEC key lifecycle, or issue #52 completion. Do not describe GeoIP/ECS as absent; describe their exact opt-in and operational limits.

PR #108 is **closed without merge**, head observed as `931c8dfe4032271c8a9ae8e5b2dae1a14ef87a2c`; do not cite its observed-latency change as present in `main` unless separately reimplemented and merged.

### Current issue and production boundaries

The live backlog now has **14 open issues**, including P0 #36, #52 and #109 and P1 #100/#101/#50. #39 and #61 were closed as `NOT_PLANNED` because they are explicitly future/post-v1 and outside this release's scope; this is not feature completion. Merged PRs above complete component increments only; they do not satisfy whole-issue acceptance. Do not close the remaining issues without matching evidence in their current acceptance criteria.

- **#36 / physical ingress:** no shared VRRP VIP/ECMP gateway acceptance, signed-config convergence or separate-host power/network/partition drill has been completed. Prior dual-IP retry tests and the EC2 loopback admission soaks do not satisfy this issue.
- **#52 / GSLB:** ECS/MMDB routing and opt-in DNSSEC signing are present in source with lab/Actions evidence. Public parent delegation and DS validation, licensed GeoIP data lifecycle, independent-authority convergence, adversarial/scale qualification and operational key rollover remain open.
- **#109 / distributed health:** signed async reports, quorum checks, safe file handling and bounded operator visibility are present. Cross-authority consensus/fencing, production trust/enrollment and independent physical partition acceptance remain open.
- **#100 / admission:** per-destination local gates are merged. Shared/fleet-wide admission, full HTTP/2/gRPC/WebSocket characterization and measured site capacity remain open.
- **#50 / observability:** OTLP and Grafana CI integrations and safer span redaction are merged. A deployed monitoring/alert pipeline, retention and overhead comparison remain unverified.

Production remains **NO-GO**. No annual 99.9% availability measurement exists; a GitHub-hosted runner, one-hour fixture test or DNS protocol matrix cannot substitute for a year-long service SLI or the required site release drills.
