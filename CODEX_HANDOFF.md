# GatewayCore — Codex handoff, verified repository snapshot

**Snapshot date:** 2026-11-16 (UTC; refresh all live status before acting)  
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
remains NOT PERFORMED. Treat 99.9% as an availability target pending its precise
SLI/window definition, never as a correctness guarantee. Source parity, DNSSEC,
signed agent authority/quorum/partition fencing, GeoIP/ECS, calibrated prediction
and remaining P0/P1 operational evidence remain incomplete. Production NO-GO.

## Continuation — annual objective, GSLB observability and quarantine (2026-11-17)

Current `main` is `b19cb7cd187959dd6ced17701afda14d5b0127be`; PR #121 merged
opt-in loopback-only GSLB metrics, bounded Prometheus alerts, synthetic alert
fixtures and an importable Grafana dashboard. Its exact-head Windows/Linux,
Prometheus, application and integration Actions passed. This was a Codex
code-review and CI merge; GitHub had no independent review recorded and no
branch protection requirement was configured.

The 99.9% objective is rolling 365 days (8h 45m 36s maximum error budget), not
30 days. `control-center/docs/AVAILABILITY_SLO.md` records a provisional
independent-failure model and monitoring contract. Those modeled numbers are
assumptions, not observed production availability; the SLI remains unknown
until an externally monitored service and sufficient annual probe coverage
exist. Do not report the objective as achieved or production GO.

Current feature branch `codex/issue109-partition-acceptance` adds
`AdministrativelyQuarantined` as a static per-site configuration veto. It
overrides healthy local probes and signed reports, including when legacy
availability-first fallback is configured; the site remains probed for
diagnostics. The setting requires configuration reload by process restart and
is not a live management API. Windows/Linux real DNS acceptance covers
withdrawal and failover behavior. This is only one authority-precedence item.

At this snapshot, open P0 issues #36, #52 and #109 remain open. #109 still needs
cross-authority partition fencing/consensus, dynamic operator trust/evidence
management and independent multi-node partition acceptance. #52 still needs
DNSSEC, delegation/zone-cut conformance, licensed GeoIP/ASN data and broader
resolver/load/chaos acceptance. #36 still needs independent gateways behind
VRRP/ECMP and capacity/fault acceptance. Other P0/P1 issues also remain open;
refresh the live GitHub issue list before the next action. Availability SLO,
CI and static quarantine are not substitutes for these gates.
