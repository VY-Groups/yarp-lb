# GatewayCore — 73-branch source audit (16 November 2026)

**Baseline:** `main` at `61b64a515a320b216bdb2e87085a87d16e74b29c`, before the subsequent opt-in PrimaryBackup feature PR #95 was created. **Scope:** the 73 branches returned by the authenticated repository API at audit start, including `main` and read-only `ha-praxy`. GitHub's `compare main...branch` metadata was checked for each GatewayCore branch, and representative feature source files and current `main`'s complete **304-file** git tree were inspected. (Ahead/behind numbers are historical snapshot data; this report is not a continuous branch sync.)

## Merge disposition

**No direct wholesale merge from the original 73 branches is approved.** Most are diverged historical snapshots because earlier PRs were squash-merged and later changes landed in main; even a positive `ahead` count can mean *already shipped content with different Git commit IDs*. Two CI branches are simple ancestors with zero ahead commits. The `ha-praxy` branch contains GPLv2-or-later HAProxy C sources and is strictly **read-only reference material**.

The current source tree already includes `RiseFallActiveHealthPolicy`, `AutonomousRecoveryObserver`, `RecoveryHealthGate`, Linux key-protection source, L4/GSLB standalone experimental engines, WAF CRS integration harness, peer telemetry, signed TLS Redis atomic quota and all major frontend pages. **Presence of a source path is not proof of feature parity or live production acceptance.** Do not backport an old copy of `Program.cs` or any old workflow: it could undo the recent security hardening, onboarding improvements, code contracts or CI evidence.

**New safe, additive port chosen:** [PR #95](https://github.com/VY-Groups/yarp-lb/pull/95) provides opt-in `PrimaryBackup` routing with backend role settings, management UI and real L7 fault tests. That feature is authored independently on current main; it is **not** a merge of HAProxy GPL sources or a promise of physical HA. Production gating still applies.

## Branch-by-branch comparison

**Ahead/behind**: GitHub commit-graph counts for `main...branch`, **not** a count of missing features.

| Branch | Ahead | Behind | Safe disposition |
| --- | ---: | ---: | --- |
| `ci/combined-pr31-pr32-all-gates-20261114` | 2 | 36 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `ci/l7-acceptance` | 0 | 60 | Ancestor of main; no merge |
| `ci/soak-onehour-0.1` | 16 | 31 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `ci/soak-onehour-issue17-shared` | 0 | 40 | Ancestor of main; no merge |
| `ci/verify-merged-ec2-pr32-all-gates-20261114` | 2 | 36 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `ci/windows-ha-ten-run-followup-20261114` | 1 | 37 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `docs/enterprise-operator-uat-20261115` | 1 | 4 | Documentation now in main or superseded; targeted copy only |
| `docs/root-readme-test10-acceptance-20261114` | 1 | 23 | Documentation now in main or superseded; targeted copy only |
| `feat/mail-provider-oauth-and-security-gates-20261114` | 16 | 22 | Older feature work already integrated or superseded; review individual files only |
| `feature/active-health-rise-fall-20261115` | 12 | 18 | Opt-in health/recovery source present in main; keep improved modern implementation |
| `feature/active-health-rise-fall-rebased-20261115` | 11 | 17 | Opt-in health/recovery source present in main; keep improved modern implementation |
| `feature/agent-client-auth-negative-tests-20261114` | 2 | 44 | Older feature work already integrated or superseded; review individual files only |
| `feature/autonomous-yarp-recovery-watch-20261115` | 16 | 18 | Opt-in health/recovery source present in main; keep improved modern implementation |
| `feature/bounded-traffic-recovery-20261115` | 15 | 20 | Older feature work already integrated or superseded; review individual files only |
| `feature/ci-failover-load-runtime-profiling` | 3 | 56 | Older feature work already integrated or superseded; review individual files only |
| `feature/ci-security-tls-benchmark-0.1` | 11 | 57 | Older feature work already integrated or superseded; review individual files only |
| `feature/control-center-0.1-full-source` | 2 | 59 | Older feature work already integrated or superseded; review individual files only |
| `feature/ec2-functional-control-center-actions-20261114` | 21 | 38 | Older feature work already integrated or superseded; review individual files only |
| `feature/ec2-real-control-center-rebased-20261114` | 13 | 37 | Older feature work already integrated or superseded; review individual files only |
| `feature/enterprise-ui-shell-login-navigation-20261115` | 13 | 8 | Older feature work already integrated or superseded; review individual files only |
| `feature/experimental-distributed-quota-20261115` | 7 | 14 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/experimental-gslb-authoritative-dns` | 4 | 52 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/experimental-l4-tcp-udp-engine` | 3 | 52 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/gslb-safe-all-down-fallback-20261114` | 8 | 49 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/ha-passive-health-graceful-drain` | 2 | 55 | Older feature work already integrated or superseded; review individual files only |
| `feature/haproxy-reference-baseline-20261115` | 4 | 20 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue17-console-backpressure-fix-20261114` | 4 | 45 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue17-hang-watchdog-20261114` | 9 | 49 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `feature/issue17-observable-onehour-20261114` | 1 | 38 | Historical CI/soak experiment; avoid reintroducing old workflow |
| `feature/issue23-bounded-ejection-safe-failover-20261114` | 23 | 40 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue23-safe-ejection-rebased-20261114` | 21 | 38 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue24-allocation-characterization-20261114` | 12 | 40 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue26-lab-ca-certificate-rotation-20261114` | 12 | 40 | Older feature work already integrated or superseded; review individual files only |
| `feature/issue40-ha-process-heartbeats-20261114` | 23 | 34 | Older feature work already integrated or superseded; review individual files only |
| `feature/l4-health-drain-idle-proxy-v1-20261114` | 5 | 49 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/l7-drain-warmup-telemetry` | 10 | 58 | Older feature work already integrated or superseded; review individual files only |
| `feature/linux-secure-dp-onprem-20261114` | 7 | 33 | Linux key-protector source in main; maintain issue #48 for physical key lifecycle |
| `feature/linux-secure-dp-rebased-20261114` | 7 | 32 | Linux key-protector source in main; maintain issue #48 for physical key lifecycle |
| `feature/linux-sigterm-graceful-acceptance` | 2 | 53 | Older feature work already integrated or superseded; review individual files only |
| `feature/owasp-crs-waf-ci-integration` | 4 | 52 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/peer-state-hmac-20261115` | 8 | 12 | Main already has peer/Redis source; no strict HAProxy table-parity claim |
| `feature/product-nonblocking-log-observability-20261114` | 7 | 44 | Older feature work already integrated or superseded; review individual files only |
| `feature/secure-engine-staging-20261114` | 15 | 49 | Older feature work already integrated or superseded; review individual files only |
| `feature/shared-gateway-logger-soak-20261114` | 14 | 41 | Older feature work already integrated or superseded; review individual files only |
| `feature/soak-failfast-sustained-slo-20261114` | 6 | 49 | Older feature work already integrated or superseded; review individual files only |
| `feature/soak-p99-timeline-analysis` | 1 | 54 | Older feature work already integrated or superseded; review individual files only |
| `feature/tailnet-two-runner-failover-20261115` | 11 | 11 | Older feature work already integrated or superseded; review individual files only |
| `feature/two-ubuntu-capacity-evidence-20261115` | 10 | 12 | Older feature work already integrated or superseded; review individual files only |
| `feature/waf-corpus-detection-body-20261114` | 5 | 49 | Experimental engine/lab exists in main; incomplete customer acceptance, DO NOT wholesale merge |
| `feature/0.1-laptop-development-kit` | 2 | 57 | Older feature work already integrated or superseded; review individual files only |
| `fix/customer-ui-brand-consistency-20261115` | 3 | 4 | Older bugfix snapshot; main contains newer merged fix |
| `fix/ec2-ci-prerequisite-gating-20261115` | 6 | 16 | Older bugfix snapshot; main contains newer merged fix |
| `fix/health-admission-passive-observer-20261115` | 15 | 15 | Opt-in health/recovery source present in main; keep improved modern implementation |
| `fix/issue40-harness-threadpool-bounded-20261114` | 1 | 33 | Older bugfix snapshot; main contains newer merged fix |
| `fix/operator-session-hygiene-readiness-20261115` | 12 | 6 | Older bugfix snapshot; main contains newer merged fix |
| `fix/peer-epoch-resync-20261115` | 3 | 7 | Main already has peer/Redis source; no strict HAProxy table-parity claim |
| `fix/peer-snapshot-bounds-ops-20261115` | 5 | 8 | Main already has peer/Redis source; no strict HAProxy table-parity claim |
| `fix/peer-time-bound-overflow-20261115` | 2 | 10 | Main already has peer/Redis source; no strict HAProxy table-parity claim |
| `fix/retired-ec2-schedule-ci-20261116` | 9 | 2 | Older bugfix snapshot; main contains newer merged fix |
| `fix/windows-ha-ten-artifact-evidence-20261116` | 4 | 1 | Older bugfix snapshot; main contains newer merged fix |
| `fix/zoho-preset-real-browser-20261114` | 8 | 25 | Older bugfix snapshot; main contains newer merged fix |
| `ha-praxy` | - | - | READ ONLY / GPL: architecture reference, never merge |
| `main` | 0 | 0 | Baseline; do not merge into itself |
| `ops/onprem-production-gates-20261114` | 61 | 31 | Old broad integration/refactor; merging would revert later independent fixes |
| `refactor/neutral-gateway-branding-20261114` | 69 | 30 | Old broad integration/refactor; merging would revert later independent fixes |
| `release/windows-e2e-tested-test8-20261114` | 1 | 28 | Already-used historical prerelease branch; never replay version bump |
| `release/windows-mail-provider-test11-20261114` | 3 | 21 | Already-used historical prerelease branch; never replay version bump |
| `release/windows-mail-provider-test12-20261114` | 1 | 20 | Already-used historical prerelease branch; never replay version bump |
| `release/windows-mailkit-zoho-india-test9-20261114` | 1 | 26 | Already-used historical prerelease branch; never replay version bump |
| `release/windows-zoho-preset-test10-20261114` | 1 | 24 | Already-used historical prerelease branch; never replay version bump |
| `test/external-integration-acceptance-20261114` | 22 | 27 | Older acceptance harness; current main retains latest tests |
| `test/real-end-to-end-acceptance-20261114` | 10 | 29 | Older acceptance harness; current main retains latest tests |
| `test/shared-quota-two-gateways-tls-20261115` | 9 | 13 | Main already has peer/Redis source; no strict HAProxy table-parity claim |

## HAProxy 3.4 capability review: prioritized low-regression roadmap

Reference material: official [HAProxy 3.4 configuration manual](https://docs.haproxy.org/3.4/configuration.html) and read-only `ha-praxy` `src/peers.c`, `src/stick_table.c` (GPL). Independent clean-room managed code only; no copy/paste of licensed C internals.

| HAProxy behavior | GatewayCore as audited | Safe next step | Qualification |
| --- | --- | --- | --- |
| Active checks with distinct `rise`/`fall` | Source + lab tests exist | Preserve; add richer health telemetry and invalid-probe behavior | Windows/Linux state, path and recovery tests |
| Backup server designation / first backup only | **New opt-in PR #95**, not in baseline main | Use new `PrimaryBackup` policy, preserve old defaults | L7 real HTTP, failback, no retries, all-down 503 |
| Graceful drain and slow-start | Existing implementation | Extend long-lived stream + rolling restart regression | Real socket EOF/SIGTERM and application ACK |
| Connection/backlog admission `maxconn`, per-server queue | Local process concurrency limiter and FIFO admission only | Design bounded **per-backend** pending queue, cancellation and upstream timeout | Overload, queue starvation, fair cancel, p99 and RAM |
| HAProxy peers and stick-table `expire`, rate counters, data fields, teaching stages | Two-node signed best-effort request-counter gossip only | Versioned typed table registry; bounded TTL, delta/backfill and restart teaching without exposing strict quotas | Split-brain/replay/clock-skew, ordered cold-start multi-peer tests |
| Backup/agent health and operator state toggles | Active/passive health and drain controls, no complete agent-check | Add opt-in authenticated external agent signal, strict expiry and explicit manual maintenance | Poisoning, stale health and policy fail-safe |
| Session affinity during topology changes | Source IP hash and YARP affinity | Constrain cookie key lifecycle, health-aware sticky failover | Restart/rotation, SNAT and no non-idempotent replay |
| HTTP abuse defenses, ACL and WAF | Reverse proxy checks and optional external WAF lab | Bounded rule lifecycle, ModSecurity/CRS integration validation | Benign+malicious labeled corpus, false positives and TLS/HTTP2 |
| PROXY protocol / trusted client address | Some L4 handling; public L7 must not trust spoofed XFF | Explicit trusted-ingress allowlist (no global proxy-header trust) | IPv4/IPv6 spoofing, mTLS and proxy chain |
| Runtime stats interface, monitoring and alerts | Admin metrics, limited Prometheus alert samples | OTLP bounded exporter, Grafana dashboards and low-cardinality failure-window metrics | Collector outages, no synchronous logging in data plane |
| GSLB, authoritative DNS + geo health | Experimental standalone DNS engine | NS/SOA, TCP fallback, EDNS0 and health-aware DNS | RFC response corpus, dual-authoritative nodes, amplification tests |

**Non-negotiable:** full HAProxy peers wire compatibility and full HAProxy stick-table parity remain NOT IMPLEMENTED. Linux key-protection code does not mean customer KMS/HSM lifecycle and recovery are accepted. A successful two-container/shared-host CI run is not a physical on-prem capacity, switch, or network-partition test.

## Future branching rule

Start each change from the current `main`; pick the smallest independently tested feature, preserve public API/backward-compatible settings, and use an explicit opt-in name with a safe default. Enforce exact-head Windows/Linux source, Chromium management E2E, security, L7 and ten-run Windows HA gates before merging. Record the implementation's remaining environmental acceptance separately. Never force merge a historical branch, use unchecked GitHub `mergeable` alone as evidence, or change a failing CI test threshold to make it green.
