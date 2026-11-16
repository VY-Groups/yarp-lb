# GSLB enterprise capability map — evidence first

Source of comparison: user-supplied OpenGSLB feature matrix and the *reference*
`gslb` branch at `48f020c3f0d7d3d353485c9a0d701061a3014c08`
(OpenGSLB Go v1.1.10). GatewayCore baseline after PR #103:
`6c2c6da4ad38586dbb0cef396d05dfda2b3cb5be`.

The matrix compares desired **features**, NOT commercial/product certifications,
vendor prices, security guarantees or claims that other providers lack a feature.
Source code, reference documentation and isolated CI do not establish real-world
performance. No AGPL OpenGSLB source is incorporated.

| Requested capability | GatewayCore status in this branch | Release gap / falsifiable acceptance |
| --- | --- | --- |
| Self-hosted data sovereignty | On-prem .NET DNS prototype | Two independent gateway hosts, network/privacy audit |
| No vendor lock-in | Independent source/runtime design goal | Dependency/license inventory, reproducible image builds |
| Authoritative DNS A/NS/SOA/EDNS/TCP | Limited lab implementation | Zone cut/delegation, conformance, transport, fuzz, DNSSEC |
| DNS AAAA / IPv6 | **New lab implementation; CI required** | IPv6 listener and NS glue, real dual-stack probes and public resolvers |
| Weighted traffic selection | Existing opt-in per-zone selection | Predictable fairness under health churn, matched load |
| Ordered primary/standby failover | Existing opt-in `RoutingPolicy=Failover` | DNS caching, DR state, physical failover behavior |
| Weighted failover *chains* | Not implemented | Multiple weighted priority groups, stable tie/drain policy and tests |
| GeoIP and CIDR routing | Not implemented | Licensed versioned dataset, deterministic longest-prefix, stale-data policy |
| Latency / RTT selection | Not implemented | Per-vantage measured RTT, min sample, timeout, bounded EMA and rollback |
| EDNS Client Subnet (ECS) | EDNS parsed; ECS **ignored** | Explicit opt-in/allowlist, privacy minimization, valid prefix/data and cache scope |
| Predictive health | Not implemented | Evidence-based confidence, false predictions, strict safety policy |
| Agent-side failure prediction | Not implemented | Signed agent identity, replay/freshness, bounded metric flow, external validation |
| External health validation | Local HTTP(S)/TCP probing only | Independent geographic quorum and application-specific readiness |
| DNSSEC | Not implemented | Signed zones, DS workflow, RFC conformance, key rotation and recovery |
| GSLB server-management API | Static startup JSON only | RBAC, strong schema, signed revisions, staged rollout and rollback |
| Agent gossip / health-state sync | Not implemented for DNS | mTLS/signed frames, version/epoch/fencing, quorum/partition fault tests |
| Observability | Gateway metrics exist; GSLB-specific incomplete | Cardinality-bounded DNS/health decisions, trace/alert tests |
| Configuration reload | Requires engine restart | Atomic validated revision swap, no dropped queries, rollback |
| Annual cost / setup effort | Not a software capability certification | Real BOM/TCO and deployment reproducibility study |

## Mandatory quality bar for every independent enhancement

1. Design/defaults: opt-in for new policies, validate invalid input at startup,
   preserve legacy A, weighted distribution, DNS flags and all-down semantics.
2. Correctness: tests for wrong type/class, IPv4/IPv6 separation, no-data
   negative-cache SOA, retries, malformed packets and zone boundaries.
3. Availability: explicit stop/drain, cancel/timeout, high cardinality and
   bounded memory; fail-closed when CA/signing readiness is not provable.
4. Security: no secrets in configs/logs, no untrusted ECS routing, authenticated
   signed state and least-privilege local listeners.
5. Evidence: Windows and Linux real-socket CI, real dig/kdig interoperability,
   multi-network DNS cache behavior and 60-minute physical capacity/chaos.
6. Release: security/PKI approval and independently reported GO/NO-GO;
   never close P0 #52 or #36 based on an isolated feature test.

## Suggested implementation sequence (independent .NET)

**P0: baseline DNS correctness** — protocol interop, strict zone cuts,
resource-record families, serial lifecycle, negative responses, IPv6
transport and controlled DNSSEC policy. Harden EDNS and anti-reflection.

**P0: physical HA / transaction safety** — two independent authoritative
instances, signed config reconciliation, bounded state age, independent
health vantage points, partitions/split brain, no replay of CA actions.

**P1: routing intelligence** — explicit region/CIDR + licensed GeoIP;
privacy-preserving ECS behind resolver trust config; weighted priority
chains, latency EMA from external probes, deterministic fallbacks.

**P1: management and monitoring** — dynamic CRUD behind RBAC/approvals,
immutable audit sinks, atomic config snapshots, native DNS metrics,
Grafana dashboards, safe reload/rollback and clear operator health states.

**P1: prediction and agents** — agents initially **advisory only**;
authenticated telemetry and cross-validation, staleness/false prediction
metrics, no unilateral drop of signing backends from untrusted ML signals.

**P2: broader service protocols and upgrades** — DoT/DoH, multi-zone
transfers/NOTIFY/TSIG if architecture and operating model require them.

## Licensing and provenance

The new reference branch explicitly specifies
`AGPL-3.0-or-later OR LicenseRef-OpenGSLB-Commercial`.
Copying *part* of its code can still trigger license obligations.
If direct reuse is desired, obtain an appropriate license or follow all
applicable AGPL terms after legal review. This project uses independently
written .NET functionality; no Go module or OpenGSLB source was copied.
Commercial readiness cannot be inferred from the source README or a table.
