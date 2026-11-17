# GSLB enterprise capability map — evidence first

Source of comparison: user-supplied OpenGSLB feature matrix and the *reference*
`gslb` branch at `48f020c3f0d7d3d353485c9a0d701061a3014c08`
(OpenGSLB Go v1.1.10). GatewayCore base `main`:
`8d6e09289daf0ebedae18bf8f581f013ffa7af84`. The current branch enforces
RFC 1982 SOA serial advances on changed existing authoritative zones during
signed GatewayAgent staging; it does not automate serial generation.

The matrix compares desired **features**, NOT commercial/product certifications,
vendor prices, security guarantees or claims that other providers lack a feature.
Source code, reference documentation and isolated CI do not establish real-world
performance. No AGPL OpenGSLB source is incorporated.

| Requested capability | GatewayCore status in this branch | Release gap / falsifiable acceptance |
| --- | --- | --- |
| Self-hosted data sovereignty | On-prem .NET DNS prototype | Two independent gateway hosts, network/privacy audit |
| No vendor lock-in | Independent source/runtime design goal | Dependency/license inventory, reproducible image builds |
| Authoritative DNS A/NS/SOA/EDNS/TCP | Limited lab implementation; merged child-cut referrals, authority flags, in-bailiwick glue, two-authority observer-feed partition checks, finite malformed UDP/TCP corpus, and a staged-config RFC 1982 serial-increment guard | Full delegation conformance, automatic serial generation, fuzz/load, DNSSEC and independent resolver acceptance |
| DNS AAAA / IPv6 | Merged lab implementation; Windows/Linux acceptance exists | IPv6 listener and NS glue, real dual-stack probes and public resolvers |
| Weighted traffic selection | Existing opt-in per-zone selection | Predictable fairness under health churn, matched load |
| Ordered primary/standby failover | Existing opt-in `RoutingPolicy=Failover` | DNS caching, DR state, physical failover behavior |
| Weighted failover *chains* | Merged opt-in `WeightedFailover` with weighted healthy priority groups | DNS cache behavior and physical DR evidence; this branch adds static maintenance quarantine, not a live drain API |
| GeoIP and CIDR routing | Merged explicit resolver CIDR longest-prefix with lab acceptance; **licensed GeoIP still missing** | Resolver/source semantics, GeoIP dataset licensing/version, stale-data policy and real geo tests |
| Latency / RTT selection | Merged `ObservedLatency` policy uses local backend probe elapsed time; it is not client RTT | Per-vantage observations, calibrated policy, timeout and rollback; never infer client RTT from server probes |
| EDNS Client Subnet (ECS) | Optional zone opt-in over allowlisted recursive resolver CIDRs and explicit region routes; source capped at IPv4 `/24` and IPv6 `/56`; ambiguous prefixes ignored | Production privacy review, RFC vectors, independent resolver and cache tests |
| Predictive health | Not implemented | Evidence-based confidence, false predictions, strict safety policy |
| Agent-side failure prediction | Not implemented; signed async health reports are evidence, not prediction | Calibrated advisory model with false-positive/negative, drift and rollback evaluation |
| External health validation | Local HTTP(S)/TCP probes plus optional signed async observer reports and synchronous external validators; each DNS process evaluates its own quorum; this branch tests independent nodes under an observer-feed partition | Authority precedence, application-specific readiness, node-to-node fencing/consensus and independent deployment acceptance |
| DNSSEC | Unsupported policy is explicit: DO=1 DS/RRSIG/DNSKEY queries return unsigned NODATA without AD or fabricated signatures; DO is not advertised in OPT | Signed zones, DS workflow, RFC conformance, key rotation and recovery |
| GSLB server-management API | Static startup JSON only; this branch adds a static operator quarantine veto | RBAC, strong schema, signed revisions, live staged rollout and rollback |
| Agent gossip / health-state sync | Signed report fan-in is per DNS node; there is no DNS-node gossip or shared consensus | Versioned cross-node state, fencing and partition fault tests |
| Observability | Gateway metrics/logging plus opt-in loopback GSLB metrics, Prometheus alerts and Grafana import; no OTel tracing/Collector pipeline | OTel trace/export/backpressure, deployed collector/Grafana, overhead and retention evidence |
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
