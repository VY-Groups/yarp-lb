# OpenGSLB reference review — source inventory and independent GatewayCore delta

**Reviewed:** user-updated `gslb` branch commit
`48f020c3f0d7d3d353485c9a0d701061a3014c08` on 2026-11-16.
**Comparison:** GatewayCore `main` baseline
`cb0b1c54c5d410fda07064605aed0f96cc8d9570`.

The former `gslb` reference was Polaris (Python/PowerDNS, BSD-3-Clause).
It has been replaced by Logan Ross's **OpenGSLB v1.1.10** (Go).
The exact new branch includes the source and examples below; it is a distinct
product, not a compatible GatewayCore engine.

## Licensing boundary (critical)

`gslb:LICENSE` and Go SPDX headers: **AGPL-3.0-or-later OR
LicenseRef-OpenGSLB-Commercial**. The reference README says commercial
licensing is available. The user intends a commercial enterprise ADC.
This review is for architecture and behavior only; no OpenGSLB code,
algorithms verbatim, source files, test fixtures, or Go dependencies were
copied into the .NET repo. Do not merge the `gslb` branch into `main`.
Distribution, remote-service and derivative-work obligations require legal
review if direct reuse is ever contemplated.

## Reviewed components (source, not README assertions alone)

| Reference file | Observable architecture | GatewayCore status |
| --- | --- | --- |
| `pkg/dns/handler.go`, `pkg/dns/server.go` | DNS A/AAAA answers and UDP/TCP transport | .NET UDP/TCP with A, NS, SOA; no health-aware AAAA/DNSSEC |
| `pkg/routing/failover.go`, `pkg/routing/weighted.go` | Explicit ordered failover, weighted selection | Independent opt-in `Failover` and unchanged default `Weighted` |
| `pkg/overwatch/validator.go`, `pkg/overwatch/registry.go` | Health-validation authority and backend state | Local HTTP polling only, new bounded success/failure hysteresis |
| `pkg/routing/geo.go`, `pkg/routing/latency.go` | Geo routing and latency preferences | NOT IMPLEMENTED; don't infer client location |
| `pkg/overwatch/gossip.go`, `pkg/overwatch/agent_auth.go` | Agent/overwatch state exchange | NOT IMPLEMENTED; no unsigned agent health admitted to DNS |
| `pkg/dnssec/keys.go`, `pkg/dnssec/signer.go` | DNSSEC key and signing workflows | NOT IMPLEMENTED |
| `pkg/api/routing_handlers.go` | API-based DNS policy updates | NOT IMPLEMENTED; local static JSON config only |
| `CHANGELOG.md` 1.1.10 | Validation failure/success thresholds, health authority | Independently reproduced local rise/fall semantics, not quorum |

The reference README advertises additional production capabilities; those
claims are **not** proof of correctness or acceptance of this separate project.
No Go binaries were executed during this comparison.

## Implemented here (incremental / safe defaults)

1. A **new opt-in** DNS `RoutingPolicy="Failover"`, selecting the
   lowest priority configured healthy site with deterministic tie order,
   automatically preferring primary again after successful health recovery.
   No existing Weighted cluster or L7 YARP behavior is modified.
2. Per-zone `FailureThreshold` and `SuccessThreshold`, each 1–10,
   defaulting to 1 to retain legacy behavior. Consecutive-probe state is
   local and published through the existing volatile health indicator.
3. Input validation prevents unknown policies/oversized priorities and
   out-of-range probe thresholds from silently changing behavior.
4. Lab tests cover pure transition logic, real DNS A failover, all-down
   SERVFAIL on strict zone, recovery and unchanged weighted distribution.
5. Documentation states strict limitations, including cached TTL responses.

## Threat model / remaining release gates

- No DNSSEC, TSIG, signing or authenticated multi-site state snapshots;
  no split-brain partition fencing or independent health-vantage quorum.
- Single local probe origin; an isolated DC may misjudge DR readiness.
  Health URL must be application-specific and must not be treated as a
  transactional signing/PKI correctness guarantee.
- DNS 5–300s TTL and client caching mean DNS answer changes do not cause
  immediate failover at the connection layer.
- No IPv6 AAAA GSLB, licensed GeoIP/ASN database, ECS client privacy controls,
  DDoS edge shield, or DNS zone-cut/referral conformance suite.
- Benchmark matched direct/other-GSLB baseline, fuzz malformed EDNS/DNS
  packets, resolve from independent public and private network vantage
  points, verify multi-NS SOA convergence, serial lifecycle and physical
  failures. **Issue #52 and issue #36 remain P0 / open.**
- New GSLB tests do not certify the rest of the GatewayCore management UI
  or production 500 Mbps ingress. Do not promote until independent HA,
  throughput, security and failover runbooks are actually accepted.

No unqualified production-readiness claim follows from GitHub CI.
