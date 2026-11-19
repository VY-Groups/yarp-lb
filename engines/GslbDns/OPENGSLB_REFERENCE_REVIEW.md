# OpenGSLB reference review — source inventory and independent GatewayCore delta

**Reviewed:** user-updated `gslb` branch commit
`48f020c3f0d7d3d353485c9a0d701061a3014c08` on 2026-11-16.
**Comparison:** GatewayCore `main` baseline
`cb0b1c54c5d410fda07064605aed0f96cc8d9570`.

The former `gslb` reference was Polaris (Python/PowerDNS, BSD-3-Clause).
It has been replaced by Logan Ross's **OpenGSLB v1.1.10** (Go).
The exact new branch includes the source and examples below; it is a distinct
product, not a compatible GatewayCore engine.

## Historical licensing review (2026-11-16)

`gslb:LICENSE` and Go SPDX headers: **AGPL-3.0-or-later OR
LicenseRef-OpenGSLB-Commercial**. The reference README says commercial
licensing is available. The user intends a commercial enterprise ADC.
At the time of this review, no OpenGSLB code, source files, test fixtures, or
Go dependencies had been copied into the .NET repo. The no-copy decision below
describes that historical review and is superseded only by the narrow,
user-authorized NSEC3 hash adaptation recorded here. Do not merge the `gslb`
branch into `main`.

## Subsequent licensing and NSEC3 update (2026-11-19)

The user explicitly authorized reuse under AGPL-3.0-or-later on 2026-11-19.
The dedicated `codex/issue52-nsec3-denial` change adds root `LICENSE` under
AGPL-3.0-or-later, applying the license to the repository as a whole, and
adds `THIRD_PARTY_NOTICES.md`. It adapts only the canonical name + salt SHA-1
rounds and base32hex encoding from `pkg/dnssec/nsec3.go`, preserving Logan
Ross's 2025 copyright and the original
`AGPL-3.0-or-later OR LicenseRef-OpenGSLB-Commercial` SPDX notice. GatewayCore
uses the AGPL option. The original OpenGSLB synthetic NXDOMAIN/NODATA proof
generation is not used; GatewayCore builds an RFC 5155 hash ring from its own
authoritative names and derives closest-encloser, next-closer, wildcard, and
exact-owner denial proofs from that ring. NSEC remains the default.

The license and attribution change is project-wide and has legal/distribution
consequences beyond the DNSSEC engine. Issue #52 remains open pending its full
criteria and deployment/public-authority evidence; this implementation is a
bounded software increment, not production readiness.

## Reviewed components (source, not README assertions alone)

| Reference file | Observable architecture | GatewayCore status |
| --- | --- | --- |
| `pkg/dns/handler.go`, `pkg/dns/server.go` | DNS A/AAAA answers and UDP/TCP transport | Independent .NET UDP/TCP with A, NS, SOA, health-aware AAAA, and opt-in signed zones |
| `pkg/routing/failover.go`, `pkg/routing/weighted.go` | Explicit ordered failover, weighted selection | Independent opt-in `Failover` and unchanged default `Weighted` |
| `pkg/overwatch/validator.go`, `pkg/overwatch/registry.go` | Health-validation authority and backend state | Local HTTP polling only, new bounded success/failure hysteresis |
| `pkg/routing/geo.go`, `pkg/routing/latency.go` | Geo routing and latency preferences | NOT IMPLEMENTED; don't infer client location |
| `pkg/overwatch/gossip.go`, `pkg/overwatch/agent_auth.go` | Agent/overwatch state exchange | NOT IMPLEMENTED; no unsigned agent health admitted to DNS |
| `pkg/dnssec/keys.go`, `pkg/dnssec/signer.go` | DNSSEC key and signing workflows | Independent opt-in P-256/SHA-256 DNSKEY, RRSIG and NSEC signer; parent DS/rollover lifecycle remains incomplete |
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

- No TSIG or DNS-node consensus; static DNSSEC keys have no automated rollover,
  HSM/KMS integration or public parent-delegation acceptance. No split-brain
  partition fencing or independent health-vantage quorum.
- Single local probe origin; an isolated DC may misjudge DR readiness.
  Health URL must be application-specific and must not be treated as a
  transactional signing/PKI correctness guarantee.
- DNS 5–300s TTL and client caching mean DNS answer changes do not cause
  immediate failover at the connection layer.
- Trusted-resolver ECS and local MMDB country/ASN
  routing are implemented in the lab; independent public delegation,
  customer database licensing/update operations, multi-authority and resolver
  cache acceptance remain open. There is no DDoS edge shield.
- Benchmark matched direct/other-GSLB baseline, fuzz malformed EDNS/DNS
  packets, resolve from independent public and private network vantage
  points, verify multi-NS SOA convergence, serial lifecycle and physical
  failures. **Issue #52 and issue #36 remain P0 / open.**
- New GSLB tests do not certify the rest of the GatewayCore management UI
  or production 500 Mbps ingress. Do not promote until independent HA,
  throughput, security and failover runbooks are actually accepted.

No unqualified production-readiness claim follows from GitHub CI.
