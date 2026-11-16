# gslb branch (Polaris) architectural review

Compared against gslb at commit 73c0b121f802bc6a3221a6d41f97d27e40f7f651
and GatewayCore main baseline 8193d3d0c497a797f9110daeadd33f90b925bda1
on 16 November 2026.

The historical branch is Polaris, written in Python, under BSD-3-Clause
(gslb:LICENSE, copyright 2014 Verisign). It is not the same .NET application
as GatewayCore. Polaris expects PowerDNS Authoritative Server and imports
polaris_common utilities not included in this branch. No direct branch merge,
copying of upstream code, or PowerDNS deployment was performed.

| Polaris source behavior | Current GatewayCore response |
| --- | --- |
| PDNS remote-backend pipe protocol | Keep standalone .NET DNS wire server, no PDNS coupling |
| Health tracker / TCP + HTTP/S probes | Existing local HTTP(S) polling; distributed health remains missing |
| Weighted rotation and primary/backup failover groups | Existing weighted GSLB sites with an all-down policy; explicit failover groups remain missing |
| Topology-aware mapping by client region | Not implemented: do not infer geography from client IP without licensed data |
| Dynamic distribution state shared via memcache | Not imported; avoid stale or unsigned remote health snapshots |
| NS/SOA record creation / serial management | Explicit NS/SOA, configurable static serial; automatic distributed revision still missing |
| Max addresses returned | GatewayCore still emits one selected GSLB address, no answer-set policy yet |

## Follow-up release gates for #52

- RFC DNS packet conformance (especially zone cuts, delegation, glue, negative
  cache TTL, malformed compression, ANY, QTYPE classes, DO/OPT/BADVERS,
  truncation and TCP retry) against dig, kdig, fuzzers and real recursive
  resolvers — including Windows/Linux behavior
- Health quorum + revision-fenced signed snapshot propagation across at least
  two independent authoritative nodes; reject expired/rolled-back state,
  never assume DC/DR health from a single local HTTP endpoint
- Privacy-aware geo/ASN policy requiring explicit IP data license/version;
  no ECS use until opt-in authorization and minimization are implemented
- Controlled load and network partition tests, anti-amplification protection,
  metrics/alerts and a security-approved authoritative DNS perimeter
- Physical two-node ingress and network failure qualification for #36 remains
  separately open; the experimental DNS service is not a replacement for it

This document is an architecture and gap analysis, not a vendor certification.
