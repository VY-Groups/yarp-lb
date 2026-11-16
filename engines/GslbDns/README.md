# GatewayCore standalone GSLB DNS — experimental authoritative transport

This separate, non-recursive .NET 10 engine is NOT the HTTP YARP dataplane and
must not be delegated a production domain. It serves explicit IPv4 GSLB hosts,
with HTTP(S) health probes, weighted selection, response rate limits and per-zone
all-down policy.

## Newly supported in lab

- UDP + length-prefixed DNS-over-TCP on the same listen address/port (localhost by
  default). TCP requests are capped at 4096 bytes, with at most 32 in-flight
  sessions and a five-second timeout. No recursive resolver, DNS forwarding,
  AXFR/IXFR or dynamic zone writes.
- Explicit SOA and NS answers only when NameServers are configured. Static
  serial must be deliberately bumped in config when site authority changes.
  In-bailiwick name server IPv4 address answers and additional glue are available;
  out-of-bailiwick NS targets are listed without forging glue.
- In-zone missing names return NXDOMAIN with an SOA negative-cache record;
  existing names with unsupported types return NODATA with SOA; names outside
  the configured zones are REFUSED.
- EDNS0 OPT input is syntax checked with a 512–1232-byte UDP buffer limit;
  unknown options and ECS are ignored, not logged or echoed. Unsupported EDNS
  versions return BADVERS via the OPT extended response code. DNSSEC DO is NOT
  advertised, and DNSSEC is not supported.
- UDP replies use complete-RR truncation (TC) when they exceed the advertised
  buffer or a conservative per-query amplification budget. Clients should retry
  over TCP. Source-IP response budgets are only a limited defense in depth.

## Example test configuration

    {
      "AllowNonLoopbackListeners": false,
      "ListenHost": "127.0.0.1",
      "ListenPort": 15353,
      "ProbeIntervalSeconds": 2,
      "MaxResponsesPerSecondPerClient": 500,
      "Zones": [{
        "Name": "app.example.test",
        "TtlSeconds": 10,
        "SoaSerial": 2026111601,
        "SoaContact": "hostmaster.app.example.test",
        "NameServers": [
          {"Host":"ns1.app.example.test","Address":"127.0.0.31"},
          {"Host":"ns2.app.example.test","Address":"127.0.0.32"}
        ],
        "FailClosedWhenAllSitesDown": false,
        "Sites": [
          {"Address":"127.0.0.21","HealthUrl":"http://127.0.0.1:19711/ready","Weight":2},
          {"Address":"127.0.0.22","HealthUrl":"http://127.0.0.1:19712/ready","Weight":1}
        ]
      }]
    }

Run: dotnet run --project engines/GslbDns/GslbDns.csproj -- /absolute/path/zones.json
The sample health URLs are placeholders, not functioning external services.
Use a disposable lab. Query A, SOA and NS via:
dig @127.0.0.1 -p 15353 app.example.test A
Then retry with +tcp as necessary. Never expose this lab service to the Internet.

## Original behavior preserved

Configured names return a weighted IPv4 site whose HTTP probe is healthy.
A failed site is excluded; when all probes fail, the default policy retains
weighted configured A records, to avoid making probe-system failures become DNS
outages. FailClosedWhenAllSitesDown: true returns SERVFAIL for A queries.
The fallback is NOT a healthy-endpoint claim. Negative answers and zone
metadata do not depend on backend health. The original five-to-300-second
answer TTL and the bounded per-source IPv4 UDP response limit remain in place.
Configurations without NameServers keep legacy A behavior; this alone is not
a complete authoritative zone.

## New opt-in health hysteresis and DNS standby policy

Legacy configurations remain **Weighted** and retain one-probe health
transitions. New per-zone settings use independent GatewayCore managed code:

- `RoutingPolicy: "Weighted"` (default): weighted selection from eligible sites,
  preserving the previous behavior and the 1..100 weight range.
- `RoutingPolicy: "Failover"`: deterministically selects the *first configured*
  healthy site with the smallest nonnegative `Priority` (0..1000). Weights are
  deliberately ignored under Failover. A missing `Priority` defaults to 0,
  so configuration order is the tie-breaker and failback is predictable.
- `FailureThreshold` and `SuccessThreshold`: 1..10 consecutive local HTTP
  probe results required to remove or restore the backend. Both default to 1.
  Startup remains unverified until the required number of successful probes.
  A successful probe resets the failure streak; a failure resets success streak.
- `FailClosedWhenAllSitesDown`: existing per-zone all-down policy. When true,
  DNS A queries return SERVFAIL instead of advertising sites that failed local
  readiness. This is recommended for CA/PKI or transaction-sensitive services.
  When false, the existing availability-first fallback still applies.

Example **test** zone (do not use these example addresses as production DNS):

    {
      "Name": "signing.example.test",
      "TtlSeconds": 5,
      "RoutingPolicy": "Failover",
      "FailureThreshold": 2,
      "SuccessThreshold": 2,
      "FailClosedWhenAllSitesDown": true,
      "Sites": [
        {"Address":"192.0.2.10","HealthUrl":"https://primary.example.test/ready","Weight":1,"Priority":0},
        {"Address":"192.0.2.20","HealthUrl":"https://standby.example.test/ready","Weight":1,"Priority":10}
      ]
    }

Values are validated during startup; invalid policy, priority or thresholds
abort rather than silently enable an unexpected routing mode. The DNS engine
does **not** retry CA operations, establish backend data replication, or prove
application transaction readiness; readiness endpoints and DR recovery have to
be accepted separately. Existing DNS caches can continue returning earlier
answers until TTL expiry. Health hysteresis may intentionally delay failover;
size thresholds and TTL from application SLOs, not to force a green CI result.

## Remaining NO-GO areas

DNSSEC signatures/keys, TLS/DoT/DoH, TSIG, DNS NOTIFY, zone transfer, true
zone-cut/delegation conformance, CNAME/MX, health-aware AAAA and regional
IPv6, geographic/ASN policy with licensed data and privacy, verified multi-site
health quorum and authenticated state propagation, split-brain protection,
ECMP/multi-NS physical hosting, public resolver interoperability and
spoofed-source reflection protection are NOT complete.

A fixed serial from a sample config is not automatic monotonic SOA serial
management. Changes must not be promoted to production without dig/kdig
interoperability, DNS stress/fuzz, dual-authoritative-node evidence, site-specific
health checks, delegation review, and independent network/security approval.
GitHub Actions exercise a disposable Windows/Linux lab; they do not certify GSLB.

## Open-source architecture references and licensing

At the time of PR #98, `gslb` held BSD-3-Clause licensed Polaris
(historical comparison retained in `POLARIS_ARCHITECTURE_REVIEW.md`).
The user replaced that branch with **OpenGSLB v1.1.10**, Go source at
`gslb:48f020c3f0d7d3d353485c9a0d701061a3014c08`. Its
`LICENSE` is **AGPL-3.0-or-later OR a separate commercial license**.
No Go source, third-party DNS library, OpenGSLB dependency or product
branding is incorporated into GatewayCore. This independent C# adaptation
targets observable features only, not OpenGSLB protocol compatibility or
vendor certification. See `OPENGSLB_REFERENCE_REVIEW.md` for mapping,
risk and test boundaries. Consult legal counsel before any future direct
code reuse or software distribution.
