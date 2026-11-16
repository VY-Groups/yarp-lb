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

## Open-source architecture reference

The separately hosted gslb Git branch contains Verisign's Polaris PowerDNS
remote-backend project, BSD-3-Clause licensed (see gslb:LICENSE). Its
PowerDNS integration, topology/weighted selection, per-site checks, failover
groups, and SOA management informed the requirements, not this C# source.
This code does not import Polaris source or polaris_common. See
POLARIS_ARCHITECTURE_REVIEW.md.
