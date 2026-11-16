# GatewayCore standalone GSLB DNS — experimental authoritative transport

This separate, non-recursive .NET 10 engine is NOT the HTTP YARP dataplane and
must not be delegated a production domain. It serves explicit IPv4 A and
IPv6 AAAA GSLB backends, with HTTP(S) and opt-in TCP health probes,
weighted/Failover selection, response rate limits and per-zone all-down policy.
The DNS listener remains IPv4-only even when answering AAAA queries.

## Private CIDR-to-region routing (opt-in, **not GeoIP**)

A zone may explicitly opt into `RoutingPolicy: "CidrRegion"` with a bounded
`CidrRoutes` table of 1–256 canonical IPv4/IPv6 CIDR prefixes. Each
`DnsSite` in that zone needs a valid `Region` (ASCII letters, digits, dash
or underscore; max 32 characters). Every mapped region must have at least one
configured site. Invalid, duplicate, noncanonical or conflicting entries
fail startup instead of silently misrouting customers.

Only the direct **DNS resolver source IP** from the UDP/TCP socket is used
for matching; it is not necessarily the actual user IP. More specific CIDR
prefixes take priority, independent of declaration order. A healthy matching
region receives weighted A/AAAA selection. If the resolver is unmapped or
every member of its preferred region is unhealthy, fall back to any healthy
configured site of that address family (or the zone's configured strict
all-down behavior when none are healthy).

Example **lab-only** zone (complete operational NS/SOA settings omitted):

    {
      "Name": "app.example.test",
      "TtlSeconds": 10,
      "RoutingPolicy": "CidrRegion",
      "FailureThreshold": 2,
      "SuccessThreshold": 2,
      "FailClosedWhenAllSitesDown": true,
      "CidrRoutes": [
        {"Cidr":"10.42.0.0/16","Region":"dc"},
        {"Cidr":"10.42.10.0/24","Region":"dr"}
      ],
      "Sites": [
        {"Address":"192.0.2.10","HealthUrl":"https://dc.example.test/ready","Weight":2,"Region":"dc"},
        {"Address":"192.0.2.20","HealthUrl":"https://dr.example.test/ready","Weight":1,"Region":"dr"}
      ]
    }

**Not equivalent to geographical user routing.** ECS remains ignored (and
must not be trusted without explicit source resolver policy and privacy
approval). No GeoIP/ASN dataset or inferred country/continent is used.
External recursive resolvers may serve cached answers to many geographically
diverse users. Use this mode only for controlled resolver networks with
explicitly owned CIDR mappings. Multi-region failure safety, DNSSEC,
signed configuration, physical DR and cache-aware rollover remain NO-GO.

## Family-correct IPv4/IPv6 backend answers (lab)

Each site `Address` may now be an IPv4 or IPv6 literal. A queries select only
configured IPv4 site addresses, and AAAA queries only configured IPv6 sites.
Health, optional priority and existing weights are applied within that family.
When no site is configured for the requested family, the authoritative result
is **NODATA with negative SOA**, not SERVFAIL or an incorrectly typed answer.

Example IPv6 site: `{"Address":"2001:db8::99","HealthUrl":"http://127.0.0.1:19711/ready","Weight":1}`.
The address and the readiness probe target are deliberately separate.
**A successful IPv4 HTTP probe is not proof of IPv6 reachability.** Production
acceptance must probe over the network/address family actually advertised.
IPv6 DNS UDP/TCP listener binding, IPv6 NS glue and DNSSEC are still missing.

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

## Bounded parallel DNS health sweeps

`MaxConcurrentHealthProbes` is an optional top-level JSON setting, default
**32**, accepted **1..128**. Each timed DNS probe cycle now dispatches
up to that many HTTP(S)/TCP probes concurrently, rather than probing all
configured sites sequentially. The complete batch finishes before another
cycle begins: no overlapping health writes to the same per-zone backend,
no unbounded per-site Task.Run fanout, and cancellation propagates on stop.
Existing readiness timeout, health hysteresis and all-down policy are unchanged.

The acceptance suite uses a deterministic blocked-probe workload to prove
that only two of six synthetic probes start before release, that all six
eventually complete, and that an invalid parallelism setting is rejected.
This supplements the real Windows/Linux DNS health and failover tests.

The engine allows up to 64 zones with up to 16 sites per zone. At maximum
cardinality, even 32 concurrent probes can require many seconds to conclude
if every target times out; operators must measure probe durations, age and
batch cadence. Local source observations are not multi-site health quorum.
**Concurrency tuning is not a production GSLB certification.**

## Backend health probe types (independent, opt-in)

Existing site configurations continue to use direct HTTP(S) readiness with the
same 1.5-second timeout. **HTTP 3xx redirects are now classified as a failed
readiness probe** instead of following them, because a redirect to a login
page or another healthy backend can incorrectly announce the original
application as ready. Configure the final HTTPS readiness URL directly;
readiness endpoints should return 2xx without redirects, even during rotation.

Optional per-site `HealthCheckType: "Tcp"` probes direct TCP connectivity to
`Address:TcpPort` (port 1..65535), using a bounded 1.5-second connection
deadline and the existing rise/fall thresholds. TCP mode must have
`HealthUrl` omitted or blank, and HTTP mode cannot specify `TcpPort`.
Unknown probe types, malformed ports or conflicting probe settings fail
startup. An example TCP site is:

    {
      "Address": "192.0.2.30",
      "HealthUrl": "",
      "Weight": 1,
      "Priority": 0,
      "HealthCheckType": "Tcp",
      "TcpPort": 5432
    }

This only confirms a TCP handshake, **not PostgreSQL replication, application
readiness, signing authority, authentication or transactional consistency**.
For critical applications, prefer a dedicated HTTPS readiness endpoint
that validates dependencies and fails closed. The probe does not send payloads
or authenticate and does not require changing the YARP L7 routing behavior.

Tests simulate a TCP listener accepting, refusing and recovering connections,
plus an HTTP 302 redirect to a separately healthy backend. DNS must never
restore the redirected primary. A real external TLS/health acceptance drill
and isolation across two independent sites remain mandatory for production.

## Opt-in observed probe latency (not user RTT)

`RoutingPolicy: "ObservedLatency"` measures successful HTTP/TCP health probe
completion time from **this DNS instance** to its configured endpoint. It
is not end-user-to-datacenter latency and does not imply geographic proximity.
A bounded exponentially smoothed measurement (alpha 0.25) is available only
after 3 successful samples, is invalidated on probe failure and must be at most
15 seconds old. If any currently eligible backend has insufficient/stale
measurements, the policy uses the preexisting weighted algorithm. If two
endpoints are within 15% of each other, weighted fallback avoids choosing a
winner based on small probe jitter. A failed or drained backend is never
made eligible by an apparently favorable latency score.

`Weighted`, `Failover`, and `CidrRegion` still behave exactly as before.
No external telemetry, service probes on your infrastructure, or
client IP/ECS geolocation is enabled. A multi-region RTT architecture needs
licensed geographic data, independently authenticated vantage-point agents,
sample freshness/replay fencing, privacy and failover acceptance before GO.

## Remaining NO-GO areas

DNSSEC signatures/keys, TLS/DoT/DoH, TSIG, DNS NOTIFY, zone transfer, true
zone-cut/delegation conformance, CNAME/MX, IPv6 DNS transport listeners,
IPv6 NS glue, geographic/ASN policy with licensed data and privacy, verified multi-site
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
