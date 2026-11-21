# GatewayCore standalone GSLB DNS — experimental authoritative transport

This separate, non-recursive .NET 10 engine is NOT the HTTP YARP dataplane and
must not be delegated a production domain. It serves explicit IPv4 A and
IPv6 AAAA GSLB backends, with HTTP(S) and opt-in TCP health probes,
weighted/Failover selection, response rate limits and per-zone all-down policy.
The DNS listener supports IPv4 and IPv6, including the standard public DNS port 53 when an operator explicitly opts in to a non-loopback listener. A privileged bind requires the service identity to have OS permission (for example, Linux `CAP_NET_BIND_SERVICE`); do not run the production service as root. The default test configuration remains loopback-only on port 15353.

## Private CIDR-to-region routing (opt-in)

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

This mode uses the resolver socket address. For end-user subnet routing, use
the separate opt-in `GeoIpEcs` policy below.

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
IPv6 DNS UDP/TCP listeners and IPv6 NS glue are supported. DNSSEC signing is
available as an explicit per-zone lab feature; independent public delegation,
rollover and multi-authority acceptance remain open.

## Newly supported in lab

- UDP + length-prefixed DNS-over-TCP on the same listen address/port (localhost by
  default). TCP requests are capped at 4096 bytes, with at most 32 in-flight
  sessions and a five-second timeout. No recursive resolver, DNS forwarding,
  AXFR/IXFR or dynamic zone writes.
- Explicit SOA and NS answers only when NameServers are configured. Static
  serial must be deliberately bumped in config when site authority changes.
  In-bailiwick name server IPv4 or IPv6 address answers and additional glue are available;
  out-of-bailiwick NS targets are listed without forging glue.
  Opt-in signed GatewayAgent staging rejects changed existing authoritative
  zones unless the proposed `SoaSerial` advances under RFC 1982; it does not
  generate serials and does not guard direct file edits.
- Empty non-terminals above configured in-zone NS address records return
  NODATA with negative SOA (RFC 8020 section 3.1), preserving resolution of
  their descendants. Label-boundary matching does not invent sibling names.
  Configured static child delegations also return referrals (see below), but
  the engine does not load or serve child-zone data and is not a full
  parent/child authoritative DNS implementation.
- In-zone missing names return NXDOMAIN with an SOA negative-cache record;
  existing names with unsupported types return NODATA with SOA; names outside
  the configured zones are REFUSED.
- EDNS0 OPT input is syntax checked with a 512–1232-byte UDP buffer limit;
  unknown options are ignored, not logged or echoed (responses carry no
  unknown option payload over UDP or TCP). Unsupported EDNS versions
  return BADVERS via the OPT extended response code. Unsigned zones keep the
  previous safe behavior: DO requests never set AD, claim DO support, or
  fabricate signatures. A zone with `DnssecPrivateKeyPath` enabled returns
  signed DNSKEY, RRSIG, NSEC, SOA/NS, dynamic A/AAAA and negative answers.
  EDNS responses advertise the server's 1232-byte UDP receive size; UDP
  response data still respect the client's advertised budget (capped at
  1232 bytes), and larger responses set TC for TCP retry. Real-socket
  acceptance sends a large NS RRset with 512- and 1232-byte client budgets:
  the 512-byte UDP response is bounded and truncated while its OPT advertises
  1232, the same query completes over TCP, and the 1232-byte UDP response
  includes the full RRset without TC.
- EDNS Client Subnet is ignored by default. A zone using `CidrRegion` can opt in
  with `EnableEcsGeoRouting: true` and an explicit `TrustedEcsResolverCidrs`
  allowlist; untrusted resolver sources cannot steer answers with forged ECS.
  Input is normalized and limited to at most
  IPv4 `/24` and IPv6 `/56`, and only explicit operator CIDR routes are used.
  Malformed or duplicate ECS options, including nonzero unused host bits after
  a partial source prefix, are ignored for routing and never echoed; the DNS
  question still uses the resolver-source routing fallback.
  Ambiguous source subnets that cross differently mapped more-specific routes
  fall back to the direct resolver source and are not echoed. A successful ECS
  decision returns the normalized source and matching route scope for cache use.
  No ECS addresses are logged or retained. This is not GeoIP/ASN lookup and
  requires trusted recursive resolvers to apply their own ECS privacy policy.
- `GeoIpEcs` is a separate opt-in policy that performs local MaxMind MMDB
  country and/or ASN lookups on trusted ECS only. The operator supplies
  absolute `GeoIpCountryDatabasePath` and/or `GeoIpAsnDatabasePath` paths in
  the top-level DNS config and explicit `GeoCountryRoutes` and/or
  `GeoAsnRoutes` mapping data values to configured site regions. No database
  download, license key or raw address is sent to a service. The default
  maximum database age is 45 days; update authorized databases before that
  window expires. A value of zero disables the freshness guard and is intended
  for synthetic CI fixtures only.
  ECS is masked to at most IPv4 `/24` or IPv6 `/56` before lookup. If a country
  or ASN record is more specific than that subnet, configured country and ASN
  routes conflict, the result is unknown/unmapped, the resolver is not
  allowlisted, or no healthy site exists in the mapped region, routing falls
  back to the existing weighted policy and the ECS value is not echoed. A
  successful match returns only the normalized subnet and selected scope for
  DNS cache behavior. Country/ASN data is inherently approximate and is not a
  source of identity or precise location. Operators remain responsible for
  database licensing, updates, resolver privacy and cache behavior.

Example **lab-only** top-level configuration and zone (database files are not
included):

    {
      "GeoIpCountryDatabasePath": "/etc/gatewaycore/geo/GeoLite2-Country.mmdb",
      "GeoIpAsnDatabasePath": "/etc/gatewaycore/geo/GeoLite2-ASN.mmdb",
      "GeoIpMaxDatabaseAgeDays": 45,
      "Zones": [{
        "Name": "app.example.test",
        "TtlSeconds": 20,
        "RoutingPolicy": "GeoIpEcs",
        "EnableEcsGeoRouting": true,
        "TrustedEcsResolverCidrs": ["192.0.2.53/32"],
        "GeoCountryRoutes": [{"CountryCode":"IN","Region":"mumbai"}],
        "GeoAsnRoutes": [{"Asn":64500,"Region":"mumbai"}],
        "Sites": [
          {"Address":"198.51.100.10","HealthUrl":"https://in.example.test/ready","Weight":1,"Region":"mumbai"},
          {"Address":"203.0.113.20","HealthUrl":"https://jp.example.test/ready","Weight":1,"Region":"osaka"}
        ]
      }]
    }
- UDP replies omit entire non-fitting RRsets (rather than emitting partial sets) and set TC when they exceed the advertised
  buffer or a conservative per-query amplification budget. Clients should retry
  over TCP. Source-IP response budgets are only a limited defense in depth.
  Cross-platform acceptance sends a finite corpus of malformed DNS/EDNS frames
  and verifies that UDP receives no response, TCP closes without a response,
  and subsequent valid queries still work. This is a parser regression check,
  not fuzzing or a complete denial-of-service assessment.

## Example test configuration

### Optional signed zone

DNSSEC is disabled unless a zone sets `DnssecPrivateKeyPath` to an absolute
path containing a P-256 PEM private key. For a disposable lab key:

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/gatewaycore/dnssec/app.example.test.pem
    chmod 600 /etc/gatewaycore/dnssec/app.example.test.pem

Add this to the zone JSON (the zone must also configure NS records):

    "DnssecPrivateKeyPath": "/etc/gatewaycore/dnssec/app.example.test.pem"

NSEC is the default. To use NSEC3 instead, configure a fixed salt and an
explicit iteration count (0 is supported and often preferable):

    "DnssecPrivateKeyPath": "/etc/gatewaycore/dnssec/app.example.test.pem",
    "DnssecDenialMode": "Nsec3",
    "DnssecNsec3SaltHex": "0011223344556677",
    "DnssecNsec3Iterations": 0

The salt is 8..32 bytes of hex and iterations are bounded to 0..50. Store the
same values in every authority's signed zone configuration; different values
produce incompatible denial chains. The service rejects an omitted iteration
field, random runtime salt, unsupported name encoding and excessive bounds.

At startup the DNS process logs each key's public `DS` record in presentation
format, with a phase label (`active`, `prepublish`, or `dual-sign`). The output
is deterministically ordered and can be checked against the independently
generated DNSKEY. The server does not publish DS records to a parent zone or
registrar. All authorities serving the same signed zone must use the same key
set and serial. On Linux, private-key paths are opened without following
symlinks, ownership and restrictive mode are checked on the opened key, and
the PEM imported is read from that same handle; the key must be owned by root
or the service identity and have no group/other permissions (`0600` is
recommended). On Windows, the final reparse point is not followed, but key ACL
authorization is deployment-managed: grant read access only to the GatewayCore
service identity using a restrictive NTFS ACL. Private key contents are never
logged.

### Manual CSK prepublication and overlap

This is an operator-controlled routine rollover procedure. It does not automate
parent DS updates, reload files, coordinate authorities, or provide emergency
key-compromise recovery. Use a separate `0600` P-256 private key at each signer;
export its public SubjectPublicKeyInfo PEM for prepublication:

    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out /etc/gatewaycore/dnssec/app-next.pem
    chmod 600 /etc/gatewaycore/dnssec/app-next.pem
    openssl pkey -in /etc/gatewaycore/dnssec/app-next.pem -pubout -out /etc/gatewaycore/dnssec/app-next.pub.pem

1. **Prepublish.** Keep the current `DnssecPrivateKeyPath` unchanged and add
   `DnssecPrepublishPublicKeyPaths` with the absolute `app-next.pub.pem` path:

       "DnssecPrivateKeyPath": "/etc/gatewaycore/dnssec/app-current.pem",
       "DnssecPrepublishPublicKeyPaths": ["/etc/gatewaycore/dnssec/app-next.pub.pem"]

   All authorities publish both DNSKEYs; the old key continues signing. Keep
   only the old DS at the parent. Compare the logged new DS with an independent
   derivation and wait at least one zone DNSKEY TTL on every authority.
2. **Dual-sign.** Remove `DnssecPrepublishPublicKeyPaths` and add
   `DnssecAdditionalSigningKeyPaths` with the new absolute private-key path.
   Keep the old key as `DnssecPrivateKeyPath`:

       "DnssecPrivateKeyPath": "/etc/gatewaycore/dnssec/app-current.pem",
       "DnssecAdditionalSigningKeyPaths": ["/etc/gatewaycore/dnssec/app-next.pem"]

   Verify the `dual-sign` DS output
   and that DNSKEY, A/AAAA, SOA, NS, and denial RRsets carry signatures from both
   key tags on every authority. Wait at least one DNSKEY TTL so cached keysets
   include both signatures before changing parent DS data.
3. **Parent overlap.** Add the new DS to the parent while retaining the old DS.
   Independently validate both chains and wait for the parent DS TTL and the
   zone's DNSKEY/signature TTLs to expire.
4. **Retire.** Remove the old DS at the parent and wait out its published TTL.
   Then set `DnssecPrivateKeyPath` to the new private key and remove
   `DnssecAdditionalSigningKeyPaths`; restart every authority and verify only
   the new DNSKEY/signatures remain. Retain the old key offline under the
   organization's recovery policy until acceptance is complete.

Any failed file, key, phase, or signer startup fails closed. Do not skip a wait
because the lab test passed. Production DNSSEC still requires parent-chain,
multi-authority and operational acceptance.

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

For a separately approved authoritative deployment on the standard public port,
set `ListenHost` to the intended service address, `ListenPort` to `53`, and
`AllowNonLoopbackListeners` to `true`. Signed engine staging also requires the
independent local public-bind permission. Configure OS capabilities/service
permissions for UDP and TCP port 53 rather than running as root. Keep the
management and metrics listeners private; this engine is non-recursive and
serves only explicitly configured zones. Each zone on a non-loopback listener
must configure at least one apex `NameServers` entry. Startup fails closed if a
publicly reachable zone cannot answer its authoritative NS query. Loopback-only
legacy A behavior remains available for local development.

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
RTT routing is opt-in and uses only configured active probes; ECS and GeoIP
routing are separately opt-in as described above. No external telemetry is
sent by these routing policies. A multi-region RTT architecture needs
licensed geographic data, independently authenticated vantage-point agents,
sample freshness/replay fencing, privacy and failover acceptance before GO.

## Remaining NO-GO areas

TLS/DoT/DoH, TSIG, DNS NOTIFY, zone transfer, full
zone-cut/delegation conformance, CNAME/MX, geographic/ASN policy with licensed data and privacy, verified multi-site
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

## Opt-in external HTTPS health validation

Set a site's `ValidatorUrls` to two distinct HTTPS origins that each return 2xx only when their independently measured site is ready. Configure the DNS process with local environment variables `GSLB_VALIDATOR_CERT_PEM` and `GSLB_VALIDATOR_KEY_PEM` as absolute local file paths. Set `GSLB_VALIDATOR_ORIGINS` to a comma-separated allowlist of exact HTTPS origins. Validators must require this client certificate. DNS verifies server certificates against system trust and verifies hostnames. Restrict access to the private key and restart for credential replacement.

Both validators and the local probe must succeed. Set `FailClosedWhenAllSitesDown` to true. One failed validation immediately excludes the site; successful evidence expires ten seconds after validation starts even if the probe scheduler stalls. Choose a probe interval and batch capacity that refresh within ten seconds. Each validator must disable caching for its readiness URL. Distinct origins are configured by the operator and need independent network placement. This is synchronous validation, without signed store-and-forward health snapshots.

### Signed synchronous readiness responses

Each configured validator origin requires its own P-256 signing key. Set `GSLB_VALIDATOR_SIGNING_KEYS` on each DNS node to a JSON object mapping canonical HTTPS origins to absolute PEM public-key paths. Keep private signing keys at the observers. Configure a distinct readiness URL for each monitored service and site. Observers should derive that URL from their own configured public origin and endpoint.

DNS sends a fresh `Gslb-Challenge` per probe (32 random bytes as uppercase hex). The validator measures readiness and signs the UTF-8 encoding of four lines with LF separators and no trailing newline: `GatewayCore.Health.v1`, the canonical absolute validator URL, the received challenge, and the decimal HTTP status. Return the base64 DER-encoded ECDSA/SHA-256 signature in `Gslb-Signature`. Only signed 2xx responses are eligible. Unsigned failures also withdraw the site. A response is valid only for its originating request. Asynchronous reports require a separate sequence and expiry protocol.

### Opt-in authenticated asynchronous agent reports (development/staging)

An independently deployed `GslbObserver` can additionally publish signed health snapshots to a DNS node over a separate HTTPS listener. This is disabled unless `AgentReports` is present and at least one site explicitly sets both `AgentSiteId` and `RequiredAgentIds`. Existing routing behavior is unchanged when omitted.

The versioned signed report includes agent and key IDs, scoped zone/site, probe type, UTC observation/expiry, monotonic epoch/sequence, an explicit `healthy`, `unhealthy` or `unknown` verdict, confidence in permille, optional measured latency and signature. `unknown` requires zero confidence and no latency; it is accepted as evidence but never promotes a site. Healthy and unhealthy verdicts require a nonzero confidence value from 1 to 1000. An observer reports confidence 1000 only for a direct HTTP result and zero for a probe exception/timeout; this is evidence strength, not a calibrated statistical probability.

When report intake and the loopback-only metrics listener are both enabled, `GET /agent-report-status` on that listener returns a bounded JSON operator snapshot for at most 64 configured agent identities. It includes the last accepted UTC timestamp, age measured using the DNS process monotonic clock, rejected totals since process start, and current fresh versus stale/missing configured report slots. Rejection totals are attributed only after the request certificate maps to a configured agent; other rejected traffic remains in the aggregate Prometheus counter. The snapshot omits source addresses, certificates, keys, zones and site IDs. `GatewayAgent` validates the bounded schema and relays it only through its existing authenticated mTLS fleet-status API; the management UI escapes the configured agent ID before rendering it. The endpoint shares the loopback metrics listener and is not intended for direct public exposure.

The receiver requires a client certificate pinned by SHA-256, a matching ECDSA P-256 report-signing key, a bounded HTTP body, a bounded per-agent request rate, a valid timestamp/expiry, and an increasing `(epoch, sequence)` for each agent/site. Certificate pins support up to four overlapping leaves per identity for rotation; an emergency SHA-256 denylist rejects revoked leaves. Agent IDs are limited to 64 ASCII identifier characters. Replay high-water marks are written atomically before a report is accepted; the state file is mode `0600` on Linux. On Windows, the replay-state directory, state file, lock file and temporary files are checked when opened or written; any allow ACE outside the effective DNS service identity, LocalSystem or Builtin Administrators causes startup/write failure. Configure a dedicated directory with those principals only, include it in secure backups, and do not delete it during restart/restore. The actual live report is memory-only, so a restarted DNS node begins unknown and requires new reports. DNS eligibility and evidence-status reads share a monotonic one-second bounded replay-state integrity check (including file mode/ACL and SHA-256 of the on-disk snapshot); an authenticated report verifies immediately before writing. A deleted, unreadable or replaced replay file—including a syntactically valid older snapshot—clears all live reports and latches a fail-closed fault. Restoring it does not silently reset a running faulted store. Startup also rejects duplicate JSON property aliases. This is an **in-process consistency check**, not an authenticated state MAC, independently trusted monotonic storage, an anti-rollback guarantee across restarts, nor a defense against privileged host compromise or a transient replacement between polls. Durable cross-restart anti-rollback still requires independent trust/backup controls under #109.

The agent-report HTTPS listener's server private key must be an absolute regular file. Linux opens every path component without following symlinks and checks the opened file and each parent directory by handle: file and directory owners must be root or the service identity; the key must be owner-readable with no group/other access (`0600` is recommended); parent directories must not be group/other-writable, except a sticky directory owned by root or the service identity (for example `/tmp`). The PEM is read from the same validated file handle. Windows opens the file without following a final reparse point and imports the bytes read from that handle, but application-level owner/ACL validation is not implemented; use a service-owned directory and restrict the key ACL to the DNS service identity. Other operating systems are not supported by this key loader. Apply the same restrictions to each observer's TLS and report-signing private keys.

`RequiredAgentIds` names the bounded candidate reporter set (2..16). Each trusted agent must have an operator-configured `VantageGroup`; the group is a configuration label, not independently verified proof of geographic or network-path diversity. Reports from multiple agents in one group count as only one vote. `MinimumHealthyAgentReports` sets the minimum number of distinct fresh healthy groups and must be 2..N; when omitted, it defaults to N to preserve the original strict unanimous behavior. A fresh `unhealthy` report from any configured candidate vetoes eligibility. Missing, stale and `unknown` reports do not vote. The threshold is satisfied only by distinct fresh healthy groups. A site's DNS eligibility is also conjunctive with its local active health probe and any synchronous external validators. The strict all-down policy then returns SERVFAIL when no other eligible site exists. Reports never promote a failed local probe. Predicted-health scores are not accepted by this protocol and cannot affect DNS selection. Each DNS node keeps its own replay state; configure agents to send to each authoritative node independently.

When an observer uses a custom server CA, `ReportServerRevocationMode` defaults to `Online` and fails closed if revocation status cannot be established. `NoCheck` is only appropriate for isolated disposable test PKI without CRL/OCSP; it disables server-certificate revocation checks and must not be copied into production configuration. Agent client leaves are pinned directly and can be revoked through the receiver's explicit denylist.

Linux multi-process acceptance runs two independent DNS authorities, partitions one observer feed, and verifies only the node without a fresh quorum withdraws and later recovers. It also restarts one authority with two of three observer leaf pins revoked: the remaining single vantage cannot restore DNS, and removing the denylist restores service only after new quorum reports are accepted. This tests local emergency revocation and partition behavior in CI; it does not establish physical network separation or cross-authority consensus.

Example shape (paths, certificate pins, keys, limits and addresses below are placeholders that must be provisioned and reviewed for a disposable environment):

    {
      "AgentReports": {
        "ListenAddress": "127.0.0.1",
        "ListenPort": 15443,
        "AllowNonLoopbackListener": false,
        "ServerCertificatePem": "/secure/report-server.pem",
        "ServerKeyPem": "/secure/report-server.key",
        "ReplayStatePath": "/var/lib/gatewaycore/gslb-agent-replay.json",
        "MaxTtlSeconds": 8,
        "MaxAgeSeconds": 6,
        "MaxClockSkewSeconds": 2,
        "MaxReportsPerMinute": 120,
        "RevokedCertificateSha256": [],
        "Agents": [
          {"AgentId":"region-a","VantageGroup":"region-a","CertificateSha256":["<64-hex-SHA256-leaf-pin>"],
           "SigningPublicKeyPems":["/secure/region-a-report.pub.pem"]},
          {"AgentId":"region-b","VantageGroup":"region-b","CertificateSha256":["<64-hex-SHA256-leaf-pin>"],
           "SigningPublicKeyPems":["/secure/region-b-report.pub.pem"]}
        ]
      },
      "Zones": [{
        "Name":"app.example.test", "TtlSeconds":5,
        "FailClosedWhenAllSitesDown":true,
        "Sites":[{"Address":"192.0.2.10", "HealthUrl":"https://app.example.test/ready",
          "Weight":1, "AgentSiteId":"primary", "RequiredAgentIds":["region-a","region-b"],
          "MinimumHealthyAgentReports":2}]
      }]
    }

Each observer's optional report configuration includes `ReportUrl` ending in `/agent-health/v1/reports`, its `AgentId`, `Zone`, `SiteId`, a P-256 `SigningKeyPem`, a client certificate/key with clientAuth EKU, an optional `ReportServerCaPem` custom CA, a protected absolute `ReportSequenceStatePath`, `ReportIntervalSeconds` and `ReportTtlSeconds`. On Linux, the sequence-state directory and its ancestors are checked without following symlinks: ancestors must be owned by root or the service identity and must not be group/other writable, except for a trusted sticky directory such as root-owned `/tmp`; the final directory must be service-private. Existing state and lock files must be regular, link-free, and owned by root or the service identity with no group/other access. Keep this path on a local filesystem whose permissions are controlled by the service administrator. Windows ACL enforcement remains deployment-managed. The report carries the SHA-256 key ID of its signer; the receiver can trust up to four public signing keys per agent during rotation. Without `ReportServerCaPem`, normal system TLS trust and hostname checks apply. The observer increments and persists a sender epoch at each restart and persists each sequence before sending. A lost sender sequence file causes old epochs to be rejected; restore it or explicitly re-enroll with a new identity.

The GitHub/Linux integration test covers disposable three-agent mTLS, two-of-three group quorum, one-agent outage tolerance, below-quorum fail-closed, negative veto, expiry, restart and recovery. Without `AuthorityFence`, two DNS authorities evaluate their own incoming reports independently and can disagree during an observer-feed partition. The optional 2-of-2 authority fence below makes each authority require a fresh positive decision from its peer as well as its own local eligibility. Predictive health, fleet trust-management UI, CA-sensitive authority validation, physical multi-network acceptance and production GO remain open.

### Opt-in two-authority agreement fence (strict 2-of-2)

For deployments that prefer a fail-closed answer over DNS availability during an authority partition, configure `AuthorityFence` on **both** authoritative nodes. This is a strict pair: each node requires its own local eligible decision and a fresh positive snapshot from its one configured peer. If either peer becomes unreachable, reports a negative decision, restarts, or has a different routing/health fingerprint, both nodes stop returning protected sites after the peer lease expires; with `FailClosedWhenAllSitesDown: true`, clients receive SERVFAIL. Restoring the link is not enough by itself: both nodes must exchange newer, signed decisions before DNS recovers.

The fence does not elect a leader or provide majority consensus. Membership is exactly two configured authorities and agreement is 2-of-2, so a peer or network failure sacrifices DNS availability. It is disabled when `AuthorityFence` is omitted, preserving existing behavior. Every zone must use strict all-down behavior and every site must include a stable, unique `AuthorityFenceSiteId`. The two nodes must use the same zone/site configuration; the engine computes a canonical SHA-256 fingerprint over routing policy, health failure/recovery thresholds, health-probe interval/concurrency, site eligibility and observer trust/vantage configuration. Private keys, listener addresses, metrics ports and observer replay state are not part of that shared fingerprint.

The authority listener and sender use HTTPS with mutually authenticated TLS. Each peer config pins 1..4 peer server certificate leaves and 1..4 peer client certificate leaves for overlap rotation, checks certificate validity and the required EKU, and verifies an independent P-256 signature on every snapshot. TLS server-name checks remain enabled. A snapshot is a complete bounded list of at most 1,024 zone/site decisions (maximum serialized body 128 KiB); partial, duplicate, unknown, wrong-peer, mismatched-config, unsigned, expired and replayed snapshots are rejected. The receiver persists a single monotonic `(epoch, sequence)` high-water point for the configured peer before admitting a decision. The sender increments and persists its epoch at process start; sequence increases for each snapshot. Current decisions are memory-only and expire against a monotonic local clock.

`LeaseSeconds` is bounded to 2..30 seconds and `PublishIntervalSeconds` to 1..10 seconds, with at least two publications fitting within a lease. Use independent persistent epoch/replay files in a protected local state directory on each DNS node and include them in secure backups. State files and lock/marker files are checked for private Linux permissions and Windows ACLs. Replay state deletion or corruption fails closed; DNS eligibility reads verify durable replay/epoch integrity at a shared one-second monotonic interval. Snapshot creation checks before and after evaluating local health evidence, publication rechecks before dispatch, and acknowledgements and authenticated incoming snapshots check immediately. Shared signature verification is serialized across concurrent incoming posts. Observed faults latch, clear local leases, and stop new publications until process/operator recovery. A previously transmitted or already in-flight snapshot cannot be recalled, and the peer's previously accepted lease can remain until its own expiry. Transient changes between checks or privileged storage rollback across restart are not ruled out. An initialized-state bit in the separate epoch file prevents reinitialization even if both replay JSON and its lock file are deleted. Restore state from a protected backup or deliberately provision a new authority identity and re-pair both nodes. Each peer endpoint must use a literal IP and port that exactly match `Peer.AllowedAddress` and `Peer.AllowedPort`; hostnames, other destinations and ports are rejected. Restrict inbound listener TCP to the other authority's exact IP (/32 for IPv4 or /128 for IPv6); for EC2 use a security-group inbound source rule for the peer's configured public /32 only. Permit outbound TCP only to the configured peer IP/port. Pin overlap and signing-key changes require coordinated configuration rollout; any mismatch fails closed until both processes agree.

Example fragment for authority A (authority B uses the same zones and reciprocal IDs, pins and keys):

    {
      "AuthorityFence": {
        "NodeId": "dns-a",
        "ListenAddress": "10.0.0.10",
        "ListenPort": 15444,
        "AllowNonLoopbackListener": true,
        "ServerCertificatePem": "/secure/dns-a-peer.pem",
        "ServerKeyPem": "/secure/dns-a-peer.key",
        "ClientCertificatePem": "/secure/dns-a-peer.pem",
        "ClientKeyPem": "/secure/dns-a-peer.key",
        "SigningPrivateKeyPem": "/secure/dns-a-decision.key",
        "EpochStatePath": "/var/lib/gatewaycore/authority-epoch.json",
        "ReplayStatePath": "/var/lib/gatewaycore/authority-peer-replay.json",
        "LeaseSeconds": 8,
        "PublishIntervalSeconds": 1,
        "Peer": {
          "NodeId": "dns-b",
          "Endpoint": "https://10.0.0.11:15444/authority-fence/v1/snapshot",
          "AllowedAddress": "10.0.0.11",
          "AllowedPort": 15444,
          "ServerCertificateSha256": ["<dns-b-server-leaf-sha256>"],
          "ClientCertificateSha256": ["<dns-b-client-leaf-sha256>"],
          "SigningPublicKeyPem": "/secure/dns-b-decision.pub.pem"
        }
      },
      "Zones": [{
        "Name": "app.example.test",
        "TtlSeconds": 5,
        "FailClosedWhenAllSitesDown": true,
        "Sites": [{
          "Address": "192.0.2.10",
          "HealthUrl": "https://app.example.test/ready",
          "Weight": 1,
          "AuthorityFenceSiteId": "primary"
        }]
      }]
    }

Keep each authority's private signing and TLS keys separate. A shared certificate/key may be used for both TLS roles only when it has both `serverAuth` and `clientAuth` EKUs. Inbound peer certificates are authenticated by exact pinned SHA-256 leaf identity; the signed snapshot additionally binds sender/receiver IDs, full configuration fingerprint, bounded lease, epoch, sequence, and complete target decisions. The loopback metrics endpoint exposes no site labels from this protocol yet; operators should use the DNS responses and service logs for local diagnostics.

The Linux multi-process acceptance uses two DNS processes and two authenticated TLS forwarding proxies. It proves initial matching positive decisions, a bidirectional authority-link partition while DNS listeners stay live (both nodes withdraw within the 5-second lease), restoration only after fresh matching snapshots, an authority restart with a new epoch, durable stale-replay rejection, and recovery only after current healthy evidence returns. This CI test does not verify physical network independence, power failure, DNS cache expiry at clients, certificate revocation through enterprise PKI, key rollover operations, or production availability.
## Opt-in weighted priority groups

Set `RoutingPolicy: "WeightedFailover"` to select the lowest numeric
`Priority` among healthy sites **of the requested address family**, then
apply the existing proportional weighted rotation within that group.
Groups are implicit: sites sharing a priority belong to the same group.
No new scheduler or external dependency is required.

For example, two healthy sites at priority 0 with weights 2 and 1 receive
two-thirds and one-third of DNS selections. Priority 10 sites receive none
until every priority 0 site of that family fails its configured health
threshold. A partial group outage uses its remaining healthy members;
it does not overflow to standby groups. Priority 20 can provide a third
fallback. Recovery automatically prefers the lowest healthy priority again
after the configured success threshold.

Existing bounds still apply: 1–16 sites per zone, priority 0–1000,
weight 1–100, and rise/fall thresholds 1–10. `Weighted`, deterministic
first-site `Failover`, and `CidrRegion` retain their previous semantics.
A and AAAA pools remain separate, including priority comparisons.

When every site of a family is down, `FailClosedWhenAllSitesDown: true`
returns SERVFAIL. With the legacy availability-first setting `false`,
the policy chooses the lowest **configured** priority group and applies
its weights despite failed probes. That response is not a healthy-site claim.
Use strict all-down behavior for transaction-sensitive deployments.

The real-socket acceptance fixture covers a three-group chain, 2:1 primary
and 1:3 backup distribution, partial primary failure, full-group failure,
TCP backup loss, tertiary failure, strict/open all-down behavior, automatic
failback and independent IPv6 selection. DNS selection ratios are not HTTP
load ratios: cached answers and long-lived connections affect traffic.
This feature adds no agent trust, gossip mesh, GeoIP, ECS routing or DNSSEC.
Those remain separate release gates under #52/#109.
`ListenHost` accepts native IPv4 and IPv6 addresses for both UDP and TCP. Use `::1` for IPv6 loopback. Non-loopback addresses still require explicit opt-in. Each process listens on one address family.

## GSLB runtime metrics (opt-in)

The DNS process can expose a Prometheus 0.0.4 scrape endpoint on a separate
loopback-only HTTP listener. `MetricsListenPort` defaults to `0` (disabled).
Set `MetricsListenPort` to an unused port from 1025–65535 and keep
`MetricsListenHost` at `127.0.0.1` (or `::1`) to enable it. The listener refuses
non-loopback addresses even when the DNS and agent-report listeners are exposed
on a private network. Scrape it locally or use a same-host metrics agent; do not
publish it directly to an untrusted network.

Exported counters cover DNS queries, no-response drops, DNS response codes and
authenticated agent-report outcomes. Gauges cover configured zones/sites,
sites passing local probe hysteresis, and (when agent reports are configured)
report-gated sites meeting quorum plus current healthy, unhealthy, unknown, and
stale-or-missing signed-report counts. The report counts are per configured
agent/zone/site slot, not distinct vantage groups; quorum remains separately
computed from distinct configured groups. Labels are fixed enums only; zone names,
backend addresses, agent IDs and client addresses are never emitted. These
runtime metrics support diagnostics and do not claim cross-authority consensus,
DNSSEC, GeoIP, or service availability by themselves. See
`control-center/ops/prometheus/METRIC_CONTRACT.md` for the series and scrape
guidance.

For an operator-planned maintenance withdrawal, set
`AdministrativelyQuarantined: true` on a site in its zone configuration. A
quarantined site remains health-probed and counted in the local health metric,
but DNS will never select it, even when every other probe or signed observer
reports healthy. The setting takes effect when the DNS process loads the updated
configuration; this is not a live management API. The default is `false`.

## Child-zone delegations

An authoritative zone may declare up to 256 `Delegations`. Each cut must be a
strict child of the configured zone and has 1–4 unique name-server names. Each
name may have one IPv4 and one IPv6 address (up to eight address rows per cut);
duplicate addresses of the same family fail startup. The parent returns a non-authoritative referral for the
cut and all names below it; it does not answer those names from the parent
GSLB site pool. In-bailiwick name servers receive additional-section glue;
out-of-bailiwick name servers never receive glue from the parent. Referral TTLs
use the parent zone TTL. The current engine does not load or serve the child
zone's data; configure its nameservers to serve that child authority.

For a signed parent, an optional `DsRecords` array can publish the child zone's
parent-side DS RRset. Each row contains `KeyTag`, `Algorithm`, `DigestType`
(`2` for SHA-256 or `4` for SHA-384), and `DigestHex` with the exact digest
length. The parent signer includes these DS records in the signed zone and,
for DO-enabled referrals, returns the DS RRset with its parent signature.
DO-enabled referrals to cuts without configured DS retain a signed NSEC/NSEC3
proof of DS absence. DS configuration on an unsigned parent, unrecognized
DNSKEY algorithms, unsupported digest types, malformed digests and duplicate
records fail startup. Derive DS data from the child's DNSKEY and independently compare it before deployment;
this feature does not push DS to a registrar or parent authority.

Example fragment:

    "Delegations": [{
      "Name": "child.example.test",
      "NameServers": [
        {"Host": "ns1.child.example.test", "Address": "192.0.2.53"},
        {"Host": "ns.other.example.net", "Address": "198.51.100.53"}
      ],
      "DsRecords": [
        {"KeyTag": 12345, "Algorithm": 13, "DigestType": 2,
         "DigestHex": "<64 hexadecimal SHA-256 characters>"}
      ]
    }]

The parent returns an authoritative negative SOA for a DS query at an unsigned
delegation. When DNSSEC signing is enabled, it includes signed NSEC proof that
the parent has no DS for that child.

DNSSEC defaults to NSEC denial proofs. A zone may opt into RFC 5155 NSEC3 with
`DnssecDenialMode: "Nsec3"`, an explicit shared `DnssecNsec3SaltHex`, and
`DnssecNsec3Iterations` from 0 to 50. Use the same stable salt, iteration
count, signed zone contents, key material and serial on every authority; the
salt is never generated at runtime. NSEC3 uses SHA-1, base32hex names and
Opt-Out disabled. The implementation builds a canonical hash ring from all
configured authoritative owner names and empty non-terminals; it supports
exact-owner NODATA and closest-encloser, next-closer and wildcard NXDOMAIN
proofs. NSEC remains the default and its wire behavior is unchanged.

Both modes use ECDSA P-256/SHA-256 (algorithm 13) and a pre-provisioned PEM
private key per zone. The server logs the public DS value
in presentation format; publish that DS at the parent registrar/zone before
delegating a signed child. For multi-authority service, provision the same key
securely to every authority and use the same zone/serial configuration. Keep
the key outside the repository and deployment artifacts, restrict access to
the service identity (`chmod 600` on Linux and an equivalent Windows ACL),
and back it up using the organization's approved secret-management process.
The signer refreshes signatures as they approach expiry.

This signer is limited: NSEC3 has no salt rotation or Opt-Out mode; neither
denial mode implements automated KSK/ZSK or algorithm rollover,
HSM/KMS integration, DS publication workflow, child-zone signing, key revocation,
TSIG, AXFR/IXFR, or external authority synchronization. Manual CSK
prepublication and dual-sign overlap are opt-in configuration phases, not an
automated lifecycle. The configured DS is not automatically published to the
parent, and differing keys/serials across authorities will break validation.
Do not enable signing for a public zone until independent
resolver/parent-delegation and multi-authority acceptance is complete.
Zone serials are operator-configured and do not automatically increment.
AXFR/IXFR, NOTIFY, TSIG and recursive service are also unsupported.

## UDP admission budget

The existing per-source UDP response budget is enforced before packet parsing (including malformed requests). `MaxUdpQueriesPerSecond` optionally bounds admitted UDP work across all sources in a process: 0 (default, disabled) or 20–200000 per fixed one-second window. `GroupIpv6UdpClientsByPrefix` (default false) optionally counts IPv6 addresses in the same /64 as one source; IPv4-mapped addresses canonicalize to IPv4. Both settings are checked by the signed engine configuration validator and at engine startup. When a budget is exhausted, packets are dropped before DNS processing; denied packets are counted by existing aggregate drop metrics. The limiter never uses the prefix as an ECS routing hint, and never exports client IPs. Defaults preserve per-address behavior and do not impose a new aggregate cap. Choose a cap and prefix policy using measured resolver traffic; a shared prefix or exhausted aggregate budget can deny legitimate traffic. This is process-local fixed-window defense in depth, not source authentication, distributed DDoS protection, a TCP rate limit or proof of load/availability targets. Deterministic tests cover multi-source saturation, same-prefix IPv6, IPv4 canonicalization, expiry, rejected signed config values and preserved defaults. Real traffic/chaos and multi-authority qualification remain open.

### Authority observer trust fingerprint

For fence-enabled authorities with signed observer reports, the configuration fingerprint uses the exact validated in-memory observer identity, vantage group, SHA-256 certificate pin and canonical public signing key ID (not a second read or textual hash of a PEM file). Equivalent public-key PEM formatting no longer changes the digest; replacing a PEM after load cannot cause a running authority to attest trust in a different key. A newly loaded replacement key does change it. Missing loaded observer trust is rejected. This changes fingerprints for report-enabled fence configurations: coordinate the restart of both authorities and expect fail-closed routing while fingerprints disagree; do not roll only one authority indefinitely. Review the same trust settings and keys on each host before rollout. No automatic trust reload, consensus membership change or live key rotation is implied. Tests cover real loaded trust stores, changed vantage groups, equivalent encodings, on-disk replacement/removal after load and required loaded state.

Observer report admission charges the authenticated certificate identity's `MaxReportsPerMinute` budget before request-body parsing, including malformed or duplicate JSON reaching the handler. Exhaustion returns HTTP 429; one observer cannot charge another observer's quota via a claimed report identity. Kestrel transport/header limits and the global concurrency limit remain separate defenses. The real mTLS fixture tests three malformed requests, a fourth rejected by rate limiting, and an unaffected second identity. This is not distributed DDoS protection.

### Chunked report body rejection

The agent report ingress continues to enforce the same 8192-byte JSON limit through Kestrel and the application reader. When a real authenticated chunked transfer trips Kestrel's size bound while reading, the endpoint translates only the HTTP 413 transport exception into a controlled 413 response and increments per-agent rejection metrics. Other transport errors are not silently converted to successful reports. The disposable mTLS authority test sends three 4096-byte chunks to verify the 413 status, continued server availability and per-observer quota isolation. This is independent of the separate peer authority-fencing protocol; it does not establish full #109 completion.
