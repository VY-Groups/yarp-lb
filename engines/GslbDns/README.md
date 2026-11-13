# Experimental standalone GSLB DNS engine — 0.1

Separate .NET 10 authoritative DNS-style **UDP A-record responder**, not a YARP HTTP route. Configured names return a weighted IPv4 site whose HTTP health probe is currently successful. If a site's health fails, it is removed from DNS answers; when all site probes fail, the default policy continues returning weighted configured A records, since a probe-system outage must not automatically cause a DNS outage. Per-zone `FailClosedWhenAllSitesDown: true` instead produces DNS **SERVFAIL**. The default fallback does not assert that those sites are healthy. Names outside the explicit configuration return REFUSED. The response preserves DNS transaction ID and applies a bounded 5–300-second TTL.

GitHub Actions tests actual UDP DNS packet responses and HTTP health transitions on Windows and Ubuntu with no public DNS delegation. The default listener is loopback-only; a non-loopback address requires `AllowNonLoopbackListeners=true`. The UDP responder also uses a bounded fixed-window per-source-IP response budget: `MaxResponsesPerSecondPerClient` defaults to 500 (supported 20–20000 responses/second), and its address table has a hard 4096-client cap. Exhausted sources are silently dropped until their window resets.

## Boundaries

**This is not production GSLB yet.** Real authoritative DNS must support TCP fallback, AAAA, CNAME/MX/NS/SOA, EDNS, DNSSEC/TSIG, zone delegation, secondary replication, public-facing DDoS/amplification defense (a per-source-IP limiter is not sufficient against spoofed-source floods), geographic policy, provider integration, regional probes/quorum, DNS TTL caching/failback control, and monitored operation. Health probes are local to this one process: they do not establish geographically distributed observations. DNS clients/caches can continue using stale TTL answers after site failure. Do not delegate live production domains to this prototype.

## All-down policy

`FailClosedWhenAllSitesDown` is optional per zone and defaults to `false`. Example zone: `{"Name":"app.example.test","TtlSeconds":10,"FailClosedWhenAllSitesDown":false,"Sites":[...]}`. Use the strict setting only when a DNS answer to an unhealthy endpoint is worse than complete unavailability. This is a prototype policy, not distributed health quorum or last-known-good storage.
