# Experimental standalone GSLB DNS engine — 0.1

Separate .NET 10 authoritative DNS-style **UDP A-record responder**, not a YARP HTTP route. Configured names return a weighted IPv4 site whose HTTP health probe is currently successful. If a site's health fails, it is removed from DNS answers; when all sites fail, the server returns DNS **SERVFAIL**. Names outside the explicit configuration return REFUSED. The response preserves DNS transaction ID and applies a bounded 5–300-second TTL.

GitHub Actions tests actual UDP DNS packet responses and HTTP health transitions on Windows and Ubuntu with no public DNS delegation. The default listener is loopback-only; a non-loopback address requires `AllowNonLoopbackListeners=true`.

## Boundaries

**This is not production GSLB yet.** Real authoritative DNS must support TCP fallback, AAAA, CNAME/MX/NS/SOA, EDNS, DNSSEC/TSIG, zone delegation, secondary replication, DDoS defense, geographic policy, provider integration, regional probes/quorum, DNS TTL caching/failback control, and monitored operation. Health probes are local to this one process: they do not establish geographically distributed observations. DNS clients/caches can continue using stale TTL answers after site failure. Do not delegate live production domains to this prototype.
