# Authoritative DNS source firewall

This opt-in host-wide policy applies only to DNS UDP/TCP listeners, not agent report or metrics endpoints. In the existing independently reviewed signed GSLB engine JSON, set:

```json
"BlockedResolverCidrs": ["192.0.2.0/24", "2001:db8::/32"]
```

These are documentation ranges; replace them with your approved resolver networks. Omitted or an explicitly empty array means no blocked networks. Maximum 128 distinct IPv4/IPv6 networks; /0, malformed, mapped, scoped, duplicate and explicit null values are refused. IPv4-mapped socket peers are normalized to IPv4. ECS does not affect admission. UDP datagrams receive no response; TCP peers are closed before acquiring a bounded session slot. The operator must consider shared recursive resolvers and NAT: blocking a resolver blocks all its clients. The setting is node-wide, so validate the same intended policy on all authorities before rollout.

Use the existing signed engine review, rollout and rollback process. Confirm an allowed resolver still receives correct authoritative answers, and an intentionally blocked disposable test resolver receives no response. Monitor gatewaycore_gslb_dns_firewall_blocked_total with transport label only; it counts UDP datagrams or TCP connections and exports no peer addresses. Counters reset on restart. Remove entries via reviewed deployment or restore previous signed configuration. Do not use as a substitute for upstream volumetric DDoS mitigation.

This is source-network admission, not recursive RPZ/content filtering, DNS answer caching, or physical acceptance. No new standalone configuration UI is claimed.
