# Experimental shared rate quota (opt-in; not v1 HA)

This is an **independent implementation** inspired by the bounded table and peer-update problems in HAProxy 3.4.7 (`ha-praxy/src/stick_table.c`, `src/peers.c`). No GPL C source is copied. This is **not** HAProxy peer synchronization, distributed health consensus, VRRP, multi-primary replication, or a production-certified failover mechanism.

## Behavior

Without `GATEWAY_PROXY_SHARED_REDIS`, GatewayCore continues to use its existing process-local `BoundedPeerRateTable`. To opt into the experimental global quota, configure **identical** values on both gateway nodes:

| Environment | Requirement |
| --- | --- |
| `GATEWAY_PROXY_SHARED_REDIS` | StackExchange.Redis connection string to a **single mutually reachable TLS endpoint**, e.g. `redis.example.internal:6380,ssl=true,sslHost=redis.example.internal,abortConnect=true`. Never relax server certificate verification |
| `GATEWAY_PROXY_SHARED_HMAC_KEY` | Secret UTF-8 key of at least 32 bytes, identical on both nodes; store in a protected secret provider, not in source, GitHub Actions, or command output |
| `GATEWAY_PROXY_IP_RATE_PER_MINUTE` | 1–1,000,000 requests per **Redis-server-clock UTC minute** per normalized peer IP |
| `GATEWAY_PROXY_IP_TABLE_CAPACITY` | 1–65,536 distinct peers per window (default 4,096) |
| `GATEWAY_PROXY_SHARED_NAMESPACE` | Identical isolated namespace across nodes (default `gatewaycore:quota:v1`, ASCII alphanumeric/colon/dash/underscore, <=80 chars) |

A single Lua transaction, evaluated on one Redis writer, enforces the shared per-IP budget and per-minute peer cardinality ceiling. A cryptographic HMAC of the actual TCP peer IP is the stored key; untrusted `X-Forwarded-For` is ignored. IPv4-mapped IPv6 is normalized. Keys expire after two minutes; the scope uses Redis time rather than each gateway's clock, eliminating gateway-clock drift within one Redis writer.

**Partition policy:** If the Redis connection fails or an atomic command times out, GatewayCore responds **503**, never admits traffic under an independent fallback quota. Reaching a peer quota or peer-cardinality cap returns **429**. No request is replayed. This is intentionally availability-reducing to avoid rate-limit double-spending during a lost connection.

**Critical constraints:** The server uses fixed windows, not HAProxy rolling request rates. Redis failover with asynchronous replication can lose acknowledged writes and therefore violate strict quotas. For an exact global cap, do not auto-promote asynchronous replicas: use one writer with a site-approved availability/fencing design. Redis Cluster and Redis Sentinel discovery are **not supported by this pilot**; no peer-to-peer gossip or quorum implementation has been added. Multiple gateway instances sharing one Redis writer can be tested in CI, but a physical partition, WAN latency, production TLS trust store, reverse-proxy identity, leader fencing, 500 Mbps sustained capacity and NIC/VRRP/ECMP failover are **NOT TESTED**.

## Testing

`.github/workflows/shared-quota-redis.yml` compiles the real Control Center, executes the exact embedded Lua transaction against disposable local Redis, and tests concurrent quota oversubscription, per-window identity bounds, isolation and unavailable connection behavior. The atomic Lua unit test uses plaintext **loopback-only** Redis. A separate `shared-quota-two-nodes.yml` CI workflow starts two real GatewayCore Linux containers using an authenticated TLS Redis server and an ephemeral trusted CA, asserts seven globally admitted requests/five 429 rejections across the two processes, then disconnects Redis and requires 503 from each process. Both gateways and Redis run on the **same disposable GitHub Actions host**, so this is a software-level integration and partition simulation, not independent fault-domain or physical HA certification.

This experimental mode must remain disabled for existing signed-config on-prem v1. Version 1 still follows `control-center/docs/V1_HA_SCOPE.md`. **Production NO-GO** until dedicated host and security evidence is approved.
