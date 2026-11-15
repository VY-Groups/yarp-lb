# HAProxy-inspired authenticated peer telemetry (experimental, opt-in)

The read-only `ha-praxy` source provides design reference for bounded peer updates and replay handling. **No HAProxy GPL source has been incorporated.** This feature synchronizes *per-peer hashed request counters*, not active connections, sessions, stickiness, config revisions, or exact admission budgets.

## Enable on two independent gateway nodes

Configure both with identical `GATEWAY_PEER_SYNC_SECRET` (>=32 UTF-8 bytes) from a secret provider, plus reciprocal settings:

| Variable | Node A | Node B |
| --- | --- | --- |
| `GATEWAY_PEER_SYNC_NODE_ID` | `node-a` | `node-b` |
| `GATEWAY_PEER_SYNC_REMOTE_ID` | `node-b` | `node-a` |
| `GATEWAY_PEER_SYNC_REMOTE_URL` | `https://node-b.internal:8443/gateway/internal/peer-sync` | `https://node-a.internal:8443/gateway/internal/peer-sync` |

Optional `GATEWAY_PEER_SYNC_CAPACITY` default 2048 (1..2048), `GATEWAY_PEER_SYNC_INTERVAL_SECONDS` default 2 (1..30). All configured values must be present and validated at startup. Peers must use a **real trusted Kestrel HTTPS listener**; HTTP, embedded URL credentials, redirects, arbitrary paths, unsigned messages and stale/replayed nonces are rejected. Never bypass server certificate verification. Disable proxying `/gateway/internal/peer-sync` from the public VIP; route this endpoint only over a private, firewall-restricted peer network.

A sender emits one bounded snapshot per interval, signed by HMAC-SHA256 over sender identity, UTC timestamp, random nonce and SHA-256 of the serialized body. The receiver checks the expected node ID, a 30-second time window, single-use nonces, a 256 KiB body cap and monotonic per-minute sequence and counts. Client IP values are HMAC-hashed, never sent in plaintext. Received identity keys are restricted to 64 hex characters; accepted identity cardinality is capped to 2048 so a worst-case hexadecimal-key JSON snapshot stays under the signed 256 KiB transport ceiling, and old per-minute snapshots cease to be reported when the window advances.

**Availability/consistency:** best-effort telemetry gossip can diverge during partitions. It has no quorum, replay of CA requests, external mutation or leader election, and MUST NEVER be used to enforce a strict global quota. To enforce an atomic shared limit across nodes, use the independent opt-in `SharedPeerRateLimiter` single Redis writer. Its own fail-closed 503 behavior on disconnect remains unchanged. Asynchronous Redis replica promotion can also lose writes and is NOT certified for hard limits.

The signed protocol has deterministic unit tests; a full production mTLS/PKI peer session, independent-host fault isolation and on-prem NIC throughput remain unverified until measured. Passing software CI is not production permission.
