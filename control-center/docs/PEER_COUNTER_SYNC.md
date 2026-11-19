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

A sender emits one bounded full snapshot or acknowledged-base delta per interval, signed by HMAC-SHA256 over sender identity, UTC timestamp, random nonce and SHA-256 of the serialized body. Protocol version 4 explicitly identifies its only supported table as `hashed-client-minute-request-count`, table schema version 1, with a 60-second entry lifetime. Unknown protocol/table/schema/TTL values fail closed; peers must be upgraded together because there is no version negotiation or mixed-version fallback. The receiver checks the expected node ID, a 30-second time window, single-use nonces, a 256 KiB body cap and monotonic per-minute sequence and counts. Client IP values are HMAC-hashed, never sent in plaintext. Received identity keys are restricted to 64 hex characters; accepted identity cardinality is capped to 2048 so a worst-case hexadecimal-key JSON snapshot stays under the signed 256 KiB transport ceiling. Local and remote table entries are collected when the minute/monotonic freshness boundary is observed; remote expiry retains epoch/sequence replay high-water marks.

This contract is deliberately one typed table only. It implements absolute-counter deltas for this single table and full snapshot backfill; generic table negotiation and multi-peer fanout remain unsupported. Those remain open parts of issue #101, along with operator UI/metrics and physical partition/soak acceptance.

**Availability/consistency:** best-effort telemetry gossip can diverge during partitions. It has no quorum, replay of CA requests, external mutation or leader election, and MUST NEVER be used to enforce a strict global quota. To enforce an atomic shared limit across nodes, use the independent opt-in `SharedPeerRateLimiter` single Redis writer. Its own fail-closed 503 behavior on disconnect remains unchanged. Asynchronous Redis replica promotion can also lose writes and is NOT certified for hard limits.

The signed protocol has deterministic unit tests; a full production mTLS/PKI peer session, independent-host fault isolation and on-prem NIC throughput remain unverified until measured. Passing software CI is not production permission.

## Process-restart resynchronization

Protocol v4 also binds every signed snapshot to a random 256-bit receiver
boot challenge. A valid HMAC request with an absent or obsolete challenge
gets HTTP 409 and a no-store `X-GC-Peer-Receiver-Epoch` response header;
it cannot populate the receiving journal. The publisher learns that value
only from its configured HTTPS peer (normal certificate verification,
no redirects) and sends a newly signed snapshot on its next periodic tick.
The first exchange after either node restarts may therefore require one
extra interval. Captured snapshots for a previous receiver boot cannot
be reapplied, even when that receiver starts with an empty nonce cache.
Changing a challenge in a captured payload invalidates its HMAC. Both
peers must upgrade together; there is no v2/v3 fallback. Keep peer endpoints
firewall-restricted. This is receiver boot binding, not durable counter
storage, persistent source epoch allocation or protection against a stolen
shared secret.

The signed snapshot now carries a process boot-epoch (UTC milliseconds), plus the per-minute sequence. Within one epoch and minute, sequence and counters must progress monotonically; after a peer restarts with a strictly newer boot epoch, the receiving peer can intentionally reset that sender's counters and resume normal gossip. Older epochs are rejected even if they present a higher sequence. Epoch changes are never permission to use gossip for strict admission.

**Clock requirement:** Restart epochs rely on non-regressing host clocks. If a node's clock moves backward before an earlier accepted boot epoch, synchronization intentionally fails closed until the issue is corrected. Tomorrow's live drill should check NTP time synchronization, process restarts while requests continue, delayed/duplicate peer frames, and recovery within the minute. The in-memory signed protocol remains two-node only and does not implement HAProxy's multi-table wire protocol or peer full-state learning.


## Freshness expiry (operational telemetry only)

Remote counters are visible only when the signed snapshot is from the current
minute AND the last accepted receipt is sufficiently recent. The shipping
service configures the freshness window as three configured publish intervals,
clamped to 6–60 seconds (default publisher interval 2s, so default 6s).
When a peer stops sending, the status API and remote telemetry counts become
unavailable even before the current minute rolls over. The last receipt time
remains available to the operator to diagnose outages, but expired request
counts are withheld.

A higher-sequence, properly authenticated fresh snapshot restores reporting.
Receipt-age expiry uses the process monotonic clock (`TimeProvider`), so NTP
correction or wall-clock rollback cannot lengthen or prematurely expire this
TTL. The authenticated `/admin/api/peer-sync/status` view exposes the last
accepted UTC timestamp and monotonic `lastAcceptedAgeSeconds`; the operator UI
uses monotonic age when deciding whether an exchange is recent. The protected
`/gateway/metrics` scrape exposes fixed-cardinality `yarp_peer_sync_enabled`,
`yarp_peer_sync_remote_fresh`, and `yarp_peer_sync_last_accepted_age_seconds`
gauges without node, IP, identity or secret labels. Age remains observable after
remote counters expire; it is `NaN` until the first accepted frame and resets
only after a newly accepted frame or process restart. The current-minute protocol check still uses UTC wall time; if that minute
is incorrect or regresses, snapshots fail closed until the minute agrees again.
Within one source epoch, frames from a minute older than the last accepted minute
are rejected, so a receiver clock rollback cannot replace newer telemetry with a
delayed prior-minute snapshot.
Expiry NEVER resets the remote boot epoch or previously accepted sequence:
replaying an old signed frame cannot revive stale counts. A local clock moved
backward does not change elapsed receipt age. Tests use separate controllable
wall and monotonic clocks for deterministic rollback, expiry, recovery,
replay and delayed lower-sequence checks; rejecting a delayed frame does not
refresh the accepted receipt's TTL.

**Strict enforcement is not provided**: this expiry is about best-effort
telemetry only. No synchronized HAProxy stick tables, request admission,
session persistence, signed config consensus or physical HA are claimed.
Network partitions and stale distributed quota remain production NO-GO.

## Protocol v4 delta/backfill

A zero BaseSequence is a full snapshot; a positive BaseSequence must match the exact currently fresh receiver sequence in the same source epoch and minute. Deltas carry absolute changed counter values, not increments; unchanged identities are retained, reductions and merged capacity overflow are rejected. The publisher keeps one bounded acknowledged full image and uses a smaller delta only after successful HTTPS delivery. Any HTTP failure, transport exception, minute change or receiver boot change forces a full snapshot on the next eligible tick. Expired state rejects deltas until full backfill. No mixed v3/v4 compatibility: upgrade both peers together and monitor recovery; rollback both together. This remains best-effort telemetry, not strict admission authority. Physical restart/partition and soak testing remain required.

### Real HTTPS acceptance (review supplemental)

Linux full-application CI starts two shipping gateway processes and a disposable TLS relay using a trusted lab certificate. The publisher learns the receiver boot challenge, establishes a full snapshot, transmits an absolute-counter delta, and receives a 204 acknowledgment. A relay deliberately acknowledges but does not deliver one delta: the next exact-base frame is rejected with 409 and the actual publisher sends a full backfill. Restarting the receiver changes its boot challenge, rejects a newly signed obsolete-epoch frame, and recovers from a fresh publisher snapshot. The receiver operator endpoint verifies counters, and a tampered HMAC is rejected over HTTPS. The relay is test-only, not a production endpoint or a claim of durable ACK. Both peers must upgrade together directly to v4 (or both roll back together); no v2/v3 mixed pairing is supported. Physical partitions, key rotation, Windows real HTTPS peer and production soak remain pending until separately tested.
