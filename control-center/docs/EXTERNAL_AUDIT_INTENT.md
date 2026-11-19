# External audit intent receipt (experimental, opt-in)

Issue #38 increment: route approval and config restore only. This adds an authenticated, bounded pre-mutation HTTPS guard, not a full immutable audit system. Existing local audit remains unchanged. The gateway data plane never calls the collector.

Set all four environment variables or none:

| Variable | Contract |
|---|---|
| GATEWAY_AUDIT_INTENT_URL | Exact HTTPS endpoint /audit/v1/intents, with normal trusted TLS, no credentials, query, fragment, redirects or ambient proxy |
| GATEWAY_AUDIT_NODE_ID | Stable ASCII alphanumeric, underscore or hyphen, 1..48 characters |
| GATEWAY_AUDIT_SENDER_KEY_FILE | Absolute non-symlink file of exactly 32 random binary bytes, owner-only on Unix; on Windows restrict ACL to the service account and protected administrators |
| GATEWAY_AUDIT_COLLECTOR_PUBLIC_KEY_FILE | Absolute non-symlink PEM SubjectPublicKeyInfo RSA public key (2048..4096 bits); integrity-protect the file/parent directory with OS permissions |

Generate and distribute sender keys independently for each node. The collector private signing key must never be installed on the gateway. Partial configuration or invalid key files fail startup. No built-in collector, no automatic retries; configure endpoint trust and access by separate operators.

## Collector contract

The gateway POSTs a bounded JSON intent containing schema, eventId, node, UTC, authenticated actor, operation, current config SHA-256 and target config SHA-256. No config payload, secrets or arbitrary administrative notes are transmitted. The exact serialized UTF-8 bytes are the signed message. X-GC-Audit-Event-Id is the lowercase GUID N format. X-GC-Audit-Signature is Base64 HMAC-SHA256 with the node sender key over ASCII:

```text
GatewayCore-Audit-Intent-v1\n<eventId>\n<uppercase hex SHA256(body)>
```

The external collector must independently validate authentication and schema, enforce node identity/unique event IDs, persist the exact intent to its append-only storage, and only then return HTTP 201 plus exactly one X-GC-Audit-Receipt containing Base64 RSA-PSS/SHA256 signature of ASCII:

```text
GatewayCore-Audit-Receipt-v1\n<eventId>\n<uppercase hex SHA256(body)>
```

The gateway uses the configured public key to verify the receipt. Missing, stale/replayed, duplicated, forged or unavailable receipts return HTTP 503 without applying/replacing config. The deadline is five seconds with three-second connection timeout. Successful receipt authorizes an *intent*, not a guarantee the subsequent write succeeds. A later write failure may leave an intent without completion, which independent operators must reconcile. No retry of the original action occurs automatically.

## Boundary

This first increment is deliberately limited to approved configuration writes and restores. Other mutations, authentication events, rejected attempts, fleet rollout, centralized outcome records, durable retry spool, signed chain/ordered receipts, rotation, real collector retention/WORM/legal hold, multi-replica behavior and live outage/network testing remain open. The test handler exercises receipt binding and negative responses; it does not establish actual external persistence. Do not call this an immutable external audit or claim production readiness until a separate collector implementation and real retention/correlation tests exist. OIDC/FIDO2 remain separate issue #38 work.
