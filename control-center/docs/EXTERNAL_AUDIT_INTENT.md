# External audit intent receipt (experimental, opt-in)

Issue #38 increment: route approval, config restore, and administrator account create, password reset, disable and enable. This adds an authenticated, bounded pre-mutation HTTPS guard, not a full immutable audit system. Existing local audit remains unchanged. The gateway data plane never calls the collector.

Set all four environment variables or none:

| Variable | Contract |
|---|---|
| GATEWAY_AUDIT_INTENT_URL | Exact HTTPS endpoint /audit/v1/intents, with normal trusted TLS, no credentials, query, fragment, redirects or ambient proxy |
| GATEWAY_AUDIT_NODE_ID | Stable ASCII alphanumeric, underscore or hyphen, 1..48 characters |
| GATEWAY_AUDIT_SENDER_KEY_FILE | Absolute non-symlink file of exactly 32 random binary bytes, owner-only on Unix; on Windows restrict ACL to the service account and protected administrators |
| GATEWAY_AUDIT_COLLECTOR_PUBLIC_KEY_FILE | Absolute non-symlink PEM SubjectPublicKeyInfo RSA public key (2048..4096 bits); integrity-protect the file/parent directory with OS permissions |

Generate and distribute sender keys independently for each node. The collector private signing key must never be installed on the gateway. Partial configuration or invalid key files fail startup. An independent collector is provided in engines/AuditCollector; the gateway intent request itself does not retry. Configure endpoint trust and access by separate operators.

## Collector contract

The gateway POSTs a bounded JSON intent containing schema, eventId, node, UTC, authenticated actor, operation, current state SHA-256 and proposed state SHA-256. No config payload, secrets or arbitrary administrative notes are transmitted. The exact serialized UTF-8 bytes are the signed message. X-GC-Audit-Event-Id is the lowercase GUID N format. X-GC-Audit-Signature is Base64 HMAC-SHA256 with the node sender key over ASCII:

```text
GatewayCore-Audit-Intent-v1\n<eventId>\n<uppercase hex SHA256(body)>
```

The external collector must independently validate authentication and schema, enforce node identity/unique event IDs, persist the exact intent to its append-only storage, and only then return HTTP 201 plus exactly one X-GC-Audit-Receipt containing Base64 RSA-PSS/SHA256 signature of ASCII:

```text
GatewayCore-Audit-Receipt-v1\n<eventId>\n<uppercase hex SHA256(body)>
```

The gateway uses the configured public key to verify the receipt. Missing, stale/replayed, duplicated, forged or unavailable receipts return HTTP 503 without applying/replacing config. The deadline is five seconds with three-second connection timeout. Successful receipt authorizes an *intent*, not a guarantee the subsequent write succeeds. A later write failure may leave an intent without completion, which independent operators must reconcile. No retry of the original action occurs automatically.

## Boundary

This increment covers approved configuration writes/restores and the four explicit administrator account operations. Other mutations, authentication events, rejected attempts, fleet rollout, centralized outcome records, durable retry spool, signed chain/ordered receipts, rotation, real collector retention/WORM/legal hold, multi-replica behavior and live outage/network testing remain open. The test handler exercises receipt binding and negative responses; it does not establish actual external persistence. Do not call this an immutable external audit or claim production readiness until a separate collector implementation and real retention/correlation tests exist. OIDC/FIDO2 remain separate issue #38 work.

The gateway rejects pre-canceled or late-canceled confirmation and control characters in the actor. Both protected configuration operations recheck their original configuration bytes after waiting for the collector; a changed baseline returns conflict rather than using a stale receipt. The existing process-local configuration gate is retained. This is not a distributed filesystem transaction or rollback of an already-started write; prohibit concurrent out-of-band file editors.


## Administrator account protection

The four USER_CREATE_INTENT, USER_PASSWORD_RESET_INTENT, USER_DISABLE_INTENT and USER_ENABLE_INTENT operations require authenticated collector receipts when the gate is configured. Under the existing account mutation lock, the gateway verifies the actor is still an enabled Administrator with the current session security stamp and binds the exact original and proposed account-file bytes by SHA-256. No passwords, salts, hashes, email addresses or raw account-file bytes are sent. Missing, forged or late receipts return 503 without changing persisted account state. A baseline changed during confirmation returns 409. Ordinary role enforcement and local audit remain; the data plane does not call the collector. Install the upgraded collector before enabling these operations. The original intent schema is retained with explicit additional operation names; an older collector will deny them.

The disposable Ubuntu CI test runs the actual gateway and collector over trusted HTTPS and verifies before/after digests, collector outage denial and recovery for all four operations. Unit receipt-validation tests and Windows collector contract/build tests remain enabled. This is not a full asynchronous gateway-wide audit spool: login, bootstrap, other security events, fleet, mail/directory settings, outcome correlation and distributed identity revocation remain tracked in #38. Production provider/retention acceptance remains #36.

## Durable recorded-event outbox (opt-in)

Upgrade the independent collector before enabling GATEWAY_AUDIT_OUTBOX_DIR. Provide the existing four external-audit variables and set the new variable to a dedicated, pre-provisioned absolute private directory owned by the gateway service account (0700 on Linux; restricted service-identity ACL on Windows). Do not share it with another process or node. Retain it across upgrades and restarts. A single exclusive owner handle protects ordinary simultaneous access. Capacity is 4096 records of at most 8192 bytes each. Each record is authenticated with the node key, flushed to a new file and atomically renamed before the local audit append. Do not remove pending/temporary records, rotate the sender key or downgrade while records are unresolved. If startup detects corrupt/incomplete state, stop and reconcile against the local and collector ledgers; do not delete evidence. Backup, filesystem and parent-directory durability/permissions remain operational prerequisites.

Every event passed through LocalAdminAudit becomes a schema-2 historical envelope: node, stable event ID, original UTC, actor, action and SHA-256 of the exact UTF-8 local JSON line (excluding newline). Invalid externally supplied actor strings are represented by a digest; details, credentials, email fields and raw tokens are never included. The existing local log retains its prior contents and format. A separate event MAC and RSA-PSS receipt purpose prevent recorded-event acknowledgments from authorizing a mutation. The collector retains the same envelope only once and can reissue a receipt for the exact already-committed schema-2 record, including after restart; changed bytes under an existing ID and duplicate schema-1 intents are rejected. Historical delivery permits up to 30 days of age and 60 seconds future skew; Object Lock retention is still calculated from the signed original time, so an older record that cannot meet the original retention requirement remains blocked. Never shorten retention or silently discard expired records. Queue ordering is not a global chronology claim.

A background worker retries in bounded batches; the queue removes a record only after a valid, exact-body receipt and local revalidation. Administrator GET /admin/api/audit/delivery returns enabled, pending, storageFault and deliveryBlocked; inspect this and the transition warnings before accepting a rollout. A full queue reports a local operation error but can still drain. A filesystem or authentication fault latches until operator recovery. Local evidence is appended even if enqueue fails, and the error is propagated. Audit callbacks can run *after* an administrative side effect, so this does not make the side effect and outbox atomic, guarantee every failed operation is blocked, or backfill direct audit writers that bypass LocalAdminAudit. No data-plane request is retried. Explicit intent receipts remain unchanged, including their strict freshness/replay protection. Structured intent/outcome correlation, transactional pre-reservation, distributed revocation and other direct audit call sites remain in #38.

Tests: Windows/Linux security contract checks cover outbox reopening, blocked delivery and corrupted/incomplete records. Linux disposable shipping gateway + collector HTTPS acceptance covers collector outage, persisted event recovery across gateway restart, exact local digest, successful drain, exact duplicate receipt and changed-payload/MAC rejection. No production credentials or real storage are used. Keep the parent audit integration PRs intact and validate the combined version before deployment.

### Shared setup/profile audit writer

Routing freeze enable/disable and organization profile changes use the same `LocalAdminAudit` instance as other administrator events, rather than appending independently to `admin-audit.jsonl`. This serializes writes and routes the two paths through the optional outbox when enabled. The organization event now uses the standard `details` object (`revision`, `organizationName`, `sector`); legacy existing rows retain their original top-level fields. Consumers reading historical records should handle both shapes. Notes are not included. Existing RBAC, CSRF and revision checks remain in place. These are post-write outcomes: an audit failure after state mutation can still leave committed state, so this is not a transactional intent/outcome guarantee, nor a replacement for signed pre-commit receipts. The combined collector acceptance exercises both freeze outcomes and the organization profile update during an outage, then checks exact queued digests and durable delivery after restart.

## Account intent/outcome correlation (initial scope)

For the four signed administrator account operations, retain the verified intent ID in the local success row. With the opt-in outbox enabled, persist an ACCOUNT_MUTATION_PREPARED event before writing the account state; if preparation fails (including full or faulty queue), return 503 with unchanged account bytes. The recorded-event schema retains the same eight fields and separate historical-event MAC/receipt purpose. For these five explicitly named account events only, a nonzero revision is SHA-256 of the lowercase intent GUID ASCII; join to the original schema-1 intent on the same node. targetDigest remains the SHA-256 of the exact local JSON line, now containing intentId. Uncorrelated historical events still use zero revision. Upgrade the collector before enabling this increment; new collectors accept old events. The prepared row is NOT success, and a missing success row is unresolved, never evidence that the account mutation did not occur. The external intent's before/after hashes and the local prepared row support operator reconciliation. The write and post-write enqueue are separate filesystem operations; this is not a crash-atomic transaction, reserved outcome slot, guaranteed automatic recovery, or cross-replica correlation. Do not replay a mutation on a missing outcome. Further journal/reconciliation and other administrative mutations remain #38 work. Tests exercise the four real account mutations with signed receipts and outbox delivery plus a simulated precommit storage fault.
