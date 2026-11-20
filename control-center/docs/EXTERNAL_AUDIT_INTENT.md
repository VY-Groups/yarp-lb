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

This increment covers approved configuration writes/restores, the four explicit administrator account operations, and inventory/fleet registration and removal. Other mutations, authentication events, rejected attempts, fleet rollout, centralized outcome records, durable retry spool, signed chain/ordered receipts, rotation, real collector retention/WORM/legal hold, multi-replica behavior and live outage/network testing remain open. The test handler exercises receipt binding and negative responses; it does not establish actual external persistence. Do not call this an immutable external audit or claim production readiness until a separate collector implementation and real retention/correlation tests exist. OIDC/FIDO2 remain separate issue #38 work.

The gateway rejects pre-canceled or late-canceled confirmation and control characters in the actor. Both protected configuration operations recheck their original configuration bytes after waiting for the collector; a changed baseline returns conflict rather than using a stale receipt. The existing process-local configuration gate is retained. This is not a distributed filesystem transaction or rollback of an already-started write; prohibit concurrent out-of-band file editors.


## Administrator account protection

The four USER_CREATE_INTENT, USER_PASSWORD_RESET_INTENT, USER_DISABLE_INTENT and USER_ENABLE_INTENT operations require authenticated collector receipts when the gate is configured. Under the existing account mutation lock, the gateway verifies the actor is still an enabled Administrator with the current session security stamp and binds the exact original and proposed account-file bytes by SHA-256. No passwords, salts, hashes, email addresses or raw account-file bytes are sent. Missing, forged or late receipts return 503 without changing persisted account state. A baseline changed during confirmation returns 409. Ordinary role enforcement and local audit remain; the data plane does not call the collector. Install the upgraded collector before enabling these operations. The original intent schema is retained with explicit additional operation names; an older collector will deny them.

The disposable Ubuntu CI test runs the actual gateway and collector over trusted HTTPS and verifies before/after digests, collector outage denial and recovery for all four operations. Unit receipt-validation tests and Windows collector contract/build tests remain enabled. This is not a full asynchronous gateway-wide audit spool: login, bootstrap, other security events, fleet, mail/directory settings, outcome correlation and distributed identity revocation remain tracked in #38. Production provider/retention acceptance remains #36.

## Inventory and fleet registration protection

INVENTORY_ADD_INTENT / INVENTORY_DELETE_INTENT and FLEET_REGISTER_INTENT / FLEET_UNREGISTER_INTENT are explicit allowed operations. Inventory mutations retain Administrator/Operator RBAC; fleet registration/removal requires Administrator. Before and after waiting for the signed receipt, the gateway revalidates the actor's enabled local account, session stamp, role and (for mapped OIDC identities) recent authentication and revocation cutoff. Existing per-resource write locks remain held during confirmation. The exact UTF-8 serialized proposed state is flushed to a private temporary file and atomically replaces the resource file; no private addresses, notes, certificate thumbprints or other payload fields are sent. Missing state has the SHA-256 digest of an empty byte array. Receipt failure/cancellation returns 503, actor failure returns 403 and unexpected state changes return 409. No automatic replay. The resource locks are process-local; an already-authorized write is not a distributed transaction or retroactively cancellable. Install an updated collector before enabling these operations. The real gateway/collector disposable test checks outage denial and recovery, exact state digest binding, role preservation and the fixed redacted envelope. Other mail/directory, fleet rollout, authentication, outcome and durable delivery requirements remain in #38.

## SMTP and directory policy protection

MAIL_SETTINGS_INTENT, MAIL_PROOF_INTENT and DIRECTORY_SETTINGS_INTENT bind the exact encrypted settings/proof bytes before persistence. SMTP and LDAPS writes share one serial management lock; the SMTP test uses the same immutable settings snapshot for actual STARTTLS delivery and the proof fingerprint. The LDAP service prepares and validates its candidate (including existing TLS/bind/group validation when enabled) without persisting it; the endpoint commits only after a signed receipt and current verified OTP prerequisite. The SMTP test can deliver an email before the collector confirms persistence of its proof: a receipt failure returns 503 and leaves the proof unchanged, not a claim that the email was unsent. The sender never automatically repeats a test, and OTP remains disabled until a proof for the current configuration exists. OTP delivery uses a single verified settings snapshot. Existing frontend/API shapes, STARTTLS and directory certificate requirements remain. On collector outage the existing verified settings are not replaced; upgrades must install the matching collector first. The disposable Linux fixture verifies real SMTP STARTTLS delivery and denial/recovery of all three persisted artifacts, with directory disabled to avoid contacting a real domain. Existing enabled LDAPS validation is unchanged; live domain acceptance stays #36. This does not complete authentication-event export, fleet rollout, setup/onboarding, durable gateway-side audit or distributed revocation.
