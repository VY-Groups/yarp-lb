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

## Topology and change-review workflow protection

TOPOLOGY_DRAFT_INTENT and TOPOLOGY_CONFIRM_INTENT require a signed receipt before changing onboarding metadata or creating a backup. The existing revision check, architecture validation and independent-approval requirement stay in place; the exact serialized state is flushed and atomically replaced. Topology events now use the shared local audit writer rather than directly appending to its file. CHANGE_REQUEST_INTENT and CHANGE_REJECT_INTENT protect creation and rejection of change requests under the existing review gate and role checks. Approval still requires the existing CONFIG_APPLY_INTENT; an atomic joint configuration and review-outcome transaction is not implemented. Account confirmation now uses the shared before/after actor fence, including recent federated authentication. A denied receipt leaves the protected file unchanged; no automatic operation retry. The disposable gateway/collector acceptance checks draft/confirm, submission and independent rejection during outage and recovery, exact SHA-256 state binding, and existing RBAC. Existing configurations remain compatible when the collector is not configured; install the newer collector first. Fleet rollout, other settings endpoints, gateway-wide durable outcome delivery and distributed identity revocation remain open in #38.

## Inventory/fleet account commit fence

Inventory add/delete and fleet membership changes acquire the account mutation gate only after collector confirmation, then revalidate the session security stamp, role, OIDC cutoff, cancellation and exact resource baseline while holding it through the durable resource write. Existing account mutations already hold that gate; do not reacquire it inside the account confirmation path. With external audit disabled the existing resource write behavior is retained. The disposable HTTPS collector acceptance uses a receipt barrier to verify that inventory cannot commit concurrently with an account reset, and that revoking the requesting account before its receipt returns denies the pending mutation without changing resource bytes. These are local-process fences, not distributed session revocation or globally atomic audit outcomes. Other resource and rollout operation commit fences still require separate review.

## Durable recorded-event outbox (opt-in)

Upgrade the independent collector before enabling GATEWAY_AUDIT_OUTBOX_DIR. Provide the existing four external-audit variables and set the new variable to a dedicated, pre-provisioned absolute private directory owned by the gateway service account (0700 on Linux; restricted service-identity ACL on Windows). Do not share it with another process or node. Retain it across upgrades and restarts. A single exclusive owner handle protects ordinary simultaneous access. Capacity is 4096 records of at most 8192 bytes each. Each record is authenticated with the node key, flushed to a new file and atomically renamed before the local audit append. Do not remove pending/temporary records, rotate the sender key or downgrade while records are unresolved. If startup detects corrupt/incomplete state, stop and reconcile against the local and collector ledgers; do not delete evidence. Backup, filesystem and parent-directory durability/permissions remain operational prerequisites.

Every event passed through LocalAdminAudit becomes a schema-2 historical envelope: node, stable event ID, original UTC, actor, action and SHA-256 of the exact UTF-8 local JSON line (excluding newline). Invalid externally supplied actor strings are represented by a digest; details, credentials, email fields and raw tokens are never included. The existing local log retains its prior contents and format. A separate event MAC and RSA-PSS receipt purpose prevent recorded-event acknowledgments from authorizing a mutation. The collector retains the same envelope only once and can reissue a receipt for the exact already-committed schema-2 record, including after restart; changed bytes under an existing ID and duplicate schema-1 intents are rejected. Historical delivery permits up to 30 days of age and 60 seconds future skew; Object Lock retention is still calculated from the signed original time, so an older record that cannot meet the original retention requirement remains blocked. Never shorten retention or silently discard expired records. Queue ordering is not a global chronology claim.

A background worker retries in bounded batches; the queue removes a record only after a valid, exact-body receipt and local revalidation. Administrator GET /admin/api/audit/delivery returns enabled, pending, storageFault and deliveryBlocked; inspect this and the transition warnings before accepting a rollout. A full queue reports a local operation error but can still drain. A filesystem or authentication fault latches until operator recovery. Local evidence is appended even if enqueue fails, and the error is propagated. Audit callbacks can run *after* an administrative side effect, so this does not make the side effect and outbox atomic, guarantee every failed operation is blocked, or backfill direct audit writers that bypass LocalAdminAudit. No data-plane request is retried. Explicit intent receipts remain unchanged, including their strict freshness/replay protection. Structured intent/outcome correlation, transactional pre-reservation, distributed revocation and other direct audit call sites remain in #38.

Tests: Windows/Linux security contract checks cover outbox reopening, blocked delivery and corrupted/incomplete records. Linux disposable shipping gateway + collector HTTPS acceptance covers collector outage, persisted event recovery across gateway restart, exact local digest, successful drain, exact duplicate receipt and changed-payload/MAC rejection. No production credentials or real storage are used. Keep the parent audit integration PRs intact and validate the combined version before deployment.

### Shared setup/profile audit writer

Routing freeze enable/disable and organization profile changes use the same `LocalAdminAudit` instance as other administrator events, rather than appending independently to `admin-audit.jsonl`. This serializes writes and routes the two paths through the optional outbox when enabled. The organization event now uses the standard `details` object (`revision`, `organizationName`, `sector`); legacy existing rows retain their original top-level fields. Consumers reading historical records should handle both shapes. Notes are not included. Existing RBAC, CSRF and revision checks remain in place. These are post-write outcomes: an audit failure after state mutation can still leave committed state, so this is not a transactional intent/outcome guarantee, nor a replacement for signed pre-commit receipts. The combined collector acceptance exercises both freeze outcomes and the organization profile update during an outage, then checks exact queued digests and durable delivery after restart.

## Account intent/outcome correlation (initial scope)

For the four signed administrator account operations, retain the verified intent ID in the local success row. With the opt-in outbox enabled, persist an ACCOUNT_MUTATION_PREPARED event before writing the account state; if preparation fails (including full or faulty queue), return 503 with unchanged account bytes. The recorded-event schema retains the same eight fields and separate historical-event MAC/receipt purpose. For these five explicitly named account events only, a nonzero revision is SHA-256 of the lowercase intent GUID ASCII; join to the original schema-1 intent on the same node. targetDigest remains the SHA-256 of the exact local JSON line, now containing intentId. Uncorrelated historical events still use zero revision. Upgrade the collector before enabling this increment; new collectors accept old events. The prepared row is NOT success, and a missing success row is unresolved, never evidence that the account mutation did not occur. The external intent's before/after hashes and the local prepared row support operator reconciliation. The write and post-write enqueue are separate filesystem operations; this is not a crash-atomic transaction, reserved outcome slot, guaranteed automatic recovery, or cross-replica correlation. Do not replay a mutation on a missing outcome. Further journal/reconciliation and other administrative mutations remain #38 work. Tests exercise the four real account mutations with signed receipts and outbox delivery plus a simulated precommit storage fault.

## Audit sender key: no-follow opened-handle validation

The external-audit **32-byte sender HMAC key** is now opened through the shared
Windows/Linux private-key loader, rather than checking a path and then
reopening it. On Linux, the loader walks each ancestor with no-follow,
validates actual opened-object owner and permissions, rejects linked ancestors,
devices and non-regular inputs, and reads the exact validated file handle.
Windows uses a reparse-point-aware handle and requires deployment-managed
service-account ACLs. The public collector verification-key PEM retains its separate 4 KiB
size and RSA validation contract, but also uses the same no-follow validated
opened-handle loader. On Linux, all path components must be trusted and
non-symlinked; unlike the private HMAC sender secret, a public PEM can be
group/world readable but never group/world writable. On Windows, the reader
rejects reparse-point input and the operator must independently restrict
modification ACLs on the file and every parent directory. A public verification
key is integrity-sensitive even though it does not contain a secret. Sender
bytes are cleared on all startup paths, including public-key loading failures. No collector signing
key is added to the gateway. Disposable Windows/Linux tests cover a valid
key, missing key, Linux owner-only mode and linked key/parent rejection.
This tightens local key loading but does not provide tamper-proof WORM storage,
a distributed gateway audit authority or production TLS trust acceptance.

### No-follow audit queue ingestion

The bounded historical-event outbox now checks its complete Linux directory
ancestry and parses each 8-KiB-or-smaller queued event from a validated,
no-follow opened regular-file handle rather than opening the path after a
separate symlink check. Temporary parse byte arrays are cleared on success
or failure. Linux tests reject a symlinked ancestor even when its target
queue has private permissions and retain readability from the actual path.
Windows retains its existing final reparse-point check and local deployment
ACL requirements. This is local spool tamper-resistance, not independent
WORM/retention attestation, cross-process anti-rollback or a solution to
compromise of the service identity. The external collector and operation
receipt requirements remain mandatory.

### Durable correlated resource PREPARED gate (#38)

When the external collector and durable outbox are configured, the common
inventory and fleet file-mutation path now requires **two independent steps
before committing any resource bytes**:

1. The existing signed external intent receipt, bound to the exact
   pre-revision digest and proposed-state digest; the caller's actor,
   role/session/revocation, cancellation and prior state are rechecked.
2. A correlated `RESOURCE_MUTATION_PREPARED` event persisted in the
   owner-only local durable outbox **before** writing the new inventory/fleet
   file. The event authenticates the same intent ID (as a SHA-256 correlation
   digest) and records the operation and before/after digests in the local
   evidence line. The outbox is flush-to-disk and refuses mutation when full,
   corrupted, inaccessible, non-private or structurally incomplete.

The implementation retains the resource serialization lock and final
account/revocation/cancellation/prior-state checks **after** the asynchronous
preparation step. A missing external receipt, failed durable write or
intervening state change now leaves the resource file unchanged. A crash
between PREPARED and the file write leaves an unresolved **attempt**, not a
false claim that a mutation succeeded; the signed collector receipt and local
spool must be reconciled by an operator. Existing account PREPARED semantics
are unchanged. Linux/Windows security acceptance checks correlated
resource events, missing intent rejection and a damaged spool's sticky fault.

This is **not** a complete distributed immutable audit deployment:
post-commit outcomes still need robust reconciliation/acknowledgement,
signed retention/WORM policy and cross-replica delivery, and Control Center
OIDC/FIDO2 session-revocation/step-up/privileged-event coverage remain
incomplete. Physical WORM infrastructure and actual IdP/passkey trials
belong in #36 after verified software completion. Do not close #38 on this
single fail-closed mutation path.
