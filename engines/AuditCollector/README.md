# Independent external audit collector (experimental)

Implements the signed intent/receipt contract of PR #257. Run on a separate management host/account from the gateway, not on the public data plane. Each node has a unique random 32-byte HMAC key; the collector private RSA key is never placed on a gateway. HTTPS uses a normally trusted certificate. There are no remote read, delete or modification APIs.

## Setup

Build: `dotnet publish engines/AuditCollector/AuditCollector.csproj -c Release -o publish/audit`.

Provision a dedicated private state directory, an empty ledger file on first enrollment, a directory containing only 1–32 files named NODE.key (exactly 32 random bytes), a PKCS#8 RSA private PEM (2048–4096 bits), TLS PFX and a separate password file. Use owner-only Unix modes (directories 0700, files 0600); Windows ACLs must be explicitly provisioned for the service identity and protected administrators. Never recreate a missing ledger to recover an existing installation. No automatic repair, truncation or rotation.

Set absolute paths in AUDIT_LEDGER_FILE, AUDIT_NODE_KEYS_DIR, AUDIT_SIGNING_PEM, AUDIT_TLS_PFX and AUDIT_TLS_PASSWORD_FILE. Set AUDIT_LISTEN_ADDRESS to a specific management IP, AUDIT_LISTEN_PORT to an unused port 1025–65535. Firewall to known gateway management hosts. Run `dotnet AuditCollector.dll` as a dedicated non-administrator account. Configure #257 gateway URL to https://collector:PORT/audit/v1/intents and provision its individual node key and collector public key.

## Acceptance and recovery

201 plus RSA-PSS receipt is issued only after the exact authenticated intent is appended and flushed to disk. Duplicate IDs, stale or malformed envelopes and invalid MACs cannot append. Sequence, previous hash, body digest and an independent RSA-PSS signature form the chain. The process validates the entire chain on startup and keeps a bounded replay index. A missing, partial, corrupt, or exhausted ledger fails closed; deliberate or accidental append failure latches until operator recovery. Capacity is 64 MiB or 100,000 entries, whichever comes first. Plan retention and capacity alerts before enabling it. Do not simply delete/rotate the file; a reviewed rotation protocol is not implemented.

With the service stopped, run `dotnet AuditCollector.dll --verify-ledger`. Retain the resulting count and head separately, e.g. in an independently controlled retention system. Verify against that checkpoint via `dotnet AuditCollector.dll --verify-ledger COUNT HEAD`. This detects a valid-prefix rollback against the supplied checkpoint. It does not prove the checkpoint is current or protected. An attacker with the collector signing key and storage privileges can rewrite history. File permissions and signatures are not WORM. An independently enforced retention backend, automated external anchoring, key rotation, collector HA, outcome delivery and storage migration are still required before claiming immutable audit.

CI builds both operating systems and runs real HTTPS acceptance on Ubuntu using disposable certificates and keys. No production account or server is contacted. Windows service runtime/ACL acceptance and combined gateway/collector integration remain unverified by this test.

## External Object Lock compliance retention (optional)

For a NEW ledger, provision an independently managed S3-compatible bucket with versioning and Object Lock enabled. A storage administrator must configure and verify enforcement of COMPLIANCE retention and deny the collector any delete, governance bypass, bucket-policy or versioning administration permissions. Grant the dedicated collector identity only PutObject, PutObjectRetention, GetObject/GetObjectVersion and GetObjectRetention for its unique prefix. Use an HTTPS endpoint with trusted certificate; the implementation never disables TLS validation.

Set ALL of these variables (or none for the original local-only mode):

| Variable | Meaning |
|---|---|
| AUDIT_WORM_ENDPOINT | Exact HTTPS S3 service origin, no path/query |
| AUDIT_WORM_REGION | Explicit SigV4 signing region |
| AUDIT_WORM_BUCKET | Existing lock-enabled bucket |
| AUDIT_WORM_PREFIX | Unique collector namespace; never share between active writers |
| AUDIT_WORM_DAYS | Retention period from signed event timestamp, 1–3650 days |
| AUDIT_WORM_ACCESS_FILE | Absolute owner-only file containing dedicated access key |
| AUDIT_WORM_SECRET_FILE | Absolute owner-only file containing dedicated secret key |
| AUDIT_WORM_PENDING_FILE | Absolute pre-provisioned, owner-only empty journal file separate from ledger |

Use a fresh ledger/prefix and journal together; retroactive locking/migration of preexisting ledger records is not implemented. Missing/partial configuration fails startup; do not remove retention settings to work around an outage. Store all paths under protected directories and preserve ledger and pending state together. Windows deployment must enforce service-account-only ACLs. The S3 client requests a non-overwriting conditional PUT, explicit SHA-256 checksum, COMPLIANCE mode and retain-until timestamp, then reads back the exact version/bytes and confirms lock metadata. A conflicting existing key is accepted only if the current version is truly locked for the required period and exactly matches the signed pending record. Keep storage version identities and checkpoints in an independently managed review process; a provider can be trusted only after verifying its actual retention enforcement.

The collector flushes a single signed pending record before asking storage to retain it. It returns no receipt until the object is verified and the local ledger append has been flushed. Temporary storage failure holds that record; no later sequence may overtake it. A five-second background retry processes the same bytes after recovery, including after process restart; an already-committed record in the pending slot is reconciled without appending twice. An earlier failed administrative operation remains failed, even if its intent is retained later. The original gateway request is never replayed. A disk fault, corrupt or partial pending record requires operator investigation; no silent reset. If an outage exceeds retention validity, operator reconciliation is required rather than shortening retention. Single collector process only. This is a bounded collector-side retry journal, not yet a gateway-side multi-event spool.

CI tests the actual adapter's SDK request/response contract using a controlled SDK fixture and the durable ledger restart paths on Windows and Linux. The existing real HTTPS collector CI remains enabled. The CI fixture is NOT actual Object Lock storage; live storage acceptance must independently attempt deleting/overwriting protected versions, check retained versions and restart/outage behavior against the chosen S3 service. Offline packaging must include the new pinned SDK dependency. Legal holds, automatic rotation, gateway-wide event delivery and multi-replica collector consensus remain pending.
