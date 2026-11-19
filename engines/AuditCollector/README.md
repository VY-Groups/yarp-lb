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
