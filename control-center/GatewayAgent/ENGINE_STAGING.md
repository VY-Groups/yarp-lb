# Independent engine configuration staging (development / opt-in)

This reference **does not** make L4, DNS/GSLB or WAF production-ready. It extends the existing GatewayAgent's authenticated transport with **file staging only** for two strictly allowlisted JSON engines: `l4` and `gslb`. WAF rule deployment is intentionally excluded because there is no safe validated ModSecurity/CRS rule bundle schema.

## Local trust requirements

1. Provision a machine/server TLS certificate in the OS store, enforce trusted client certificates, and pin only the intended controller certificate thumbprints in `Agent:TrustedClientThumbprints`. Invalid/untrusted certificates must never be bypassed.
2. Keep `Agent:EnableEngineConfigChanges=false` until approved. Only activate with 1–3 pinned controller ECDSA P-256 **public** PEM paths and local ACL-protected `Agent:StageDirectory`.
3. Explicitly configure absolute, existing `Agent:EngineConfigPaths:l4` and/or `Agent:EngineConfigPaths:gslb`. Only these local paths can be changed; clients cannot supply filesystem paths or commands.
4. `Agent:AllowEngineNonLoopbackListeners=false` by default. A remote listener requires **both** local opt-in and payload `AllowNonLoopbackListeners=true`. Loopback endpoint is the agent example's default.
5. Protect the agent stage directory and engine files with restrictive host ACLs; it contains versions of live configuration. Keep private signing keys **off agents**.

## Protocol / operator sequence

- `GET /agent/v1/engines`: reports allowlisted IDs, SHA-256 revision and staging-only status.
- `POST /agent/v1/engines/{engineId}/config/prepare`: accepts `TransactionId`, `ExpectedRevision`, `Config` (JSON object), `KeyId`, `Sequence`, `ExpiresUnixSeconds`, `Signature`. Validates schema, listener binding and a cryptographic v2 signature over the *engine-identified* envelope `{"EngineId":"l4","Config":{...}}` or `{"EngineId":"gslb","Config":{...}}`. The signed transaction and expected hash must match the local file. A durable per-engine high-water sequence rejects replay after restarts.
- `POST /agent/v1/engines/{engineId}/config/activate`: `TransactionId` + `PreparedRevision`; writes to the allowlisted file only if it has not drifted and the transaction remains current.
- `POST /agent/v1/engines/{engineId}/config/rollback`: `TransactionId`; restores original bytes only if no later sequence superseded it and the live bytes match expected original or prepared bytes.

Every endpoint is subject to the agent's **existing HTTPS client certificate** middleware. No inbound plaintext management operation succeeds. Failed signature, version, path, port, IP or schema validation causes rejection. Config activation is a local file replacement; **the process is not reloaded/restarted**. Operators must separately validate application readiness and perform a pre-drained rollout. Neither manual service controls nor any new internet-facing binding is enabled by this feature.

## Explicit limitations and deployment gate

- No Control Center UI or fleet-wide orchestration yet invokes these engine endpoints.
- No distributed transaction, multi-node atomic commit, post-activation health rollback, WAF CRS signing, ACME, DNSSEC, PKI enrollment, external WORM audit, or cross-host fault test is implemented here.
- The pinned signature is not a substitute for mTLS or independent approval. Only a controller private key may sign; the agent only stores pinned public keys.
- Validate system ACLs, real client-certificate chain and revocation behavior, correct engine process startup, restart/drain, and rollback on dedicated hosts before using beyond disposable lab.
- CI runs source/schema/signature tests on Windows/Ubuntu. A green CI run verifies neither the live HTTPS endpoints nor production mTLS provisioning.

## No purchased SSL certificate required for local testing

The CI test suite generates a new ephemeral **self-signed test CA** and separate CA-issued client certificates inside a throwaway workspace. The test agent binds `https://127.0.0.1:<dynamic-port>` with its own temporary self-signed server certificate. There is **no external CA, domain ownership, or purchased SSL certificate** prerequisite.

To exercise this on a disposable developer machine, generate or use a short-lived private test CA, issue distinct `clientAuth` leaf certificates, and configure `Agent:TrustedClientThumbprints` with 1–8 allowed leaf fingerprints. For a test CA only, set `Agent:LabOnlyClientCaCertificatePath` to the absolute path of its **public root PEM**, and bind the agent HTTPS listener **only to 127.0.0.1**. This switch immediately refuses startup if engine config, proxy config or service actions are enabled. It turns off network-based revocation lookup **only in this isolated loopback mode** because a disposable CA has no published CRL. The certificate key material is never committed.

The production/default mode has no `LabOnlyClientCaCertificatePath`: Kestrel requires and validates a client certificate with revocation checking enabled, with a normally trusted enterprise CA and an independently pinned leaf fingerprint. Do **not** deploy the test-root mode on production servers, remote public listeners, or CA/RA/eSign infrastructure.

`Agent:TrustedClientThumbprints` is checked on each authenticated request so a protected JSON config reload can overlap old/new controller pins with no agent listener restart. `Agent:RevokedClientThumbprints` is a local emergency-denylist for pinned client identities. The denylist is **not a substitute for an enterprise CRL/OCSP mechanism**. Zero downtime in a real distributed gateway fleet, offline/online revocation behavior under a managed CA, and live CA trust-anchor rotation remain unverified until tested on actual infrastructure.
