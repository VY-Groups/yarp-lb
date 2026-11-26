# Independent engine configuration staging (development / opt-in)

This reference **does not** make L4, DNS/GSLB or WAF production-ready. It extends the existing GatewayAgent's authenticated transport with **file staging only** for two strictly allowlisted JSON engines: `l4` and `gslb`. WAF rule deployment is intentionally excluded because there is no safe validated ModSecurity/CRS rule bundle schema.

## Local trust requirements

1. Provision a machine/server TLS certificate in the OS store, enforce trusted client certificates, and pin only the intended controller certificate identities in `Agent:TrustedClientThumbprints`. Prefer explicit `SHA256:<64 hex characters>` certificate-DER fingerprints. Existing bare 40-character SHA-1 certificate thumbprints remain accepted for compatibility during migration; a SHA-256 entry is never interpreted as SHA-1. Invalid/untrusted certificates must never be bypassed.
2. Keep `Agent:EnableEngineConfigChanges=false` until approved. Only activate with 1–3 pinned controller ECDSA P-256 **public** PEM paths and local ACL-protected `Agent:StageDirectory`.
3. Explicitly configure absolute, existing `Agent:EngineConfigPaths:l4` and/or `Agent:EngineConfigPaths:gslb`. Only these local paths can be changed; clients cannot supply filesystem paths or commands.
4. `Agent:AllowEngineNonLoopbackListeners=false` by default. A remote listener requires **both** local opt-in and payload `AllowNonLoopbackListeners=true`. Loopback endpoint is the agent example's default.
5. Protect the agent stage directory and engine files with restrictive host ACLs; it contains versions of live configuration. Keep private signing keys **off agents**.

## Protocol / operator sequence

- `GET /agent/v1/engines`: reports allowlisted IDs, SHA-256 revision and staging-only status.
- `POST /agent/v1/engines/{engineId}/config/prepare`: accepts `TransactionId`, `ExpectedRevision`, `Config` (JSON object), `KeyId`, `Sequence`, `ExpiresUnixSeconds`, `Signature`. Validates schema, listener binding and a cryptographic v2 signature over the *engine-identified* envelope `{"EngineId":"l4","Config":{...}}` or `{"EngineId":"gslb","Config":{...}}`. The signed transaction and expected hash must match the local file. A durable per-engine high-water sequence rejects replay after restarts.
- `POST /agent/v1/engines/{engineId}/config/activate`: `TransactionId` + `PreparedRevision`; writes to the allowlisted file only if it has not drifted, the transaction remains current, and no durable rollback fence exists.
- `POST /agent/v1/engines/{engineId}/config/rollback`: `TransactionId`; restores original bytes only if no later sequence superseded it and the live bytes match expected original or prepared bytes. A durable transaction-local rollback fence is written before restoration, including when the file is already at its original revision. Delayed activation of the rolled-back transaction is refused; a subsequent deployment requires a new signed sequence and transaction.

Every endpoint is subject to the agent's **existing HTTPS client certificate** middleware. No inbound plaintext management operation succeeds. Failed signature, version, path, port, IP or schema validation causes rejection. Config activation is a local file replacement; **the process is not reloaded/restarted**. Operators must separately validate application readiness and perform a pre-drained rollout. Neither manual service controls nor any new internet-facing binding is enabled by this feature.

For a GSLB config containing an authoritative `NameServers` or `Delegations`
zone, prepare compares the current and proposed zone objects. Any changed
existing zone requires an explicitly increased `SoaSerial` under RFC 1982;
serial rollback and the ambiguous half-range transition are rejected. A
serial-only increase is allowed. The operator or config author still has to
choose and write the new serial: it is not generated automatically. New/deleted
zones and changes made outside this signed staging endpoint are not covered by
the transition comparison. A staged file still requires a controlled service
restart, and serial equality across independent DNS nodes requires coordinated
signed rollout.

### Optional read-only GSLB runtime summary

Set `Agent:GslbMetricsPort` to the DNS process's loopback-only
`MetricsListenPort` to enable `GET /agent/v1/engines/gslb/runtime-status`;
`0` disables it. The GatewayAgent contacts only `127.0.0.1` on this configured
port, with redirects and proxy use disabled, a two-second timeout, and a 16 KiB
response cap. It returns only fixed quorum and observer-freshness counts after
validating the expected metric series. The Control Center calls this endpoint
with its existing pinned mTLS client and displays the per-authority snapshot.
This does not query DNS answers, confirm that the DNS process is actually
serving, or compare authority nodes. Configure a local Prometheus collector to
scrape the DNS metrics listener as well; this management view is not durable
metrics storage.

## Explicit limitations and deployment gate

- No Control Center UI or fleet-wide orchestration yet invokes these engine endpoints.
- No distributed transaction, multi-node atomic commit, post-activation health rollback, WAF CRS signing, ACME, DNSSEC, PKI enrollment, external WORM audit, or cross-host fault test is implemented here.
- The pinned signature is not a substitute for mTLS or independent approval. Only a controller private key may sign; the agent only stores pinned public keys.
- Validate system ACLs, real client-certificate chain and revocation behavior, correct engine process startup, restart/drain, and rollback on dedicated hosts before using beyond disposable lab.
- CI runs source/schema/signature tests on Windows/Ubuntu. A green CI run verifies neither the live HTTPS endpoints nor production mTLS provisioning.

## No purchased SSL certificate required for local testing

The CI test suite generates a new ephemeral **self-signed test CA** and separate CA-issued client certificates inside a throwaway workspace. The test agent binds `https://127.0.0.1:<dynamic-port>` with its own temporary self-signed server certificate. There is **no external CA, domain ownership, or purchased SSL certificate** prerequisite.

To exercise this on a disposable developer machine, generate or use a short-lived private test CA, issue distinct `clientAuth` leaf certificates, and configure `Agent:TrustedClientThumbprints` with 1–8 allowed leaf fingerprints. Prefer `SHA256:<64 hex characters>`, computed over the complete DER certificate. For a test CA only, set `Agent:LabOnlyClientCaCertificatePath` to the absolute path of its **public root PEM**, and bind the agent HTTPS listener **only to 127.0.0.1**. This switch immediately refuses startup if engine config, proxy config or service actions are enabled. By default it turns off network-based revocation lookup only in this isolated loopback mode because a disposable CA may have no published CRL. The certificate key material is never committed.

The disposable Windows CRL acceptance sets `Agent:LabOnlyClientCaCheckRevocation=true` together with that loopback-only CA path. This keeps the generated trust anchor process-scoped while enabling `X509Chain` online revocation checks with a five-second retrieval bound. It exercises Windows chain and CRL handling against the real Kestrel listener but does **not** exercise the Windows System root store, enterprise trust-anchor installation, OCSP responder behavior, or deployed certificate rotation. Never enable this lab switch on a public listener or a production host.

The production/default mode has no `LabOnlyClientCaCertificatePath`: Kestrel requires and validates a client certificate with revocation checking enabled, with a normally trusted enterprise CA and an independently pinned leaf fingerprint. Do **not** deploy the test-root mode on production servers, remote public listeners, or CA/RA/eSign infrastructure.

`Agent:TrustedClientThumbprints` is checked on each authenticated request so a protected JSON config reload can overlap old/new controller pins with no agent listener restart. During migration, old SHA-1 and new SHA-256 pins can coexist in the same list; remove the old SHA-1 value only after all controllers use the replacement certificate. `Agent:RevokedClientThumbprints` accepts either format and is a local emergency-denylist for pinned client identities. The denylist is **not a substitute for an enterprise CRL/OCSP mechanism**. Zero downtime in a real distributed gateway fleet, offline/online revocation behavior under a managed CA, and live CA trust-anchor rotation remain unverified until tested on actual infrastructure.

The agent writes a local structured log entry when the accepted pin-set revision first loads and whenever its SHA-256 fingerprint changes. The log contains only sorted-set revision fingerprints, not certificate keys or passwords. This is local process logging only; it is not immutable or centralized audit evidence and must be forwarded to an independently protected audit system for that requirement.

### Optional signed Linux restart

`Agent:EnableGslbSignedRestart=true` enables only the fixed `gatewaycore-gslb.service` restart after a valid signed GSLB file activation. The service operator must provision the unit, delegate only this service restart, configure `Agent:GslbMetricsPort` to its IPv4-loopback metrics port, and ensure the engine starts with exactly the allowlisted JSON file. `GET /agent/v1/engines/gslb/config/revision` distinguishes the file digest from the engine's startup digest. The restart endpoint requires the original live digest, prepared revision, current signed sequence and (commercial builds) authenticated quorum. It durably records an attempt before invoking systemctl and rejects replay. Confirm actual authoritative UDP/TCP DNS answers before proceeding to a second node. If restart may have published a new serial, old-file rollback is refused; recover using a fresh signed forward revision. The endpoint does not prove DNS traffic or coordinate other hosts. Noncommercial restart remains lab-only; commercial engine prepare/activate/rollback now require the existing authenticated fleet fence.

### Two-authority rolling operator coordinator

Use `python3 ops/acceptance/gslb_signed_rollout.py --help`. The host-owned manifest includes exactly two distinct node records (HTTPS agent origin, CA/client certificate/private-key paths, pinned agent certificate SHA-256, literal DNS endpoint and independently signed `prepareFile`), plus common `beforeSerials`. The separate signed envelopes must share a transaction ID and sequence, and must declare identical authoritative zone names and forward serials. Default preflight checks both agents' file/loaded digest and real authoritative SOA serial over UDP **and** TCP. Explicit `--execute` and an unused private journal path are required for mutation. Prepare both, then activate/restart one at a time, recheck both authorities before advancing. Commercial operators must independently acquire the existing authenticated quorum transaction lease. A failure or uncertain restart stops the rollout; reconcile the journal and agent state before any new transaction. Never rewind a published serial. This is software orchestration, not automatic authority-lease issuance, Windows service support, public delegation or zero-downtime certification.

### Windows signed restart

On Windows the same opt-in endpoint uses the fixed SCM service `GatewayCoreGslb`, not an HTTP-supplied service or command. A trusted host administrator must provision a Windows-service-compatible wrapper running the DNS engine with the exact allowlisted JSON path, and grant the agent only query/start/stop rights for that service. The fixed Windows PowerShell executable uses noninteractive SCM controls, waits for Stopped then Running, and the agent still checks the live loaded digest. The existing persisted restart intent and commercial quorum fence apply on both platforms. Do not register the console DNS executable directly as an SCM service. No arbitrary shell, service installation, or forced dependent-service stop is exposed. A lost response is an unconfirmed restart and must be reconciled before any new signed transaction. Real Windows SCM restart acceptance on a provisioned DNS service remains required.
