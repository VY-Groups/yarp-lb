# GatewayCore offline commercial licensing — isolated development

**DO NOT MERGE TO MAIN. Owner-directed draft feature branch. No release authorization.**
This is the initial verification SDK, not a complete license system and not wired into the running product. The existing product and release behavior are unchanged.

## Fixed constraints
- Customer installations must activate, validate, renew, upgrade, recover and operate with zero internet connectivity and no license heartbeat or mandatory telemetry.
- No HSM, TPM, dongle or additional hardware dependency. Windows and Linux; physical and VM support by design, subject to acceptance.
- Company-only issuer in a separate private system. Customer packages contain only pinned public verification keys, never production private signing material.
- No universal license, unsigned fallback, frontend-only authorization or hidden bypass.
- No license-server dependency or expensive signature checks in the per-request data path. Invalid fresh installs cannot activate; existing traffic safety and emergency recovery require a separate explicit policy and integration tests.

## Implemented in phase 1
Dependency-free .NET 10 verification SDK and dedicated Windows/Linux CI. GCL1 is an exact ASCII compact envelope: GCL1.keyId.base64url(payload).base64url(signature). Signature is ECDSA P-256 SHA-256 IEEE P1363 (64 bytes) over the first three segments verbatim, including format and key ID. The payload is UTF-8 JSON, with a closed schema, bounded size/depth, unique keys, strict types, integer Unix UTC timestamps, uppercase SHA-256 installation public-key digest, unique explicit feature list, subscription limits, allocation ID and revision. Exact signed payload bytes are used for the checkpoint digest; no JSON reserialization. Pinned keys are injected by a trusted caller; no key is trusted from the file itself. The test harness uses ephemeral signing keys only.

Verification authenticates entitlement contents and matches a caller-provided installation-key digest. It evaluates validity using caller-provided time and compares an optional previous checkpoint. It does NOT create installation keys, prove local key possession, enforce a fleet seat count, persist a revision floor, detect clock rollback or protect against administrator-level code patching. The caller must implement those controls. The verifier is not connected to runtime configuration or management APIs. Expired and future licenses never grant active entitlements in this SDK.

## Next development gates
1. Protected local installation key generation, proof-of-possession activation requests, portable offline import and transactional checkpoint store; Windows DPAPI and Linux private service-owned storage. Test invalid and missing state, interruption, replay and recovery.
2. Separate private issuer and database: operator MFA, two-person issuance/reissue, encrypted software key custody, key rotation, offline signed revocation bundles, subscription and individual node allocation records. No real signing secret in this repository.
3. License Center UI/API and software agreement versioning after authentication/privacy acceptance. Strict backend enforcement, read-only status, no activation bypass. Integrate PR #545 only once independently eligible; do not merge it as part of licensing.
4. Entitlement gates for L7, fleet, HA, GSLB, L4 and WAF at activation, configuration change and runtime initialization; no public per-request issuer call. Preserve established traffic and emergency rollback/security remediation under agreed expiry rules.
5. Test no-egress activation/renewal, restart, corrupt state, modified binaries, cross-node copies, VM clone/rollback limits, HA/DC-DR, node replacement, signing-key rotation, offline revocation, expiry and upgrades. Signed package manifests, selective obfuscation compatible with actual dependencies, independent security assessment, and physical acceptance.
6. Review historical AGPL grants and third-party obligations, commercial agreement, subscription terms and lawful distribution before selling. No legal certification.

Software-only limits: a privileged customer can patch verification, clone exportable key material or roll back all local state. No absolute anti-crack or offline immediate revocation claims. Signed licenses prevent undetected modification by a genuine verifier; code signing only provides enforced integrity where a trusted execution policy checks it. No mandatory online service, no hardware dependency.

## Phase 2 — local activation and state
Added explicit provisioning, P-256 installation identity and signed GCR1 activation requests (public SPKI and random request ID, proof of possession). Windows encrypts the private key using user-scope DPAPI, so the installer must provision the final service account and ACLs; Linux uses a 0700 service directory and 0600 files, with no claim of encryption at rest. A signed state envelope stores the exact license and observed time floor, protected by an exclusive local file lock and flushed temporary-file replacement. Imports require active signed entitlements and the same customer/deployment/allocation; stale or equivocal revisions, edited state and significant observed time rollback are denied. Missing or interrupted state never regenerates a key silently. Tests exercise activation, restart, renewal, tamper, independent-install copy refusal and observed rollback. No power-loss or whole-directory snapshot rollback guarantee, no hard-link or hostile-root containment claim; the provisioned local directory and parent ACLs must be trusted. The issuer must durably deduplicate request IDs, and actual service provisioning/recovery and runtime integration remain pending.
