# ACME certificate lifecycle

GatewayCore now has an opt-in ACME v2 HTTP-01 renewal path. Certes 4.1.0 (MIT)
handles ACME signed requests and certificate export. GatewayCore publishes the
HTTP-01 key authorization through its bounded challenge store, validates the
returned certificate with the same SAN, EKU, chain, validity and private-key
checks used by the live TLS rotator, atomically replaces the configured PFX,
then waits for the isolated traffic listener to select the new leaf. A failed
validation or activation restores the last-good PFX. The renewal coordinator
only requests a new order inside its configured 1-to-60-day renewal window.

The account private key is persisted only as ASP.NET Data Protection ciphertext
under the private control-plane directory. Linux requires the account-key file
and ACME JSON to be mode 0600 and the key directory to be private.
Account-key startup now validates the full Linux directory ancestry before
creating or opening a key. Existing account ciphertext is read through the
validated opened file handle with a 16 KiB hard bound and no symlink traversal;
Windows retains the existing Data Protection and deployment ACL boundary. Windows uses
the existing LocalMachine DPAPI-protected Data Protection key ring. The renewal
worker adds up to three minutes of startup jitter, checks every six hours when
the certificate is outside the renewal window, and uses jittered exponential
failure backoff capped at six hours. Logs record only exception type; they omit
the domain, directory response, paths, credentials and certificate material.

## Enablement

ACME is disabled unless both environment variables are explicitly set:

```text
YARP_ACME_HTTP01_PUBLIC_ENTRYPOINT=true
YARP_ACME_CONFIG_FILE=/absolute/private/path/acme.json
```

The existing isolated listener configuration must enable `TrafficCertificateDnsNames`
and its traffic PFX/password paths must exactly match the ACME JSON. TCP/80 on
the configured traffic HTTP listener must be reachable by the ACME CA, directly
or through an operator-verified mapping. Management and metrics listeners never
serve challenges.

Example JSON (use the staging directory first):

```json
{
  "directoryUrl": "https://acme-staging-v02.api.letsencrypt.org/directory",
  "dnsName": "gateway.example.com",
  "contactEmail": "ops@example.com",
  "pfxPath": "/var/lib/gatewaycore/traffic.pfx",
  "pfxPasswordFile": "/var/lib/gatewaycore/traffic.pwd",
  "renewalWindowDays": 30,
  "agreeToTermsOfService": true
}
```

The terms-of-service setting must be set only after the operator has reviewed
the selected CA's terms. Production Let's Encrypt is rejected unless
`allowProductionCa` is explicitly set to `true`; the staging endpoint remains
the default. Keep the password file in the same protected state directory with
the listener's required permissions.

## Verified behavior and remaining limits

Windows and Linux TlsInventory acceptance use a deterministic fake CA. The fake
CA requests the token over a real local HTTP socket, returns a signed test leaf,
and the test verifies atomic PFX installation, live TLS certificate replacement,
not-due suppression, encrypted account-key restart recovery, challenge cleanup,
wrong-SAN rejection, last-good preservation and temporary-file cleanup. The
revocation contract tests also verify active-leaf refusal, exact typed thumbprint
confirmation, hostname/EKU and reason bounds, and one submission of a prior leaf
to the deterministic issuer. These tests prove code-side contracts without
contacting a public CA.

No public domain, public port-80 reachability, Let's Encrypt staging order, DNS
resolution, or production issuance has been tested. HTTP-01 is implemented;
DNS-01 is not. Revocation is manual and only tested against the deterministic
issuer; automatic revocation, OCSP/CRL freshness checks, external failure alerts,
multi-node shared challenge state, and a public-domain acceptance run remain
open. For multiple GatewayCore nodes, every node must be
reachable through the challenge routing arrangement or a shared HTTP-01 token
store must be deployed; the current token store is process-local. Keep issue #37
open until real staging validation and the remaining operational criteria pass.

### Revocation authority trust boundary

The concrete ACME revocation adapter now applies the **same** HTTPS directory,
approved-host, default-port, exact `/directory` path and no-credential/query/
fragment policy as issuance. Unknown remote hosts and local loopback authorities
are rejected for production revocation before the encrypted account key is
loaded or any outbound request can occur. Loopback remains available only in
explicitly configured isolated issuer preflight tests, never by default in
revocation. Windows/Linux unit and adapter-negative tests cover the boundary.
This does not add live public-domain certificate revocation acceptance.

## Guarded manual revocation

When ACME is configured, `POST /admin/api/tls/acme/revoke` is available only
to an authenticated Administrator through the existing management security
middleware. It is limited to two requests per five minutes. The request contains
a bounded base64 DER leaf, uppercase SHA-1 thumbprint, reason, and exact
`REVOKE <THUMBPRINT>` confirmation. GatewayCore verifies the configured DNS
name, TLS server-auth EKU, thumbprint and reason allowlist, then rechecks that
the leaf is not currently served before submitting it using the existing
protected ACME account. DER buffers are zeroed after use; audit events contain
only thumbprint, hostname, reason and failure type.

This is a manual prior-certificate operation, not automatic renewal revocation.
The current leaf is deliberately never revoked by this endpoint. The CI fake
issuer verifies request selection and rejection behavior; it does not prove
public CA acceptance, OCSP/CRL propagation, or that clients enforce revocation.

## Revocation request boundary and certificate lifecycle serialization

The revocation endpoint does not bind the JSON body before checking its size.
Kestrel enforces a 32 KiB endpoint request limit for both fixed-length and
chunked bodies, and the handler's bounded reader independently caps bytes before
JSON deserialization. Oversized requests return HTTP 413 before audit or issuer
calls. The Windows/Linux TlsInventory acceptance sends real HTTP requests for
both oversized body forms and confirms the bounded JSON path still works.

ACME renewal PFX replacement/live activation and operator revocation share one
process-local lifecycle gate. The gate is held through CA revocation response
and through renewal listener activation, so the managed renewal worker cannot
change the selected TLS leaf between revocation eligibility validation and the
CA decision. External out-of-band writes to the configured PFX are not covered
by this process-local gate and must not run concurrently with GatewayCore's ACME
operations. The acceptance test holds a fake CA revocation response while a
renewal attempts activation and verifies that the leaf and PFX remain unchanged
until revocation completes.

### Renewal write and rollback state fence

ACME captures and validates one bounded live PFX byte snapshot (512 bytes–1 MiB) and its UTF-8 password (1–16384 bytes, optional BOM). Under the local lifecycle gate it compares current PFX bytes and normalized password before replacement. If the active file or password changed while awaiting the CA, the order may have succeeded at the CA but the candidate is not installed. Activation-failure rollback also checks that the still-current bytes are the exact installed candidate and the password is unchanged; on conflict it fails without replacing the newer files. This is optimistic local fencing, not an OS-level compare-and-swap or multi-host lock; administrative/manual writes must be coordinated with renewal. UTF-8 password file required. No auto-revocation or replay of an orphaned order. The fake CA acceptance adds a concurrent manual-PFX replacement scenario; original activation rollback and revocation serialization checks remain.

### Account-key storage hardening

Account-key creation and reload both require a non-linked immediate parent directory, with private Linux permissions. New Linux directories and temporary ciphertext files are created with restrictive modes rather than tightened after creation. Ciphertext is read through a bounded stream (64–16384 bytes); corrupt, oversized or truncated state fails closed rather than regenerating the account identity. Temporary plaintext PEM byte buffers are cleared after protection. This is not a race-proof filesystem sandbox or protection against a compromised service identity; operators must protect the complete directory ancestry and Windows ACLs. Acceptance includes existing unsafe directory, Linux directory symlink, malformed/oversized ciphertext and recovery of the original account identity.

### Private ACME config ingestion hardening

The opt-in ACME JSON configuration now has a 16 KiB input cap and uses the
shared no-follow Windows/Linux opened-handle reader. On Linux it verifies the
opened file's owner/mode and all parent directory components; Windows rejects
reparse-point leaf files and still requires service-identity ACL policy.
Configuration must be valid UTF-8 and a single unambiguous JSON object:
duplicate, mixed-case or Unicode-escaped duplicate property names are rejected
before deserialization, so a last-value-wins parser cannot silently switch
`directoryUrl`, `allowProductionCa` or active PFX bindings. Inputs are
cleared from the temporary byte buffer on every success and error path.
Disposable Windows/Linux TLS inventory tests validate legitimate settings,
duplicate aliases, oversize and invalid UTF-8; Linux tests a linked ancestor.
This is startup-input hardening only: it does not add DNS-01, staging CA
validation, external renewal notifications or cross-node issuance coordination.

### Private traffic certificate and password reads

The ACME renewal coordinator and live TLS certificate rotator read the active
PFX and password through the same bounded, no-follow opened-handle validator.
PFX input is limited to 1 MiB (minimum 512 bytes), and password input to 16 KiB;
temporary PFX/password byte arrays are cleared after use. Linux checks service
or root ownership, private file modes and every parent component on the opened
path. Windows rejects reparse-point files; service-identity ACLs remain an
operator responsibility. Renewal fails before contacting the issuer when the
PFX or password is linked, too large, or has unsafe Linux permissions. The
Windows/Linux acceptance verifies live-certificate PFX link/mode rejection and
renewal PFX/password link and password-mode rejection on Linux.

### ACME account-key directory bootstrap without symlink traversal

On Linux, the ACME account-key store now creates its private key directory
through the shared no-follow, opened-directory-descriptor traversal rather
than calling path-based `Directory.CreateDirectory` first and checking
ownership afterwards. The previous order could create a child folder outside
the trusted state tree through an existing symlink before throwing.
The issuer now fails closed before such a filesystem write; Windows retains
its existing directory and ACL boundary. Linux integration tests require
that existing and dangling linked ancestors are refused without creating an
external directory. This hardens on-disk account-key lifecycle only;
DNS-01, public CA staging acceptance and multi-node challenge coordination
remain unimplemented.

### Exact JSON schema for destructive revocation requests

`POST /admin/api/tls/acme/revoke` now requires precisely the four declared
JSON properties (`certificateDerBase64`, `thumbprint`, `confirmation`,
`reason`) once each. The existing case-insensitive web serializer continues
to accept PascalCase and camelCase, but duplicate/case-aliased names, missing
fields, unknown extension fields, arrays, and malformed input produce HTTP 400
*before* the request proceeds to the administrator audit or certificate
revocation coordinator. No insecure compatibility fallback is provided.
The bounded 32 KiB Content-Length and chunked transport limits are unchanged,
and real HTTP negative tests check the exact request boundary. This hardens
the existing HTTP-01 revocation path; it does not implement DNS-01 or prove
public-CA staging validation.


### DNS-01 publisher boundary — cleanup lease before side effects

The opt-in Certes DNS-01 path requires an explicitly supplied trusted publisher.
The provider first acquires a cleanup lease without changing DNS; publication
then occurs through that lease. If an update partially reaches a provider and
then times out or throws, the already-held lease is disposed on the failure
path so it can remove or reconcile only that lease's exact owner/value. Lease
cleanup must be idempotent and preserve unrelated TXT values for concurrent
validations. A provider that fails
while acquiring the lease must leave DNS unchanged. Readiness still requires
the exact TXT value at at least two distinct configured authoritative servers.

No DNS provider is registered by default. This interface contract and its
synthetic partial-write regression test do not establish a live provider,
staging CA order, multi-node fencing, or full issue #37 acceptance.
