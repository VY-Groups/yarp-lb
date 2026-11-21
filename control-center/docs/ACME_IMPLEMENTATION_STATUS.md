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

### DNS-01 publisher and Certes issuer path — opt-in, not yet deployed

A new `CertesAcmeCertificateIssuer.IssueDns01Async` uses the existing
Data Protection-encrypted account identity, obtains a real Certes DNS-01
challenge, computes the SHA-256-derived RFC 8555 DNS TXT value, and invokes
an **explicit, trusted** `IAcmeDns01Publisher` before asking the CA to validate.
The publisher is required to publish `_acme-challenge.<target>` for a bounded
8-minute lifetime and probe the configured authoritative nameservers.
Validation is gated until the exact TXT appears at **two or more distinct
authorities** (at most 16 observed), with bounded polling and mandatory
async lease cleanup on success, timeout, network error and cancellation.
The publisher must enumerate all configured authoritative hosts; recursive
resolver cache responses are not evidence of authoritative propagation.
Other simultaneous TXT values are permitted to avoid clobbering unrelated
validations.

The test suite validates base64url SHA-256 TXT format, safe canonical owner
names, independent-authority evidence, replay/stale/missing values, bounded
retry and cleanup through deterministic synthetic publishers. The actual
Certes API method follows the same PFX output bounds and authorization
timeout as HTTP-01. **No DNS provider is registered by default**, the
background scheduler still uses HTTP-01, and no operator-managed DNS mutation,
live staging CA order, multi-node TXT propagation or DNS-01 certificate
activation has yet been proven. The DNS-01 API cannot activate accidentally
without an authenticated operator-supplied publisher. Do not mark #37
complete or claim production DNS-01 until provider credentials, publication/
revoke fencing, fleet coordination and staging CA acceptance are added.

### Independent authoritative DNS-01 wire evidence

The optional `AcmeDns01WireVerifiedPublisher` wraps a separately authenticated
`IAcmeDns01Publisher` and **ignores** that writer's own reported
`ProbeAuthoritativeAsync` results. Instead it queries two to sixteen
explicitly pinned, distinct authoritative IP addresses directly using DNS over
TCP/53; no DNS resolver discovery, recursion or public caller-supplied
endpoints are used. It checks transaction IDs, exact QNAME/TXT/IN echo,
`QR` and `AA` bits, NOERROR, non-truncated DNS frames, bounded resource
records, backward-only DNS name pointers, and the complete 43-byte TXT
character-string. A malformed, non-authoritative, unreachable or incorrect
server contributes **no** healthy vote. The issuer's existing cleanup lease
is still released when any required authority fails. Strict production
construction rejects duplicate server IDs, reused IP addresses, loopback
endpoints and non-53 ports. Loopback/ephemeral ports are enabled exclusively
by an internal socket-test constructor.

The Windows/Linux TLS acceptance now exercises two real independent TCP
socket listeners, a non-AA second server, wrong digests, truncated/corrupt
wire data, pointer errors and a malicious writer that fabricates reports.

**Trust limitation:** The AA bit is a protocol assertion by the contacted
server, not cryptographic proof of DNSSEC or operator independence. The
pinned addresses and their network paths must be trusted and configured by
an operator. A production-approved DNS publication implementation, bounded
credential rotation, DNSSEC validation where required, live external
propagation and CA staging order remain outstanding. This code is a
verification layer, **not** a complete DNS provider or release acceptance.

### Bounded RFC 2136/TSIG DNS-01 publication option

`AcmeDns01NsupdateWriter` adds an operator-provisioned DNS-01 publication
backend for externally managed RFC 2136 authoritative zones. It invokes a
locally installed and **SHA-256-pinned** `nsupdate` binary with `-v`
(TCP) and `-k <private-key-file>` through an argument list, not through a
shell. The binary is checked again before each add/delete. A single
owner-only (0600), bounded TSIG file containing exactly one
`algorithm hmac-sha256` key is validated before use; the shared secret is
never included in argv, command input, log output or error messages.
The process has a 12-second hard timeout and all output is drained without
retaining or logging the text.

The writer accepts only canonical public hostnames strictly beneath one
configured public DNS zone, the exact `_acme-challenge` owner and a
canonical 43-character SHA-256 base64url digest. It sends only:

```text
server <pinned-update-server-IP> 53
zone <configured-public-zone>.
update add _acme-challenge.api.example.com. 30 TXT "<43-character-digest>"
send
```

Cleanup is `update delete <same-owner>. TXT "<same-digest>"`, not a
whole-owner or whole-TXT-RRset removal. Disposing a successful publication
lease performs that exact-value delete independently of the ACME
cancellation token. An ambiguous failed add triggers bounded best-effort
compensating deletion. **DNS TTL is not a lease:** a crashed process can
leave an authoritative record behind; durable clean-up recovery and update
idempotency across multiple gateway nodes are still required.

The writer deliberately refuses to self-attest TXT propagation.
Operators must wrap it in `AcmeDns01WireVerifiedPublisher` using separately
pinned authoritative endpoints; only those direct TCP DNS answers can
satisfy the issuer's two-or-more-authority readiness gate. Grant its TSIG
identity update permission **only** for the approved `_acme-challenge`
TXT names, never unrestricted zone write authority. Keep the executable,
TSIG file and their parent paths root-/service-controlled and out of
source control; do not configure DNS update credentials in public API or UI.

The Windows/Linux test harness checks the strict script and configuration;
Linux additionally runs a disposable fake `nsupdate` process to verify
stdin/argv separation, exact cleanup, nonzero-exit compensation and
executable tampering rejection. A fake executable is not proof of a live
RFC 2136 server or public DNS operation. No automatic scheduler/provider
configuration or CA staging validation is enabled by this PR; external DNS
network credentials, signed response trust, live DNSSEC/TSIG interoperability,
fleet coordination and physical #36 remain pending.

For the updater executable, the Linux integrity preflight follows every
parent directory with no symlink traversal and rejects the **immediate**
executable directory when group/other identities can write it. Trusted
root-managed public executable directories such as `/usr/bin` (mode 0755)
are supported; the private 0700 directory requirement applies to the TSIG
secret/state paths, not normal installed system binaries. Explicit symlinked
binaries/ancestors and group-writable executable directories remain denied.
An approved, independently pinned SHA-256 hash is checked before every
operation, and deployments must update that pin only after reviewing a
verified executable replacement.
