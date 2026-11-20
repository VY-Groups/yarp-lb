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
and ACME JSON to be mode 0600 and the key directory to be private. Windows uses
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
