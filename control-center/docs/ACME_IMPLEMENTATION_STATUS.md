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
wrong-SAN rejection, last-good preservation and temporary-file cleanup. This
proves the coordinator, challenge endpoint and Kestrel rotation contract without
contacting a public CA.

No public domain, public port-80 reachability, Let's Encrypt staging order, DNS
resolution, or production issuance has been tested. HTTP-01 is implemented;
DNS-01 is not. Automatic revocation, OCSP/CRL freshness checks, failure alerts
to an external operator, multi-node shared challenge state, and a public-domain
acceptance run remain open. For multiple GatewayCore nodes, every node must be
reachable through the challenge routing arrangement or a shared HTTP-01 token
store must be deployed; the current token store is process-local. Keep issue #37
open until real staging validation and the remaining operational criteria pass.
