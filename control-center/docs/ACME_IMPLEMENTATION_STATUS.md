# ACME certificate lifecycle status

GatewayCore does not currently issue or renew certificates through ACME. The
`AcmeTargetPolicy` code is only a preflight contract: it restricts directory
URLs to the official Let's Encrypt staging/production directory endpoints (or
an explicitly enabled loopback test authority), normalizes DNS names to IDNA
ASCII and rejects IP literals, private-use names, wildcard names and HTTP-01
without an explicit challenge-entrypoint flag. It does not resolve DNS or
prove that an address is publicly reachable.

An opt-in HTTP-01 response primitive now serves an exact
`/.well-known/acme-challenge/{token}` GET from a bounded, process-local table.
It validates the RFC 8555 token/key-authorization binding and binds each
publication to a normalized eligible DNS hostname. The request Host must match
that hostname; another host cannot retrieve, replace or remove a live token.
It limits entries and lifetimes, expires challenges, disables caching, and
returns 404 for unknown, expired or wrong-host tokens. It has no remote write API or disk persistence. The route is
disabled by default and requires
`YARP_ACME_HTTP01_PUBLIC_ENTRYPOINT=true` plus the explicit isolated listener
configuration; the route checks the configured traffic IP and HTTP port and
rejects HTTPS and every other local socket, including management sockets.
The operator must make the HTTP-01 public port reachable on TCP/80 (directly or
through a verified port mapping). The current application has no issuer that
publishes tokens, so enabling the route alone still returns 404 until a future
ACME adapter is added. It must not be treated as issuance or renewal support.

The test suite covers this input policy on Windows and Ubuntu. Opt-in isolated
traffic listeners can also hot-reload a PFX when an operator or future issuer
atomically replaces the configured file and supplies explicit DNS names in the
listener JSON's `TrafficCertificateDnsNames` array. Omit the field to preserve
the existing startup-only certificate behavior. A renewal writer must write
the complete encrypted PFX to a temporary file in the same directory, set
the required private-file permissions, then atomically rename it over the
configured PFX path. The
rotation path checks SAN coverage, server-auth EKU, private key, validity and
the operating-system certificate chain before it serves new handshakes. A bad
candidate leaves the last-good certificate active. Existing TLS handshakes get
a bounded 10-second Kestrel handshake window; retired keys are held for a
20-second grace period, swaps are limited to one per 5 seconds, and at most 4
retired certificate handles are retained. On Windows, imported CNG user-key
containers are deleted by exact key name at retirement or shutdown; Linux uses
ephemeral key loading. The existing static-certificate behavior remains when
`TrafficCertificateDnsNames` is omitted. Windows PFX/password file ACLs still
need to be restricted to the service identity by deployment; the application
does not change those ACLs.

The Windows and Ubuntu TlsInventory acceptance runs exercise real Kestrel
handshakes while candidate PFX files are replaced. Malformed, wrong-SAN,
expired, not-yet-valid, less-than-one-day-valid, wrong-EKU and untrusted-chain
candidates are rejected while the last-good certificate remains served. This
does not exercise a live CRL/OCSP responder or ACME issuance/revocation.

There is still no ACME account/key persistence, issuer/client, order/authorization
flow, token publisher, renewal scheduler, backoff/jitter, OCSP/CRL check
specifically at activation, revocation workflow, or failure alerting. This is a
partial challenge-response and runtime certificate-rotation increment for issue
#37; it does not satisfy the issue or make automatic TLS deployment safe.

A real lifecycle still needs an independently reviewed issuer adapter that
publishes tokens, persists account identity securely, writes validated
candidates atomically, and integration tests with a deterministic ACME CA (such
as Pebble) that exercise the challenge handler, renewal scheduling, failure
alarms and revocation. Public staging validation also requires an operator-supplied
eligible domain and reachable challenge entrypoint; CI has neither. No
production CA or DNS credentials belong in CI.
