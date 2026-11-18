# ACME certificate lifecycle status

GatewayCore does not currently issue or renew certificates through ACME. The
`AcmeTargetPolicy` code is only a preflight contract: it restricts directory
URLs to the official Let's Encrypt staging/production directory endpoints (or
an explicitly enabled loopback test authority), normalizes DNS names to IDNA
ASCII and rejects IP literals, private-use names, wildcard names and HTTP-01
without an explicit challenge-entrypoint flag. It does not resolve DNS or
prove that an address is publicly reachable.

The test suite covers this input policy on Windows and Ubuntu. The application
has no ACME account/key persistence, challenge route, issuance flow, renewal
scheduler, backoff/jitter, TLS listener certificate swap, rollback, revocation,
rate limiting or failure alerts. The HTTP-01 flag is not a challenge listener
and must not be interpreted as one. This is a partial security increment for
issue #37; it does not satisfy the issue or make automatic TLS deployment safe.

A real lifecycle still needs an independently reviewed issuer adapter and
integration tests with a deterministic ACME CA (such as Pebble) that exercise
the production challenge handler, certificate validation, active Kestrel
certificate selection, renewal overlap and rollback. Public staging validation
also requires an operator-supplied eligible domain and reachable challenge
entrypoint; CI has neither. No production CA or DNS credentials belong in CI.
