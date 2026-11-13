# Traffic lifecycle, failure, and observability (development 0.1)

## Draining (new requests only)
- Destination `Metadata.TrafficState`: `active` (default) or `draining`. The gateway middleware filters draining destinations **before session affinity and balancing**, including for built-in YARP algorithms. Previously forwarded requests are not canceled. Long-lived connections may remain indefinitely; operator must inspect in-flight counters and manually enforce a maintenance deadline.
- `Metadata.SlowStartSeconds`: integer 0–600. Applies only to `WeightedRandom`, starting at effective weight 1 then linearly rising to configured `Weight` over the window. Ramp begins when the first request observes the destination eligible, not directly from a probe callback. An unhealthy interval resets the timer only if traffic observes the unavailable state. This **is not a full HAProxy automatic post-recovery slow-start monitor**.
- Source-IP hashing deliberately ignores slow-start: changing weights continuously would remap sticky source identities.
- Configure `HealthCheck.AvailableDestinationsPolicy=HealthyAndUnknown` for fail-closed clusters; the YARP default can otherwise enter healthy-or-panic mode when all destinations fail.
- Drafts remain subject to independent review; a freeze flag is local, not distributed.

## Prometheus metrics
A process-local exporter at `GET /gateway/metrics` rejects non-loopback connections. Metrics include request totals/status classes, duration histogram, in-flight request count, destination counts and YARP current in-flight/active health, working set and managed heap size. No unbounded path or client labels. Use a **local** collector forwarding to your protected Prometheus-compatible infrastructure.

## Acceptance
GitHub Actions test real HTTP draining, recovery, warmup distribution, active health failover, all-down 503, and hot reconfiguration. Dedicated k6/wrk soak tests and long-lived connection drain tests are **not yet covered**. All results are development evidence, not production approval.

## Example destination metadata
```json
{ "Address": "https://app1.example.net/", "Metadata": { "Weight": "80", "TrafficState": "active", "SlowStartSeconds": "30" } }
```

## Certificate readiness
`GET /admin/api/tls/inventory` lists non-secret LocalMachine/My certificate metadata and currently declared Kestrel listeners for authenticated local administrators. It does not export private keys or alter bindings. Certificate renewal, backend client certificate deployment, trust policy validation, CT monitoring and ACME automation are not implemented.

## Backend mTLS transport profile
YARP clusters may set `Metadata.BackendClientCertificateThumbprint` to a 40-hex-character LocalMachine/My certificate thumbprint. The management API rejects invalid thumbprints and requires HTTPS destinations. YARP `ConfigureHttpClient` loads a trusted, valid client-auth EKU certificate with its private key in the local Windows certificate store; it does **not** alter or disable backend server-certificate trust. New cluster metadata triggers creation of a fresh outbound handler. **Production backend mTLS and managed certificate rotation remain unverified until two-sided CA trust and failure tests pass.**
