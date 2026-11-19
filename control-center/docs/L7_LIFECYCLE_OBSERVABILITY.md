# Traffic lifecycle, failure, and observability (development 0.1)

## Draining (new requests only)
- Destination `Metadata.TrafficState`: `active` (default) or `draining`. The gateway middleware filters draining destinations **before session affinity and balancing**, including for built-in YARP algorithms. Previously forwarded requests are not canceled. Long-lived connections may remain indefinitely; operator must inspect in-flight counters and manually enforce a maintenance deadline.
- `Metadata.SlowStartSeconds`: integer 0–600. Applies only to `WeightedRandom`, starting at effective weight 1 then linearly rising to configured `Weight` over the window. Ramp begins when the first request observes the destination eligible, not directly from a probe callback. An unhealthy interval resets the timer only if traffic observes the unavailable state. This **is not a full HAProxy automatic post-recovery slow-start monitor**.
- Source-IP hashing deliberately ignores slow-start: changing weights continuously would remap sticky source identities.
- Configure `HealthCheck.AvailableDestinationsPolicy=HealthyAndUnknown` for fail-closed clusters; the YARP default can otherwise enter healthy-or-panic mode when all destinations fail.
- Drafts remain subject to independent review; a freeze flag is local, not distributed.

## Prometheus metrics
A process-local exporter at `GET /gateway/metrics` rejects non-loopback connections. Metrics include request totals/status classes, duration histogram, in-flight request count, destination counts and YARP current in-flight/active health, working set and managed heap size. Signed peer telemetry exports fixed-cardinality `yarp_peer_sync_enabled`, `yarp_peer_sync_remote_fresh` and monotonic `yarp_peer_sync_last_accepted_age_seconds` gauges without peer or client labels; receipt age is `NaN` until the first authenticated frame is accepted. Per-destination request counters retain at most 4,096 destination IDs per process; requests beyond that fixed cap increment the unlabelled `yarp_control_destination_telemetry_untracked_requests_total` aggregate and remain visible through the authenticated destination-metrics and traffic-report APIs. No per-overflow-destination series is created. Use a **local** collector forwarding to your protected Prometheus-compatible infrastructure.

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

## Per-destination request admission

Per-destination concurrency control is **opt-in**. In **Backends → Add/Edit backend**, configure maximum in-flight requests, maximum queued requests, and queue timeout. The same metadata can be set in reviewed configuration:

```json
{
  "Address": "https://app1.example.net/",
  "Metadata": {
    "GatewayCore.Admission.MaxInFlight": "64",
    "GatewayCore.Admission.MaxPending": "128",
    "GatewayCore.Admission.QueueTimeoutMs": "5000"
  }
}
```

`MaxInFlight` accepts 1–50,000; `MaxPending` accepts 0–4,096 (default 0); queue timeout accepts 1–60,000 milliseconds (default 5,000). A partial or invalid policy is rejected on reviewed configuration apply and by the YARP configuration filter. Existing destinations without these metadata keys retain their prior behavior.

The gateway chooses the destination first, then admits or queues the request for that destination. The queue is FIFO, bounded both per destination and to 16,384 waiters per gateway process. Queue-full and queue-timeout failures return local HTTP 503 with `X-GatewayCore-Rejection`; these responses do not replay a request or select a different backend. Before releasing a queued request, the gateway rechecks current destination health and drain state. If the selected destination became unavailable, the request gets a local 503 and is not transferred elsewhere. Client disconnect and shutdown cancel queued waiters. An acquired slot remains held around the complete YARP forwarding lifecycle, including response body streaming, WebSocket lifetime, and exceptions.

This limit is **process-local**, not a shared fleet quota: with multiple gateway nodes, each node can admit up to the configured number. Use backend-side limits or a separately designed atomic shared quota if a fleet-wide ceiling is required. A queue wait seconds summary and in-flight, queued, rejected, timeout and cancellation metrics are exported at `/gateway/metrics`; destination labels have the same configured cluster/destination cardinality bound as the YARP config. Dashboards must scrape this loopback-only endpoint through an approved local collector.

The admission registry retains state for currently applied opt-in destinations and retires removed/disabled destinations only after no admission handle or forwarding lease references them and the gate is idle. This prevents destination-id churn from permanently exhausting the 4,096-entry registry without splitting one destination across independent gates. The real-process CI E2E also negotiates TLS HTTP/2, multiplexes concurrent streams over one client connection, and checks queueing, local overload rejection, FIFO grant, and response-body lease lifetime. The CI-only harness installs its pinned HTTP/2 client after verifying it is running on a disposable GitHub Actions runner. The local 60-minute harness is a per-process loopback queue/lifecycle test; these tests do **not** establish 500 Mbps throughput, fleet-wide limits, gRPC/HTTP/3 or other protocol coverage, annual availability, or production acceptance. Its artifact reports `EC2 (verified)` and includes instance/region only when the IMDSv2 identity-document signature validates against the region certificate published by AWS; otherwise the environment is `local/unverified`.

The applied YARP runtime snapshot reconciler is the only writer of admission policies. It assigns monotonically increasing observation revisions and rejects stale revisions. Request handling only acquires a handle for the most recently reconciled policy; its possibly older route snapshot cannot restore or change limits. Until reconciliation observes a newly applied snapshot, the last reconciled policy remains in force; if reconciliation cannot safely apply a queue shrink because it would strand accepted waiters, the gate fences new admissions even through previously acquired handles while accepted waiters drain, until a later snapshot can install the new policy.

### gRPC admission wire acceptance

The real-process TLS acceptance runs the same gRPC server-streaming scenario twice: exact HTTP/2 on both transport legs, then exact HTTP/3 over QUIC on both legs with a separate HTTP/3-only TLS Kestrel origin. The CI-only HTTP/3 origin uses a unique short-lived CA registered in the disposable runner's current-user trust store on Linux or the machine root store on GitHub-hosted Windows (to avoid interactive user-root confirmation), then removed during cleanup; shipping backend certificate verification is not disabled. Linux CI installs Microsoft MsQuic and fails if QUIC is unavailable; Windows runs HTTP/3 when supported and explicitly reports a skip otherwise. A disposable empty protobuf frame is sent in a gRPC POST; the origin streams two framed messages and a `grpc-status: 0` trailer. One response is deliberately held open while the second call queues and a third is rejected locally, on the same required protocol. Release must admit the queued call, preserve trailers, return gauges to zero and prove exactly two upstream POSTs. A second scenario sends two distinct protobuf messages bidirectionally, requiring the first echoed response before upload completes and successful half-close/trailers. This verifies wire-level full duplex, not generated SDK interoperability, physical HA or gRPC application readiness. Existing listener defaults remain unchanged.
### Graceful host shutdown and QUIC

The public readiness endpoint becomes unavailable once ApplicationStopping is signaled. Proxy entry and final pre-forward checks reject new or still-pending work with HTTP 503 and `gateway_shutdown`; an already-forwarding stream is not linked to that shutdown token. Kestrel and its configured host shutdown budget govern completion. Linux CI runs actual SIGTERM while a real HTTP/3 gRPC response is held and a second POST is queued: pending/new work must be refused, the held stream must finish with its original trailers, upstream attempts must remain exactly those accepted before shutdown, and the process must exit zero. Transport refusal during QUIC shutdown is also valid. This does not directly decode GOAWAY frames, require Windows POSIX signal support, or prove ingress VIP draining/zero loss across physical hosts.
