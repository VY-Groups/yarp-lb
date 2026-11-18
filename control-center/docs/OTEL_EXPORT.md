# OpenTelemetry export

GatewayCore can export ASP.NET Core request spans, YARP proxy child spans, ASP.NET Core metrics, runtime metrics, bounded proxy request count/latency metrics, and structured access logs to an OTLP/HTTP protobuf collector. This is opt-in; without `YARP_OTEL_ENDPOINT`, no OpenTelemetry providers are registered.

## Configuration

Set the following in the GatewayCore service environment:

```text
YARP_OTEL_ENDPOINT=https://otel-collector.example:4318
YARP_OTEL_TRACE_SAMPLE_RATIO=0.05
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<short-lived-token>
```

`YARP_OTEL_ENDPOINT` must be an HTTPS base URL with no path, credentials, query, or fragment. Plain HTTP is accepted only for loopback development collectors (`127.0.0.1` or `::1`). The collector certificate must chain to a CA trusted by the host. Keep collector credentials in the service secret store, rotate them, and never put them in source, command history, logs, or issue comments. The sampling ratio is finite and bounded from `0` to `1`; the default is `0.05` and parent sampling honors W3C trace context.

Export uses the SDK's bounded batch queue and background worker; request handling does not synchronously wait for collector delivery. When the queue is full or the collector is unavailable, telemetry may be dropped. The proxy path continues serving traffic. Metrics export every 15 seconds with a five-second timeout. Trace batch limits use the OpenTelemetry SDK defaults for the pinned package version. The exporter includes the bounded console writer's total/low/high priority drop and write-error counters from the `GatewayCoreYarp.Logging` meter.

## Data and privacy contract

- Request and proxy spans use W3C trace context. Proxy spans can carry bounded route, cluster, and destination IDs that match `[A-Za-z0-9_-]{1,80}`. ASP.NET server span names are normalized from the HTTP method and router-provided route template; unmatched requests use a method-only name so raw paths and identifiers are not exported through the span name.
- A privacy processor removes client/network addresses and ports, raw URL path/query/full URL, user-agent, authorization, and cookie attributes before export. ASP.NET instrumentation keeps query values redacted. The route template is the supported request dimension; never add request bodies, headers, IPs, query strings, credentials, or arbitrary user data to span attributes.
- Proxy request count and duration metrics contain only a fixed response-status class (`2xx`, `3xx`, `4xx`, `5xx`, or `other`). They intentionally have no route, backend, IP, or path labels, keeping exporter cardinality bounded. The existing local Prometheus endpoint and authenticated per-destination diagnostics remain separate.
- OTLP logs are provider-filtered to the `GatewayCore.AccessLog` category at Information and above. Authentication, application, and audit categories are excluded. Access records include a UTC timestamp and client IP by default; a forwarded address is trusted only when the immediate peer exactly matches `GATEWAY_TRUSTED_PROXY_IPS`. Access-log IPs are intentionally customer-visible data and require an approved recipient, access-control, and retention policy. The lossy console writer is never an immutable audit source.

## Current limits

The Windows/Linux control-center CI test now emits a paired loopback middleware comparison with telemetry disabled and enabled (default 5% trace sampling). Each mode receives three alternating-order samples of 10,000 HTTP requests at concurrency 16 after 500 warmups; the JSON output includes RPS and p50/p95/p99 plus median percentage deltas. Export is drained to a disposable local HTTP receiver outside the timed request windows. This isolates the shipping telemetry middleware and SDK on GitHub runner hosts; it is not a full YARP-to-backend throughput comparison and must not be reported as customer or production overhead.

This integration does not provide a production Collector deployment, durable central storage, production Grafana hosting, audit-log replication, or a fleet-wide report store. The loopback-only Docker fixture in `ops/observability` verifies real Collector ingestion, Prometheus translation, Grafana dashboard provisioning and test Alertmanager delivery; it is disposable evidence with no persistent volumes. Local per-destination health/ejection/queue metrics remain on the separate loopback Prometheus endpoint unless explicitly added to the OTLP meter. Before production use, deploy a secured Collector and metrics backend, configure authentication and retention, validate redaction and queue-loss behavior end to end, verify alert delivery to approved operators, measure the actual gateway plus backend path on Windows and Linux with the site's traffic mix, and test collector outage/recovery. These steps remain open under issue #50; exporter source and CI do not establish production monitoring or availability.
