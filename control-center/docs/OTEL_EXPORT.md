# OpenTelemetry export

GatewayCore can export ASP.NET Core request spans, YARP proxy child spans, ASP.NET Core metrics, runtime metrics, and bounded proxy request count/latency metrics to an OTLP/HTTP protobuf collector. This is opt-in; without `YARP_OTEL_ENDPOINT`, no OpenTelemetry providers are registered.

## Configuration

Set the following in the GatewayCore service environment:

```text
YARP_OTEL_ENDPOINT=https://otel-collector.example:4318
YARP_OTEL_TRACE_SAMPLE_RATIO=0.05
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<short-lived-token>
```

`YARP_OTEL_ENDPOINT` must be an HTTPS base URL with no path, credentials, query, or fragment. Plain HTTP is accepted only for loopback development collectors (`127.0.0.1` or `::1`). The collector certificate must chain to a CA trusted by the host. Keep collector credentials in the service secret store, rotate them, and never put them in source, command history, logs, or issue comments. The sampling ratio is finite and bounded from `0` to `1`; the default is `0.05` and parent sampling honors W3C trace context.

Export uses the SDK's bounded batch queue and background worker; request handling does not synchronously wait for collector delivery. When the queue is full or the collector is unavailable, telemetry may be dropped. The proxy path continues serving traffic. Metrics export every 15 seconds with a five-second timeout. Trace batch limits use the OpenTelemetry SDK defaults for the pinned package version.

## Data and privacy contract

- Request and proxy spans use W3C trace context. Proxy spans can carry bounded route, cluster, and destination IDs that match `[A-Za-z0-9_-]{1,80}`.
- A privacy processor removes client/network addresses and ports, raw URL path/query/full URL, user-agent, authorization, and cookie attributes before export. ASP.NET instrumentation keeps query values redacted. The route template is the supported request dimension; never add request bodies, headers, IPs, query strings, credentials, or arbitrary user data to span attributes.
- Proxy request count and duration metrics contain only a fixed response-status class (`2xx`, `3xx`, `4xx`, `5xx`, or `other`). They intentionally have no route, backend, IP, or path labels, keeping exporter cardinality bounded. The existing local Prometheus endpoint and authenticated per-destination diagnostics remain separate.
- Access logs are a separate operator-controlled stream. They include a UTC timestamp and the socket peer IP by default; a forwarded address is trusted only when the immediate peer exactly matches `GATEWAY_TRUSTED_PROXY_IPS`. Do not forward access logs to a broad audience without an approved retention/redaction policy.

## Current limits

This integration does not provide OpenTelemetry log export, a production Collector deployment, durable central storage, production Grafana hosting, alert delivery, audit-log replication, or a fleet-wide report store. The loopback-only Docker fixture in `ops/observability` verifies Collector ingestion, Prometheus translation, and Grafana dashboard provisioning; it is disposable test evidence and has no persistent volumes. The integration does not yet export every local YARP health/ejection/queue/drop counter through OTLP. Keep the local loopback-only Prometheus scrape for those existing counters. Before production use, deploy a secured Collector and metrics backend, configure authentication and retention, validate redaction and queue-loss behavior end to end, verify alert delivery, measure overhead on Windows and Linux, and test collector outage/recovery. These steps remain open under issue #50; exporter source and CI do not establish production monitoring or availability.
