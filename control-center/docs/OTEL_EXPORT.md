# OpenTelemetry export

GatewayCore can export ASP.NET Core request spans, YARP proxy child spans, ASP.NET Core metrics, runtime metrics, bounded proxy request count/latency metrics, local rejection counts, and structured access logs to an OTLP/HTTP protobuf collector. Proxy request count and duration metrics include validated configured route, cluster and destination IDs plus a fixed HTTP status class. At most 4,096 distinct route/cluster/destination tuples are exported per process, including one reserved `_other` tuple for overflow (so at most 4,095 named tuples are retained). Local rejections use `gateway.proxy.local_rejections` with only `gateway.proxy.rejection.reason`; the eight GatewayCore rejection codes are allowlisted and every other value is collapsed to `other`, for at most nine reason series per process. This bounds proxy-metric identity cardinality independently of traffic volume. This is opt-in; without `YARP_OTEL_ENDPOINT`, no OpenTelemetry providers are registered.

The per-request dimension budget keeps validated IDs in a value-tuple key and validates them with a non-allocating character scan. This avoids building a composite string or LINQ string enumerator for every proxy metric sample after a tuple has been registered. A Windows baseline run of the pre-change helper measured 208 allocated bytes per warmed call; the candidate measured 0 bytes across 100,000 calls. The Windows/Linux EngineConfig acceptance keeps a regression check at no more than one allocated byte per call. This focused measurement covers the helper only; the current-main paired Issue #34 profile and allocation traces are still pending before claiming a whole-request improvement.

## Configuration

Set the following in the GatewayCore service environment:

```text
YARP_OTEL_ENDPOINT=https://otel-collector.example:4318
YARP_OTEL_TRACE_SAMPLE_RATIO=0.05
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer%20<short-lived-token>
```

`YARP_OTEL_ENDPOINT` must be an HTTPS base URL with no path, credentials, query, or fragment. Plain HTTP is accepted only for loopback development collectors (`127.0.0.1` or `::1`). The collector certificate must chain to a CA trusted by the host. Keep collector credentials in the service secret store, rotate them, and never put them in source, command history, logs, or issue comments. The sampling ratio is finite and bounded from `0` to `1`; the default is `0.05` and parent sampling honors W3C trace context.

Export uses the SDK's bounded batch queue and background worker; request handling does not synchronously wait for collector delivery. When the queue is full or the collector is unavailable, telemetry may be dropped. The proxy path continues serving traffic. Metrics export every 15 seconds with a five-second timeout. Trace batch limits use the OpenTelemetry SDK defaults for the pinned package version. The exporter includes the bounded console writer's total/low/high priority drop and write-error counters from the `GatewayCoreYarp.Logging` meter.

## Durable external audit delivery state (opt-in)

When OTLP is configured, the `GatewayCore.ControlCenter` meter exports four
**label-free** observable gauges: `gateway.audit.outbox.enabled` (0/1),
`gateway.audit.outbox.pending` (0..4096, or -1 when unreadable),
`gateway.audit.outbox.storage_fault` (0/1), and
`gateway.audit.outbox.delivery_blocked` (0/1). No event IDs, actor names,
request paths, outbox file contents, intent data, signatures, URLs or
credentials are exported. The existing `AuditOutboxWorker` refreshes a
cached status after each bounded delivery pass (2-second schedule); OTLP
measurement callbacks merely read four integers and never enumerate files,
block the proxy request path or contact the audit collector.

The gauges are seeded during application startup. **enabled=0 does not
mean successful audit delivery**: it means the durable external audit queue
was not configured and the other three gauges are zero. enabled=1 with
pending=-1 or storage_fault=1 requires an urgent operator investigation;
delivery_blocked=1 indicates the authenticated transport was unsuccessful.
Gauges are a weakly consistent operational snapshot, **not** immutable
audit records or proof that a particular remote event was received.
The protected `/admin/api/audit/delivery` endpoint remains the detailed
admin-only status source. CI validates all gauge values and zero labels
through a .NET `MeterListener` and validates actual OTLP metric names
through the disposable wire-collector capture. Production sites must still
verify retained immutable receipts, two-host continuity, alert routing and
disaster recovery; those are outstanding #50/#36 acceptance gates.

## Bounded console writer recovery and loss evidence

The background console output writer counts failed output records in
`yarp_logging_write_errors`. Broken pipes, disposed writers, permission
failures and invalid-state failures do **not** terminate the bounded queue
consumer. If a subsequent write is possible, the consumer resumes normally
without blocking the gateway request path or recursively logging an error.
`yarp_logging_dropped_high_priority` and
`yarp_logging_dropped_low_priority` separately count admission drops at
the queue boundary; output failures are counted under write errors rather
than misreported as queue drops. Alert on nonzero write errors and on any
high-priority drops. This lossy logger is **not** durable audit delivery.

The Windows/Ubuntu `NonBlockingConsoleLoggerTests` injects four distinct
output failures then verifies one later warning succeeds, all losses are
accounted for, and no admission drop is invented. This proves only the
background writer's local recovery contract; it does not substitute for
collector delivery, production monitoring or immutable audit acceptance
under #50.

## Data and privacy contract

- Request and proxy spans use W3C trace context. Proxy spans can carry bounded route, cluster, and destination IDs that match `[A-Za-z0-9_-]{1,80}`. **ASP.NET route provenance is mandatory:** any inbound `http.route` Activity tag is discarded, even if it contains balanced `{parameter}` braces. Only the selected framework `RouteEndpoint.RoutePattern.RawText`, obtained after endpoint selection by the trusted response instrumentation hook, can be added back as a bounded route template. Static server-configured endpoints and parameterized templates may be preserved; an unmatched request or one with no selected endpoint uses a method-only span name. The tests include a forged brace-wrapped customer path that must not be exported, plus a **real loopback Kestrel request** through the shipping ASP.NET instrumentation and selected `RouteEndpoint`; its request-path canary must be absent while the configured parameterized route pattern remains in the exported span. Fixed safe `gateway.route.id` dimensions remain available separately. Operators must still review their configured route literals for PII; this does not certify arbitrary application-controlled endpoint metadata as secret-free.
- A deny-by-default span attribute processor preserves only bounded gateway route/cluster/destination IDs, known HTTP request methods, numeric HTTP response status, safe configured route templates, HTTP scheme/protocol version and bounded error type. All other span attributes (including arbitrary header names/arrays, vendor enrichment, raw URLs, client/network addresses and user agent) are removed before export. Unknown methods do not become raw span names. The route template is the supported request dimension; never add request bodies, headers, IPs, query strings, credentials, or arbitrary user data to span attributes or events. This attribute contract is separate from access logs, trace context and metrics; it does not claim blanket PII removal across every signal.
- Proxy request count and duration metrics contain validated configured route, cluster and destination IDs plus a fixed response-status class (`2xx`, `3xx`, `4xx`, `5xx`, or `other`). The tuple budget is capped at 4,096 total combinations, with the overflow tuple included in that limit. IDs must match `[A-Za-z0-9_-]{1,80}`; invalid IDs and overflow are aggregated as `_other`. These labels come only from YARP configuration, never from request data. Metrics do not include client IPs, request paths, headers or tenant/user identifiers. The existing local Prometheus endpoint and authenticated per-destination diagnostics remain separate for health and queue details.
- Local proxy rejection counts use `gateway.proxy.local_rejections` and the single `gateway.proxy.rejection.reason` attribute. The exporter reads a private per-request marker set by GatewayCore's local rejection middleware, never the public response header. Only the fixed GatewayCore codes `gateway_shutdown`, `admission_destination_unresolved`, `admission_policy_conflict`, `invalid_admission_config`, `admission_configuration_unavailable`, `destination_queue_timeout`, `destination_queue_full`, and `destination_unavailable_after_queue` are retained; any other internal code maps to `other`. Upstream response headers cannot create rejection metric samples. This metric does not export raw response headers, destination identity, exception text, request data, client IPs or backend-provided strings. Its reason cardinality is at most nine series per process. It supplements, but does not replace, the local Prometheus endpoint and authenticated per-destination queue/health diagnostics.
- OTLP logs are provider-filtered to the **`GatewayCore.TelemetryAccess`** category at Information and above. Each exported access summary contains UTC timestamp, a fixed allowlisted HTTP method (unrecognized methods become `_OTHER`), validated route ID or `_other`, response status and duration. The outbound provider **excludes** the separate `GatewayCore.AccessLog` category, which still includes client IP and trusted-forwarded address source for local controlled operations. No client IP, source address, forwarded header, raw path, query, body or user/tenant ID is present in the exported access summary. Authentication, application and audit categories also remain excluded. Keep local access logs access-controlled and retention-limited; this deliberate OTLP privacy change removes the formerly exported IP fields. Neither the lossy local logger nor OTLP is an immutable audit source.

## Current limits

The Windows/Linux control-center CI test now emits a paired loopback middleware comparison with telemetry disabled and enabled (default 5% trace sampling). Each mode receives three alternating-order samples of 10,000 HTTP requests at concurrency 16 after 500 warmups; each sample reuses one HTTP/1.1 client and drains every response body before stopping the latency timer. The JSON output includes per-pair and per-mode RPS and p50/p95/p99, median percentage deltas, and min/max sample ranges. Export is drained to a disposable local HTTP receiver outside the timed request windows; background exports may still run during the request interval. The complete JSON is appended to the GitHub Actions job summary when available and printed in the test log. This isolates the shipping telemetry middleware and SDK on GitHub runner hosts; it is not a full YARP-to-backend throughput comparison and must not be reported as customer or production overhead. A measurable regression is a prompt to measure the actual site path, not a result to dismiss or generalize.

This integration does not provide a production Collector deployment, durable central storage, production Grafana hosting, audit-log replication, or a fleet-wide report store. The loopback-only Docker fixture in `ops/observability` verifies real Collector ingestion, Prometheus translation, Grafana dashboard provisioning and test Alertmanager delivery; it is disposable evidence with no persistent volumes. Local per-destination health/ejection/queue metrics remain on the separate loopback Prometheus endpoint unless explicitly added to the OTLP meter. Before production use, deploy a secured Collector and metrics backend, configure authentication and retention, validate redaction and queue-loss behavior end to end, verify alert delivery to approved operators, measure the actual gateway plus backend path on Windows and Linux with the site's traffic mix, and test collector outage/recovery. These steps remain open under issue #50; exporter source and CI do not establish production monitoring or availability.

### Trace attribute filtering allocation guard (#34)

The sampled-span privacy processor now collects only disallowed attribute
**keys** using a cleared, reusable array-pool buffer, removes them after
tag enumeration, and returns the buffer in a `finally` block. It no longer
materializes the entire `Activity.TagObjects` collection into a new heap
array for each processed span. Bounded allowed operational attributes and
deny-by-default rejection of URLs, client addresses, headers and unknown
enrichment are unchanged. A regression test exercises 96 private tags over
repeated spans to force buffer growth and reuse. This targets **trace-export
instrumentation** only; it does not prove any overall gateway
allocated-bytes/request reduction. Issue #34 still requires three-or-more
paired, pinned whole-proxy profiles and Windows/Ubuntu runtime evidence.

### Strict trace ID validation (#34)

Sampled trace route/cluster/destination IDs now use a bounded ASCII scan
rather than regular expressions or LINQ. Only 1–80 ASCII letters, numbers,
underscores and hyphens are accepted; trailing newlines are rejected rather
than matching the old regular-expression `$` anchor. Regression tests verify
actual rejection and preservation in the privacy processor. This is a
trace-instrumentation candidate, not a demonstrated 8.6 KiB/request reduction;
new exact-head paired profiling and independent review are required.

### Export-only log cost and default-disabled behavior

The IP-free `GatewayCore.TelemetryAccess` event is emitted **only** when an
OTLP exporter is configured at startup. When `YARP_OTEL_ENDPOINT` is absent,
no outbound event is created; normal local `GatewayCore.AccessLog` remains
unchanged. When export is enabled, the bounded console provider excludes the
export-only category, preventing a second formatted INFO line per request.
The independent OTLP logger provider still receives the structured safe
summary and its bounded async queue/timeout settings remain unchanged.

The first three-pair profile of the privacy PR (head `5cd4a2ba`) measured
**+847.222 B/request** (95% CI **+846.456 to +847.989**) with active OTLP.
That measurable overhead was **not accepted as a production optimization**.
This follow-up removes local duplicate formatting and redundant disabled-mode
work; it requires a *fresh* exact-head paired profile before any claim of
reduced full-gateway overhead. Both old and new profiles use synthetic loopback
traffic and do not replace Windows/Ubuntu or production monitoring acceptance.
