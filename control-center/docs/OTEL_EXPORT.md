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

## Data and privacy contract

- Request and proxy spans use W3C trace context. Proxy spans can carry bounded route, cluster, and destination IDs that match `[A-Za-z0-9_-]{1,80}`. ASP.NET server span names are normalized from the HTTP method and router-provided route template; unmatched requests use a method-only name so raw paths and identifiers are not exported through the span name.
- A deny-by-default span attribute processor preserves only bounded gateway route/cluster/destination IDs, known HTTP request methods, numeric HTTP response status, safe configured route templates, HTTP scheme/protocol version and bounded error type. All other span attributes (including arbitrary header names/arrays, vendor enrichment, raw URLs, client/network addresses and user agent) are removed before export. Unknown methods do not become raw span names. The route template is the supported request dimension; never add request bodies, headers, IPs, query strings, credentials, or arbitrary user data to span attributes or events. This attribute contract is separate from access logs, trace context and metrics; it does not claim blanket PII removal across every signal.
- Proxy request count and duration metrics contain validated configured route, cluster and destination IDs plus a fixed response-status class (`2xx`, `3xx`, `4xx`, `5xx`, or `other`). The tuple budget is capped at 4,096 total combinations, with the overflow tuple included in that limit. IDs must match `[A-Za-z0-9_-]{1,80}`; invalid IDs and overflow are aggregated as `_other`. These labels come only from YARP configuration, never from request data. Metrics do not include client IPs, request paths, headers or tenant/user identifiers. The existing local Prometheus endpoint and authenticated per-destination diagnostics remain separate for health and queue details.
- Local proxy rejection counts use `gateway.proxy.local_rejections` and the single `gateway.proxy.rejection.reason` attribute. The exporter reads a private per-request marker set by GatewayCore's local rejection middleware, never the public response header. Only the fixed GatewayCore codes `gateway_shutdown`, `admission_destination_unresolved`, `admission_policy_conflict`, `invalid_admission_config`, `admission_configuration_unavailable`, `destination_queue_timeout`, `destination_queue_full`, and `destination_unavailable_after_queue` are retained; any other internal code maps to `other`. Upstream response headers cannot create rejection metric samples. This metric does not export raw response headers, destination identity, exception text, request data, client IPs or backend-provided strings. Its reason cardinality is at most nine series per process. It supplements, but does not replace, the local Prometheus endpoint and authenticated per-destination queue/health diagnostics.
- OTLP logs are provider-filtered to the `GatewayCore.AccessLog` category at Information and above. Authentication, application, and audit categories are excluded. Access records include a UTC timestamp and client IP by default; a forwarded address is trusted only when the immediate peer exactly matches `GATEWAY_TRUSTED_PROXY_IPS`. Access-log IPs are intentionally customer-visible data and require an approved recipient, access-control, and retention policy. The lossy console writer is never an immutable audit source.

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

### No-listener proxy metrics fast path (#34)

When no `MeterListener` observes the proxy request count or duration
instruments, request telemetry no longer resolves the reverse-proxy feature,
registers route/cluster/destination dimension tuples, derives status classes,
or creates metric tags solely for export. The hot path checks each instrument's
runtime `Enabled` state; a listener registering later immediately receives
measurements without requiring a gateway restart.

The private local-rejection marker is still removed from `HttpContext.Items`
on every request, even when telemetry is disabled. A listener subscribing
**only** to `gateway.proxy.local_rejections` receives the original allowlisted
reason, and a counter-only subscriber receives counter updates without
requiring a duration histogram subscriber. Isolated acceptance tests cover
these cases and bound warmed unobserved-call allocations to <=2 bytes/call.

This may reduce overhead in no-OTLP or selectively collected configurations;
it does **not** bypass YARP, privacy filtering, access logging, forwarding or
the configured OTel exporter when its instruments have active subscribers.
The per-helper allocation bound is not whole-proxy throughput or memory
evidence. Issue #34 remains subject to three paired pinned before/after
whole-gateway tests, allocation stack attribution, correctness/TLS/POST/streaming
matrix and independent reviewer approval.

#### Exact-head two-mode #34 paired profile

The `Issue 34 - paired allocation profile` workflow now performs **two**
separate pinned three-pair before/after runs for the same PR base/head, VUs,
payload and k6 load script. It first profiles with an actual OTLP receiver
and active instrumentation. It then runs an **additional no-OTLP/no-subscriber
profile**, because `Instrument.Enabled` is the optimization boundary of the
unobserved request-metrics fast path. Both modes record bounded allocation
traces and separate 95% paired uncertainty intervals in the workflow summary
and artifact tree:

- `artifacts/issue34/paired-report.json`: OTLP-enabled result
- `artifacts/issue34/unobserved/paired-report.json`: OTLP-disabled result

The test does not aggregate unlike modes into one result or label a negative
delta in either mode as 500 Mbps production acceptance. Missing off-mode
paired reports or trace files fail the job. Actual Windows paired execution
and deployed one-hour, 500 Mbps physical/operational soak remain unverified.
