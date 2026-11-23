# GatewayCore observability lab

This disposable stack exercises the real GatewayCore OTLP exporters against an OpenTelemetry Collector, scrapes translated metrics with Prometheus, provisions the versioned Grafana dashboard, and routes an isolated synthetic alert through Alertmanager to a bounded in-memory webhook receiver. All published ports bind to loopback; the Docker network is private to this Compose project. Anonymous Grafana access and plaintext OTLP are for this isolated local test only.

From the repository root:

```sh
docker compose -f control-center/ops/observability/compose.yml up -d
```

Configure a local GatewayCore process with:

```text
YARP_OTEL_ENDPOINT=http://127.0.0.1:4318
YARP_OTEL_TRACE_SAMPLE_RATIO=0.05
```

Open Grafana at `http://127.0.0.1:3000` and select **GatewayCore / GatewayCore HTTP and Availability**. Prometheus is available at `http://127.0.0.1:9090`; the Collector exposes its Prometheus exporter only inside the Compose network. OTLP-derived panels appear after requests are exported and scraped.

The test stack creates a disposable always-firing rule named `GatewayCoreObservabilityDeliveryTest`. Alertmanager sends it to the local test receiver at `http://127.0.0.1:18080/events`; this receiver keeps at most 100 events in memory and does not log webhook payloads. The fixture validates delivery wiring only. It is intentionally not a customer notification endpoint and is not included in production alert rules.

Stop and remove the ephemeral stack with:

```sh
docker compose -f control-center/ops/observability/compose.yml down --remove-orphans
```

This is an integration fixture, not a production deployment recipe. Production requires authenticated TLS to the Collector and alert receivers, secret-managed credentials, protected Grafana/Prometheus access, durable storage and retention, customer-configured alert routing, tested outage handling, and host-specific capacity measurements. The fixture uses no persistent volumes; its Prometheus, Alertmanager, receiver, and Grafana state is disposable.

## Log-loss alert routing from the OTLP Collector

The shipped Prometheus rules detect `yarp_logging_dropped_total`,
`yarp_logging_dropped_high_priority_total`, and
`yarp_logging_write_errors_total` from **either** a directly scraped
`gatewaycore-gateway` or OTLP-translated metrics under the lab
`otel-collector` job. Without the Collector scrape label, the previous
rules could miss exporter-supplied loss counters entirely. Critical severities,
five-minute increase windows and existing zero-tolerance high-priority drop
criteria are unchanged.

The observability CI workflow now runs the pinned Prometheus `promtool test
rules` command against `control-center/ops/prometheus/alert-tests.yml`,
including positive Collector-job alerts and a no-fault control case.
The production deployment must explicitly configure its scrape job labels
and route receiver credentials, then prove a real high-priority warning/error
loss and writer fault reach its paging destination. This disposable stack
does not establish that operational acceptance and #50 remains open.

## Collector-down alert gate

Prometheus now raises `GatewayOtelCollectorScrapeFailed` when a configured
`otel-collector` scrape target reports `up == 0` continuously for one
minute. The alert is critical and uses the existing alert routing rules.
The real pinned-Prometheus `promtool` unit test verifies both a failing
collector scrape and a healthy negative control.

This is a **missing-evidence** detection rule informed by the
[GatewayCore GSLB engineering security review](../../docs/GSLB_BRANCH_DEEP_REVIEW.md):
collector silence must not be misinterpreted as healthy proxy operation.
It does not change proxy availability, sampling, backpressure or existing
alert thresholds. When the Collector job is **not configured at all**,
Prometheus does not create `up` for that job, and this rule alone cannot
detect that inventory omission. The operator must independently verify
that every opted-in production node and its required Collector are in
the monitoring inventory, that protected alert delivery is live, and
that offline/retention evidence is preserved. This lab is not physical
production acceptance; #50/#36 remaining gates are unchanged.

## Required Collector target missing from the reference stack

The **opt-in** Collector + Prometheus Docker reference stack loads
`collector-required-alerts.yml` with
`GatewayOtelCollectorTargetMissing`:
`absent(up{job="otel-collector"})` for one minute is critical even if
other gateway scrape jobs are healthy. This closes the missing-scrape-job
inventory gap that `GatewayOtelCollectorScrapeFailed` (`up == 0` for an
existing target) cannot detect. They are complementary alerts, not
interchangeable signals. Real Prometheus `promtool test rules` fixtures
verify the completely missing target, existing-down target and healthy
Collector independently.

**Scope is deliberately strict:** this inventory rule is wired **only**
into `control-center/ops/observability/prometheus.yml`, which explicitly
requires the Collector scrape job. Do not put it in the shared
`control-center/ops/prometheus/gateway-alerts.yml` or deploy it on a
gateway that intentionally has no OTLP exporter/Collector. A production
site using this reference profile must retain the Collector job and
review the alert receiver wiring and retention. This tests configured
software policy, not deployed pager delivery or customer-site retention.
The missing-evidence security principle is also documented in
[the GatewayCore GSLB engineering review](../../docs/GSLB_BRANCH_DEEP_REVIEW.md).
No source code from that reviewed separate runtime was imported.
