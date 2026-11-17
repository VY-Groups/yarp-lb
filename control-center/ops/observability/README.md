# GatewayCore observability lab

This disposable stack exercises the real GatewayCore OTLP exporters against an OpenTelemetry Collector, scrapes translated metrics with Prometheus, and provisions the versioned Grafana dashboard. All published ports bind to loopback; the Docker network is private to this Compose project. Anonymous Grafana access and plaintext OTLP are for this isolated local test only.

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

Stop and remove the ephemeral stack with:

```sh
docker compose -f control-center/ops/observability/compose.yml down --remove-orphans
```

This is an integration fixture, not a production deployment recipe. Production requires authenticated TLS to the Collector, secret-managed credentials, protected Grafana/Prometheus access, durable storage and retention, alert routing, tested outage handling, and host-specific capacity measurements. The fixture uses no persistent volumes; its Prometheus and Grafana state is disposable.
