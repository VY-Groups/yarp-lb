# GatewayCore #50 — site telemetry acceptance evidence

This is an operator evidence procedure, **not** a claim of production acceptance. Run only after independent software review, on an authorized isolated environment. Do not copy bearer tokens, customer labels, IP addresses or unredacted traces into GitHub. See [OTEL_EXPORT.md](OTEL_EXPORT.md) for signal contracts and issue #36 for the consolidated physical gate.

## Preconditions and immutable test identity

Record UTC start/end, gateway build SHA and artifact SHA256, OS/runtime, collector image digest, Prometheus and Grafana versions, redacted network diagram, trace sampling configuration, metric scrape interval, alert rule revision, dashboard revision, retention configuration, and an independent reviewer. Record the gateway node identity separately for each host. Keep the original baseline and candidate workload manifests, generator settings, and raw metrics in restricted storage; publish only redacted evidence locations and hashes.

The operator must have authorized read-only Prometheus access and access to Collector/Grafana health, gateway logs and the protected audit-delivery status endpoint. Never expose management endpoints publicly. Use a locally provisioned **read-only** Prometheus API token if required; commands below intentionally omit credentials.

## Collector-to-Prometheus signal contract

Set `PROM_URL` to a trusted HTTPS or loopback HTTP Prometheus **origin**,
and list each expected deployed gateway's exact `service_instance_id`.
Do not put credentials in the URL. The verifier refuses redirects, ambient
proxies, missing nodes, duplicate/unexpected nodes, stale/nonfinite samples,
private labels, and any unhealthy or disabled audit-delivery state.
It never prints response bodies or customer identifiers. Example for two
authorized site gateway nodes (substitute actual IDs in the restricted
operator session, never commit them):

```bash
: "${PROM_URL:?set approved Prometheus origin}"
python3 ops/acceptance/check_audit_outbox_metrics.py \
  --expected-node gateway-node-a \
  --expected-node gateway-node-b
```

Expected: **PASS only** if the Prometheus instant vector for all four
`gateway_audit_outbox_*` metrics contains exactly one fresh sample per
expected gateway node. Each series must be exported through the
`otel-collector` job and must have no private request, actor, customer or
credential labels. For each expected node the accepted values are
`enabled=1`, `pending` in 0..4096, `storage_fault=0` and
`delivery_blocked=0`. An unconfigured outbox (`enabled=0`) is **not**
delivery success; a missing node is FAIL regardless of any other healthy
gateway. The default freshness budget is 180 seconds and must be
preapproved for the site's export/scrape interval. An actual credentialed
Prometheus endpoint requires the site-approved management identity workflow;
this example intentionally embeds no authentication material.

During the controlled fault matrix, run the same checker against each
gateway's expected identity and **require a FAIL** when the outbox becomes
blocked, unreadable or unavailable. Verify that the corresponding critical
Prometheus alert fires and an authenticated operator receives a notification.
After recovery it must return PASS again, with the protected
`/admin/api/audit/delivery` endpoint and signed collector receipts checked
independently. Store the full timestamped evidence privately; no gauge
proves that a particular remote audit record was delivered.

## Controlled fault and recovery

On disposable infrastructure, separately simulate Collector unreachable, exporter credentials rejected, audit collector unreachable, audit outbox unreadable, and restoration. Use the test harnesses already in CI for reproducible software assertions before any site fault. Do not modify production routing or real audit records. For each injected fault record: UTC injection time, trigger command or change ticket, expected metric and alert, first observed metric timestamp, first alert firing timestamp, notification receipt, recovery time, dropped high-priority log count, gateway request errors, and whether the data plane stayed available.

Pass only if failures become visible within the **preapproved** scrape/evaluation/delivery budget, audit failure is never silently reported as healthy, high-priority logging loss remains zero under the approved workload, and gateway traffic is not synchronously blocked by OTLP unavailability. A telemetry export failure must not be mistaken for durable audit success. Verify independent authenticated collector receipts and retention separately; gauges alone are insufficient.

## Dashboard, privacy and load acceptance

Export versioned Grafana dashboard JSON and alert rule files, then record rendered panels for request rate, 5xx/502/503/504, p50/p95/p99, per-destination health/ejection, queue rejection, GC/working set, TLS expiry, DNS health, audit delivery and high-priority logging loss. Test one firing and one resolution notification for each applicable critical rule. Preserve actual routing/notification receipts. Any missing required panel or untested alert is FAIL.

Run matched baseline (OTLP disabled) and candidate (OTLP enabled) on **each supported Windows/Linux target**, same build, traffic mix, concurrency, response sizes, certificates and generator placement. Preserve per-minute RPS, response-body Mbps, p50/p95/p99, error count, CPU, allocated bytes/request, GC and NIC drops. Report absolute and percentage deltas, not just aggregate averages. The physical #36 solo-node gate remains **at least 750 Mbps and 1.5× measured peak RPS in every one of 60 consecutive one-minute windows**, zero errors, with the unchanged approved p99 and drop gates; do not infer those values from a synthetic CI pass.

Inspect sampled OTLP protobuf and stored Grafana/Prometheus series for forbidden request paths, query strings, raw headers, cookies, client IPs, user identifiers, secrets and high-cardinality labels. Use synthetic canaries; do not export real personal data. Verify W3C parent/child continuity through actual gateway and upstream hops, including HTTP/2, and test missing/invalid incoming trace context. Any privacy leak or unbounded cardinality is FAIL.

## Evidence record (one row per scenario)

| Field | Required value |
| --- | --- |
| Scenario / issue | Stable identifier, #50 and #36 linkage |
| Prerequisites | Exact host/build/config/collector/dashboards/alert revision and authorization |
| Command or fault | Exact sanitized command or change ticket |
| Expected | Preapproved numeric threshold, state transition and alert recipient |
| Actual | Timestamped metric query, traces, logs, alert receipt, traffic metrics |
| Evidence | Restricted artifact path and SHA256, redacted public summary |
| Verdict | PASS / FAIL / NOT RUN (never count NOT RUN as PASS) |
| Review | Independent reviewer and date; rollback verification |

Do not close #50 based solely on this document or a green CI run. Remaining software implementation defects, absent disposable integration acceptance, or broken CI stay under #50; only genuine site/environment evidence is transferred to #36.
