# v0.1 real exporter metric contract

Source: shipping `control-center/Program.cs`, `GatewayRequestHistogram.cs`.
Machine-checked in GitHub Actions against **actual HTTP response** from the
real Control Center loopback-internal socket, not copied documentation.

### Exact # TYPE families from running Control Center

```metrics
yarp_control_destination_active_health
yarp_control_destination_inflight_requests
yarp_control_destination_requests_total
yarp_control_gc_collections_total
yarp_control_gc_heap_bytes
yarp_control_http_duration_seconds
yarp_control_http_duration_seconds_sum
yarp_control_http_inflight_requests
yarp_control_http_requests_total
yarp_control_http_responses_total
yarp_control_process_working_set_bytes
yarp_logging_dropped_high_priority_total
yarp_logging_dropped_total
yarp_logging_write_errors_total
```

### Required gateway-series (exact samples, not invented aliases)
- `yarp_control_http_requests_total`
- `yarp_control_http_responses_total`
- `yarp_control_http_duration_seconds_bucket`
- `yarp_control_http_duration_seconds_count`
- `yarp_control_http_duration_seconds_sum`
- `yarp_control_process_working_set_bytes`
- `yarp_control_gc_heap_bytes`
- `yarp_control_gc_collections_total`
- `yarp_control_destination_inflight_requests`
- `yarp_control_destination_active_health`
- `yarp_logging_dropped_total`
- `yarp_logging_dropped_high_priority_total`
- `yarp_logging_write_errors_total`

### Explicit external-exporter series
- `up`
- `probe_success`
- `probe_ssl_earliest_cert_expiry`

External probes **do not come from YARP**. They require separately tested
blackbox/Prometheus monitoring. CI's promtool scenario does not imply a live
Alertmanager notification. **Readiness**: `/gateway/health/ready` (503 until
at least one backend is Active=Healthy), only on the configured data-plane
listener in isolated mode. `/gateway/health` is process liveness only.

For the provisional 99.9% HTTP objective, scrape one
`probe_success{job="gatewaycore-availability",service="gatewaycore-http",region="<bounded-region>"}`
and matching `up` series every 10 seconds from each independent external probe
region. Scrape failures are recorded as failed samples; missing series alert
and are never filled with success. Burn alerts are
in `gateway-alerts.yml`; their syntax and synthetic behavior are checked by
`onprem-promtool.yml`. This does not configure a live probe, central TSDB, or
Alertmanager receiver. See `control-center/docs/AVAILABILITY_SLO.md` for the
assumption model and incident evidence format.

### Alert/template routing
- `/gateway/metrics` is restricted to the management metrics listener in split mode.
- A management IP allowlist and pinned trusted client certificate are required.
- Traffic interface must not expose admin UI or metrics.
- Prometheus histogram p99 is bucket-derived; capacity gate uses client-observed p99.
