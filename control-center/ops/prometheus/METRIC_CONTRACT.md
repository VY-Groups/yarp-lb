# v0.1 real exporter metric contract

Source: shipping `control-center/Program.cs`, `GatewayRequestHistogram.cs`, and `PeerSyncPrometheus.cs`.
Machine-checked in GitHub Actions against **actual HTTP response** from the
real Control Center loopback-internal socket, not copied documentation.

### Exact # TYPE families from running Control Center

```metrics
yarp_control_destination_active_health
yarp_control_destination_admission_inflight_requests
yarp_control_destination_admission_queue_timeouts_total
yarp_control_destination_admission_queue_wait_seconds
yarp_control_destination_admission_queued_requests
yarp_control_destination_admission_rejected_total
yarp_control_destination_admission_waiter_canceled_total
yarp_control_destination_admission_untracked_destinations
yarp_control_destination_inflight_requests
yarp_control_destination_requests_total
yarp_control_destination_telemetry_untracked_requests_total
yarp_control_gc_collections_total
yarp_control_gc_heap_bytes
yarp_control_http_duration_seconds
yarp_control_http_duration_seconds_sum
yarp_control_http_inflight_requests
yarp_control_http_requests_total
yarp_control_http_responses_total
yarp_control_process_working_set_bytes
yarp_logging_dropped_high_priority_total
yarp_logging_dropped_low_priority_total
yarp_logging_dropped_total
yarp_logging_write_errors_total
yarp_peer_sync_enabled
yarp_peer_sync_last_accepted_age_seconds
yarp_peer_sync_remote_fresh
yarp_peer_sync_publish_attempts_total
yarp_peer_sync_publish_acknowledgements_total
yarp_peer_sync_publish_http_failures_total
yarp_peer_sync_publish_transport_failures_total
yarp_peer_sync_publish_resynchronizations_total
yarp_peer_sync_publish_last_ack_age_seconds
yarp_peer_sync_publish_in_flight
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
- `yarp_control_destination_telemetry_untracked_requests_total`
- `yarp_control_destination_admission_inflight_requests`
- `yarp_control_destination_admission_queued_requests`
- `yarp_control_destination_admission_rejected_total`
- `yarp_control_destination_admission_queue_timeouts_total`
- `yarp_control_destination_admission_waiter_canceled_total`
- `yarp_control_destination_admission_untracked_destinations`
- `yarp_control_destination_admission_queue_wait_seconds_bucket`
- `yarp_control_destination_admission_queue_wait_seconds_sum`
- `yarp_control_destination_admission_queue_wait_seconds_count`
- `yarp_logging_dropped_total`
- `yarp_logging_dropped_low_priority_total`
- `yarp_logging_dropped_high_priority_total`
- `yarp_logging_write_errors_total`
- `yarp_peer_sync_enabled`
- `yarp_peer_sync_remote_fresh`
- `yarp_peer_sync_last_accepted_age_seconds`
- `yarp_peer_sync_publish_attempts_total`
- `yarp_peer_sync_publish_acknowledgements_total`
- `yarp_peer_sync_publish_http_failures_total`
- `yarp_peer_sync_publish_transport_failures_total`
- `yarp_peer_sync_publish_resynchronizations_total`
- `yarp_peer_sync_publish_last_ack_age_seconds`
- `yarp_peer_sync_publish_in_flight`

The logging counters are process-lifetime values and reset at restart. The
low/high counters partition the total (`dropped_total = low_priority_total +
high_priority_total`); writer errors are tracked separately. These series carry
no request, client, route, or backend labels. Grafana shows all four values,
while the critical high-priority-drop and writer-error rules remain separately
actionable.

Peer-sync gauges are also process-local. `enabled` and `remote_fresh` are 0/1;
`last_accepted_age_seconds` is monotonic and remains measurable after stale
counters are collected. It is `NaN` until the first authenticated peer frame;
these fixed-cardinality series have no peer, node, client, or identity labels.

Publisher diagnostics are process-local, reset at restart, and also have no
labels. The publisher performs one request at a time and has no durable queue;
an acknowledgment is an HTTPS status response, not a durability guarantee.
Expected signed receiver-boot challenges do not increment HTTP failures.
`yarp_peer_sync_publish_last_ack_age_seconds` uses the monotonic clock and is
`NaN` before the first successful acknowledgment. `in_flight` is bounded to 0
or 1 by the serial publisher. A `resynchronizations_total` increment means a
previously known receiver boot epoch changed; initial epoch discovery is not a
resynchronization event.

Per-destination request counters have a process-local cap of 4,096 distinct
IDs. Requests for additional IDs increment
`yarp_control_destination_telemetry_untracked_requests_total`, a single
unlabelled aggregate; no overflow destination IDs become Prometheus labels.

Per-destination admission state uses the same fixed 4,096-entry registry cap.
Its queue-wait histogram exports cumulative fixed bounds from 1 ms through
60 seconds plus `+Inf`, with the existing sum and count. This supports
bucket-derived tail-latency estimates while keeping memory and series count
bounded. `yarp_control_destination_admission_untracked_destinations` is a
single unlabeled gauge for enabled policies omitted when the admission registry
is full; those destinations fail closed rather than forwarding without their
configured limit.

`YarpDestinationAdmissionRejected` and `YarpDestinationAdmissionQueueTimeout`
alert when either local counter increases in a five-minute window. These are
actual local 503 outcomes, not generic upstream 502/503/504 responses or a
queue-depth threshold. They retain only the scrape labels and the existing
bounded configured `destination` identifier; they include no request path,
client identity, or backend address. A queue that is occupied but still
servicing requests does not fire these alerts. Rule syntax, firing labels,
annotations, and the no-event case are covered by the synthetic promtool test.
Successful rule tests validate expression behavior only; they do not establish
that a deployed Alertmanager has an approved receiver or that notifications
reach an operator.

### Explicit external-exporter series
- `up`
- `probe_success`
- `probe_ssl_earliest_cert_expiry`

External probes **do not come from YARP**. They require separately tested
blackbox/Prometheus monitoring. CI's promtool scenario does not imply a live
Alertmanager notification. **Readiness**: `/gateway/health/ready` (503 until
at least one backend is Active=Healthy), only on the configured data-plane
listener in isolated mode. `/gateway/health` is process liveness only.

For the provisional 99.9% annual HTTP objective, scrape one
`probe_success{job="gatewaycore-availability",instance="<probe-target>",service="gatewaycore-http",region="<bounded-region>"}`
and matching `up` series every 10 seconds from each independent external probe
region. Scrape failures are recorded as failed samples; missing series alert
and are never filled with success. A rolling-year SLI needs at least 98% of
expected samples and 13 months of TSDB retention; until then its status is
unknown. Burn alerts are
in `gateway-alerts.yml`; their syntax and synthetic behavior are checked by
`onprem-promtool.yml`. This does not configure a live probe, central TSDB, or
Alertmanager receiver. See `control-center/docs/AVAILABILITY_SLO.md` for the
assumption model and incident evidence format.

### Alert/template routing
- `/gateway/metrics` is restricted to the management metrics listener in split mode.
- A management IP allowlist and pinned trusted client certificate are required.
- Traffic interface must not expose admin UI or metrics.
- Prometheus histogram p99 is bucket-derived; capacity gate uses client-observed p99.

### GSLB DNS process metrics

The optional GSLB exporter is disabled by default (`MetricsListenPort: 0`).
When enabled, it binds only to a dedicated loopback address and port. Scrape it
from a same-host Prometheus agent and remote-write or forward the samples to the
central Prometheus server. Never expose this unauthenticated endpoint directly
to an untrusted network.

| Series | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `gatewaycore_gslb_dns_queries_total` | counter | `transport=udp\|tcp` | DNS messages received |
| `gatewaycore_gslb_dns_dropped_total` | counter | `transport=udp\|tcp` | Received messages that produced no DNS response |
| `gatewaycore_gslb_dns_responses_total` | counter | `transport=udp\|tcp`, `rcode` fixed enum | DNS responses successfully sent |
| `gatewaycore_gslb_agent_reports_total` | counter | `result=accepted\|rejected\|storage_error` | Signed report processing outcomes |
| `gatewaycore_gslb_configured_zones` | gauge | none | Configured zones |
| `gatewaycore_gslb_configured_sites` | gauge | none | Configured backend sites |
| `gatewaycore_gslb_locally_healthy_sites` | gauge | none | Sites passing their local probe hysteresis |
| `gatewaycore_gslb_administratively_quarantined_sites` | gauge | none | Sites quarantined by operator configuration |
| `gatewaycore_gslb_report_gated_sites` | gauge | none | Sites requiring signed-agent quorum (present only when configured) |
| `gatewaycore_gslb_agent_quorum_targets` | gauge | `state=quorum\|below_quorum` | Report-gated sites by current local quorum state |
| `gatewaycore_gslb_agent_evidence_reports` | gauge | `state=healthy\|unhealthy\|unknown\|stale_or_missing` | Current signed report count across configured agent/zone/site slots; not unique vantage groups |

No zone, hostname, backend address, agent ID, certificate or client-address
labels are exported. The local health and quorum gauges are separate inputs;
neither alone represents final DNS eligibility, which also depends on address
family and validators. Import `gateway-alerts.yml` for the opt-in runtime
alerts. These signals do not measure end-user service availability; the
independent HTTPS probe and rolling 365-day SLI above do. The importable
Grafana dashboard is `gslb-dashboard.json`; its JSON syntax was checked locally.
The existing CI workflow parses Prometheus rules and exercises synthetic alert
behavior.

The authenticated operator Metrics page also provides point-in-time backend
health exports in JSON and CSV. These include cluster/destination IDs, active
and passive health, in-flight request counts, and process-lifetime status
counters. They deliberately omit backend URLs/IPs, client addresses, and request
paths. Exports are local to one process and do not represent historical uptime
or a fleet-wide SLI.

The importable `gateway-dashboard.json` presents request rate, 5xx rate, p50/p95/p99
latency, backend health and in-flight requests, log loss, process memory, and
external availability. Its rolling-year SLI panel is hidden until at least 98%
of the expected 10-second probe samples exist. Import it into Grafana with the
Prometheus datasource UID variable `DS_PROMETHEUS`; select only the bounded
gateway or availability scrape jobs. CI validates the JSON, required series,
panel IDs, coverage gate and absence of request/client identity labels. This is
an importable dashboard artifact, not a deployed Grafana service or a live
Alertmanager notification path.
