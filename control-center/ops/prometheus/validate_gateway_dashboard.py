"""Validate the importable GatewayCore Grafana dashboard without dependencies."""

import json
import re
from pathlib import Path


dashboard_path = Path(__file__).with_name("gateway-dashboard.json")
dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
panels = dashboard.get("panels", [])
assert dashboard.get("uid") == "gatewaycore-http-availability"
assert len(panels) >= 8, "dashboard must retain the operator overview panels"
panel_ids = [panel.get("id") for panel in panels]
assert len(set(panel_ids)) == len(panel_ids), "Grafana panel IDs must be unique"

queries = "\n".join(
    target.get("expr", "")
    for panel in panels
    for target in panel.get("targets", [])
)
required_series = {
    "yarp_control_http_requests_total",
    "yarp_control_http_responses_total",
    "yarp_control_http_duration_seconds_bucket",
    "gatewaycore:availability_probe_success:sample",
    "yarp_control_destination_active_health",
    "yarp_control_destination_telemetry_untracked_requests_total",
    "yarp_control_destination_inflight_requests",
    "yarp_control_destination_admission_inflight_requests",
    "yarp_control_destination_admission_queued_requests",
    "yarp_control_destination_admission_rejected_total",
    "yarp_control_destination_admission_queue_timeouts_total",
    "yarp_control_destination_admission_queue_wait_seconds_sum",
    "yarp_control_destination_admission_queue_wait_seconds_count",
    "yarp_logging_dropped_total",
    "yarp_logging_dropped_high_priority_total",
    "yarp_logging_write_errors_total",
    "yarp_control_process_working_set_bytes",
    "yarp_control_gc_heap_bytes",
}
for series in required_series:
    assert series in queries, f"dashboard is missing required series {series}"

assert "count_over_time" in queries and "3090528" in queries, (
    "rolling-year SLI must stay hidden until at least 98% of 10-second samples exist"
)
assert 'probe_success{job="gatewaycore-availability"}' in queries and "sum_over_time" in queries, (
    "dashboard must expose sampled external interruption duration"
)
assert re.search(r'job=~"\$job"', queries), "panels must share the bounded job selector"
for private_label in ("clientIp", "client_ip", "request_path", "authorization"):
    assert private_label not in queries, f"dashboard must not query private label {private_label}"

print(f"PASS: Grafana dashboard JSON and {len(panels)} metric panels validated")
