"""Source contract only. It does NOT test Prometheus deployment or alert delivery."""
import unittest
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
APP = (BASE / "Program.cs").read_text(encoding="utf-8")
HIST = (BASE / "GatewayRequestHistogram.cs").read_text(encoding="utf-8")
RULES = (BASE / "ops/prometheus/gateway-alerts.yml").read_text(encoding="utf-8")

class SourceMappedMetrics(unittest.TestCase):
    def test_rule_series_exist_in_shipping_source(self):
        for metric in (
            "yarp_control_http_requests_total",
            "yarp_control_http_responses_total",
            "yarp_control_http_duration_seconds_bucket",
            "yarp_control_destination_active_health",
            "yarp_logging_dropped_total",
            "yarp_logging_dropped_high_priority_total",
            "yarp_logging_write_errors_total",
        ):
            with self.subTest(metric=metric):
                self.assertIn(metric, APP + HIST)
                self.assertIn(metric, RULES)
    def test_metrics_are_restricted_to_management_mtls(self):
        self.assertIn('app.MapGet("/gateway/metrics"', APP)
        listener = (BASE / "GatewayListenerIsolation.cs").read_text(encoding="utf-8")
        self.assertIn("OnMetrics(ctx)", listener)
        self.assertIn("ClientCertificateMode.RequireCertificate", listener)
    def test_health_endpoint_is_liveness_only(self):
        self.assertIn('app.MapGet("/gateway/health"', APP)
        self.assertIn('app.MapGet("/gateway/health/ready"', APP)
        listener = (BASE / "GatewayListenerIsolation.cs").read_text(encoding="utf-8")
        self.assertIn("AnyDestinationHealthy", listener)
        self.assertIn("OnData(ctx)", listener)
    def test_certificate_metric_is_from_external_probe(self):
        self.assertIn("probe_ssl_earliest_cert_expiry", RULES)
        self.assertNotIn("probe_ssl_earliest_cert_expiry", APP)
    def test_no_invented_gateway_metrics(self):
        for guessed in ("gateway_requests_total", "gateway_build_info", "gateway_tls_certificate_not_after_timestamp_seconds"):
            self.assertNotIn(guessed, RULES)

if __name__ == "__main__":
    unittest.main()
