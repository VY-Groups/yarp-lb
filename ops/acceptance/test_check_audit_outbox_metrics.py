#!/usr/bin/env python3
"""Offline positive/negative tests of the production runbook acceptance gate."""
import copy
import time
import unittest

from check_audit_outbox_metrics import METRICS, _api_url, verify


def fixture(nodes=("gateway-a", "gateway-b"), now=2000000000):
    values = {
        "gateway_audit_outbox_enabled": 1,
        "gateway_audit_outbox_pending": 0,
        "gateway_audit_outbox_storage_fault": 0,
        "gateway_audit_outbox_delivery_blocked": 0,
    }
    return {name: {
        "status": "success",
        "data": {"resultType": "vector", "result": [
            {"metric": {"job": "otel-collector", "instance": "collector:8889",
                        "service_instance_id": node},
             "value": [now, str(values[name])]} for node in nodes
        ]}
    } for name in METRICS}


class AuditMetricAcceptanceTests(unittest.TestCase):
    NOW = 2000000000

    def valid(self):
        return fixture(now=self.NOW)

    def test_two_node_healthy_positive(self):
        self.assertEqual(verify(self.valid(), ["gateway-a", "gateway-b"], now=self.NOW), 2)

    def test_missing_node_or_unexpected_node_is_not_a_pass(self):
        for change in ("missing", "unexpected", "duplicate"):
            with self.subTest(change=change):
                payload = self.valid()
                rows = payload[METRICS[0]]["data"]["result"]
                if change == "missing":
                    rows.pop()
                elif change == "unexpected":
                    rows.append({"metric": {"job": "otel-collector",
                                            "service_instance_id": "rogue-node"},
                                 "value": [self.NOW, "1"]})
                else:
                    rows.append(copy.deepcopy(rows[0]))
                with self.assertRaises(ValueError):
                    verify(payload, ["gateway-a", "gateway-b"], now=self.NOW)

    def test_unhealthy_states_always_reject(self):
        for name, bad in (
            ("gateway_audit_outbox_enabled", "0"),
            ("gateway_audit_outbox_pending", "-1"),
            ("gateway_audit_outbox_pending", "4097"),
            ("gateway_audit_outbox_storage_fault", "1"),
            ("gateway_audit_outbox_delivery_blocked", "1"),
        ):
            with self.subTest(metric=name, bad=bad):
                p = self.valid()
                p[name]["data"]["result"][1]["value"][1] = bad
                with self.assertRaises(ValueError):
                    verify(p, ["gateway-a", "gateway-b"], now=self.NOW)

    def test_untrusted_labels_and_unhealthy_samples_fail_closed(self):
        for scenario in ("private-label", "wrong-job", "stale", "future",
                         "nan", "fraction", "scalar", "no-series"):
            with self.subTest(scenario=scenario):
                p = self.valid()
                row = p[METRICS[2]]["data"]["result"][0]
                if scenario == "private-label":
                    row["metric"]["client_ip"] = "private-canary"
                elif scenario == "wrong-job":
                    row["metric"]["job"] = "gatewaycore-gateway"
                elif scenario == "stale":
                    row["value"][0] = self.NOW - 1000
                elif scenario == "future":
                    row["value"][0] = self.NOW + 1000
                elif scenario == "nan":
                    row["value"][1] = "NaN"
                elif scenario == "fraction":
                    row["value"][1] = "0.5"
                elif scenario == "scalar":
                    p[METRICS[2]]["data"]["resultType"] = "scalar"
                elif scenario == "no-series":
                    p[METRICS[2]]["data"]["result"] = []
                with self.assertRaises(ValueError):
                    verify(p, ["gateway-a", "gateway-b"], now=self.NOW)

    def test_duplicate_expected_nodes_and_bad_urls_are_rejected(self):
        with self.assertRaises(ValueError):
            verify(self.valid(), ["gateway-a", "gateway-a"], now=self.NOW)
        for url in ("http://prometheus.example", "https://user:token@prom.example",
                    "https://prom.example/path", "https://prom.example/?token=x",
                    "http://127.0.0.1:9090/redirect?q=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _api_url(url)
        self.assertEqual(_api_url("http://127.0.0.1:9090"),
                         "http://127.0.0.1:9090/api/v1/query")
        self.assertEqual(_api_url("https://prometheus.example"),
                         "https://prometheus.example/api/v1/query")


if __name__ == "__main__":
    unittest.main()
