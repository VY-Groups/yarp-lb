import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from instrument_lab_stats import ADDITION, ANCHOR, instrument
from report import build_report
from run_paired_profile import measurement as parse_measurement


def measurement(alloc, *, rps=100.0, p95=30.0, p99=50.0, errors=0):
    return {
        "duration_seconds": 45.0,
        "requests": 4500,
        "errors": errors,
        "failed_rate": errors / 4500,
        "checks_rate": 1.0,
        "rps": rps,
        "p95_ms": p95,
        "p99_ms": p99,
        "allocated_bytes": alloc,
        "working_set_delta_bytes": 1024,
        "gc0_delta": 2,
        "gc1_delta": 1,
        "gc2_delta": 0,
        "gc_pause_ms_delta": 4.0,
        "managed_heap_delta_bytes": 100,
    }


def records(before_commit="before-sha", after_commit="after-sha"):
    result = []
    for number, baseline_alloc, candidate_alloc in ((1, 500000, 470000),
                                                     (2, 510000, 480000),
                                                     (3, 490000, 460000)):
        pair = {
            "before": {
                "round": number,
                "revision": "before",
                "commit": before_commit,
                "workload": {"vus": 75, "duration": "45s", "payload_bytes": 0,
                             "connection_reuse": True},
                "direct": measurement(100000),
                "proxy": measurement(baseline_alloc, rps=95, p95=40, p99=60),
            },
            "after": {
                "round": number,
                "revision": "after",
                "commit": after_commit,
                "workload": {"vus": 75, "duration": "45s", "payload_bytes": 0,
                             "connection_reuse": True},
                "direct": measurement(100000, rps=99),
                "proxy": measurement(candidate_alloc, rps=98, p95=35, p99=55),
            },
        }
        result.extend([pair["before"], pair["after"]] if number % 2 else
                      [pair["after"], pair["before"]])
    return result


class ReportTests(unittest.TestCase):
    def test_k6_and_gateway_counter_parser_keeps_all_requested_metrics(self):
        metrics = {
            "http_reqs": {"count": 4500, "rate": 100.0},
            "http_req_failed": {"value": 0.0, "fails": 0},
            "checks": {"value": 1.0},
            "http_req_duration": {"p(95)": 30.0, "p(99)": 50.0},
        }
        before = {
            "processId": 17, "allocatedBytesTotal": 100000, "processWorkingSetBytes": 200000,
            "gc0Collections": 10, "gc1Collections": 3, "gc2Collections": 1,
            "gcPauseTimeMs": 40.0, "gcManagedHeapBytes": 50000,
        }
        after = {
            "processId": 17, "allocatedBytesTotal": 500100, "processWorkingSetBytes": 210000,
            "gc0Collections": 12, "gc1Collections": 4, "gc2Collections": 1,
            "gcPauseTimeMs": 44.0, "gcManagedHeapBytes": 52000,
        }
        parsed = parse_measurement(metrics, 45.0, before, after)
        self.assertEqual(parsed["requests"], 4500)
        self.assertEqual(parsed["errors"], 0)
        self.assertEqual(parsed["rps"], 100.0)
        self.assertEqual(parsed["allocated_bytes"], 400100)
        self.assertEqual(parsed["working_set_delta_bytes"], 10000)
        self.assertEqual((parsed["gc0_delta"], parsed["gc1_delta"], parsed["gc2_delta"]), (2, 1, 0))
        self.assertEqual(parsed["gc_pause_ms_delta"], 4.0)

    def test_three_paired_rounds_report_ci_and_nonproduction_scope(self):
        report = build_report(records(), "before-sha", "after-sha")
        self.assertEqual(report["paired_rounds"], 3)
        self.assertFalse(report["production_claim"])
        self.assertEqual(report["paired_extra_allocation_delta"]["count"], 3)
        self.assertLess(report["paired_extra_allocation_delta"]["ci95_high"], 0)
        self.assertIn("sample_stddev", report["paired_extra_allocation_delta"])
        self.assertIn("p99_ms", report["paired_metric_deltas"]["proxy"])
        self.assertEqual([row["round"] for row in report["paired_rounds_detail"]], [1, 2, 3])

    def test_preserves_existing_error_thresholds(self):
        test_records = records()
        test_records[0]["proxy"]["failed_rate"] = 0.01
        test_records[0]["proxy"]["errors"] = 45
        with self.assertRaisesRegex(ValueError, "existing <1%"):
            build_report(test_records, "before-sha", "after-sha")

    def test_requires_all_revisions_and_pinned_commits_per_round(self):
        test_records = records()
        test_records.pop()
        with self.assertRaisesRegex(ValueError, "before and after"):
            build_report(test_records, "before-sha", "after-sha")
        test_records = records()
        test_records[1]["commit"] = "not-candidate"
        with self.assertRaisesRegex(ValueError, "pinned revision"):
            build_report(test_records, "before-sha", "after-sha")

    def test_requires_order_to_alternate_between_paired_rounds(self):
        test_records = records()
        test_records[0], test_records[1] = test_records[1], test_records[0]
        with self.assertRaisesRegex(ValueError, "alternating"):
            build_report(test_records, "before-sha", "after-sha")

    def test_rejects_unmatched_workload_settings(self):
        test_records = records()
        test_records[-1]["workload"]["vus"] = 74
        with self.assertRaisesRegex(ValueError, "identical workload"):
            build_report(test_records, "before-sha", "after-sha")

    def test_rejects_counter_reset_and_latency_gate_regression(self):
        test_records = records()
        test_records[0]["proxy"]["gc2_delta"] = -1
        with self.assertRaisesRegex(ValueError, "decreased/reset"):
            build_report(test_records, "before-sha", "after-sha")
        test_records = records()
        test_records[2]["direct"]["p99_ms"] = 5000
        with self.assertRaisesRegex(ValueError, "latency"):
            build_report(test_records, "before-sha", "after-sha")

    def test_uncertain_delta_is_reported_without_claiming_improvement(self):
        test_records = records()
        for record in test_records:
            record["proxy"]["allocated_bytes"] = 500000
        report = build_report(test_records, "before-sha", "after-sha")
        self.assertIn("includes zero", report["paired_extra_allocation_delta"]["interpretation"])
        self.assertFalse(report["production_claim"])

    def test_diagnostic_overlay_is_identical_and_idempotent(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            path.write_text("before\n" + ANCHOR + "after\n", encoding="utf-8")
            instrument(source)
            first = path.read_text(encoding="utf-8")
            instrument(source)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            self.assertEqual(first.count(ADDITION), 1)

    def test_diagnostic_overlay_fails_closed_on_unrecognized_source(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            path.write_text("no known anchor\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                instrument(source)


if __name__ == "__main__":
    unittest.main()
