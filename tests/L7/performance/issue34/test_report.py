import unittest
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import urllib.request

from instrument_lab_stats import (ADDITION, ANCHOR, DIMENSION_CALL_PATTERN, METRIC_CALL,
                                 METRIC_CALL_WITH_DIMENSIONS, instrument,
                                 instrument_activity_lifecycle)
from report import build_report
from run_paired_profile import (_drain_bounded_log, measurement as parse_measurement,
                               format_early_trace_exit, OtlpReceiver, resolve_checkout)


ISSUE34_DIR = Path(__file__).resolve().parent
OLD_TELEMETRY_HELPER = """    public static void CompleteProxyActivity(Activity? activity, HttpContext context, string? destinationId)
    {
        if (activity is null) return;
        SetBoundedId(activity, "gateway.destination.id", destinationId);
        activity.SetTag("http.response.status_code", context.Response.StatusCode);
        if (context.Response.StatusCode >= 500)
            activity.SetStatus(ActivityStatusCode.Error);
    }"""
STOPPED_TELEMETRY_HELPER = OLD_TELEMETRY_HELPER[:-5] + "        activity.Stop();\n    }"


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
    def test_disposable_otlp_receiver_counts_nonempty_signal_exports(self):
        receiver = OtlpReceiver()
        try:
            payloads = {
                "traces": b"gateway.proxy.request gateway.route.id gateway.cluster.id gateway.destination.id api",
                "metrics": b"gateway.proxy.requests gateway.route.id gateway.cluster.id gateway.destination.id api A B",
                "logs": b"disposable access log",
            }
            for signal in ("traces", "metrics", "logs"):
                request = urllib.request.Request(
                    f"{receiver.endpoint}/v1/{signal}", data=payloads[signal],
                    headers={"Content-Type": "application/x-protobuf"}, method="POST")
                with urllib.request.urlopen(request, timeout=2) as response:
                    self.assertEqual(response.status, 200)
            snapshot = receiver.snapshot()
            for signal in ("traces", "metrics", "logs"):
                self.assertEqual(snapshot[signal]["requests"], 1)
                self.assertEqual(snapshot[signal]["payload_bytes"], len(payloads[signal]))
            self.assertIn("gateway.proxy.requests", snapshot["metrics"]["markers"])
            self.assertIn("gateway.destination.id", snapshot["metrics"]["markers"])
        finally:
            receiver.close()

    def test_k6_and_gateway_counter_parser_keeps_all_requested_metrics(self):
        metrics = {
            "http_reqs": {"count": 4500, "rate": 100.0},
            # k6 Rate summary `fails` counts false samples, which for
            # http_req_failed are successful requests; it is not HTTP errors.
            "http_req_failed": {"value": 0.0, "passes": 0, "fails": 4500},
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

    def test_http_errors_come_from_k6_failure_rate_not_rate_sample_counts(self):
        metrics = {
            "http_reqs": {"count": 1000, "rate": 100.0},
            "http_req_failed": {"value": 0.002, "passes": 2, "fails": 998},
            "checks": {"value": 1.0},
            "http_req_duration": {"p(95)": 30.0, "p(99)": 50.0},
        }
        parsed = parse_measurement(metrics, 10.0, {
            "processId": 17, "allocatedBytesTotal": 100, "processWorkingSetBytes": 100,
            "gc0Collections": 0, "gc1Collections": 0, "gc2Collections": 0,
            "gcPauseTimeMs": 0.0, "gcManagedHeapBytes": 0,
        }, {
            "processId": 17, "allocatedBytesTotal": 200, "processWorkingSetBytes": 100,
            "gc0Collections": 0, "gc1Collections": 0, "gc2Collections": 0,
            "gcPauseTimeMs": 0.0, "gcManagedHeapBytes": 0,
        })
        self.assertEqual(parsed["errors"], 2)
        self.assertEqual(parsed["failed_rate"], 0.002)

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


    def test_rejects_impossible_rate_latency_and_counter_evidence(self):
        cases = (
            ("checks_rate", 1.25, "between 0 and 1"),
            ("rps", -1, "request rate must be positive"),
            ("p95_ms", -10, "latency ordering"),
            ("p99_ms", 5, "latency ordering"),
            ("requests", 4500.5, "whole numbers"),
            ("errors", 0.5, "whole numbers"),
        )
        for field, value, reason in cases:
            with self.subTest(field=field):
                samples = records()
                samples[0]["proxy"][field] = value
                if field == "errors":
                    samples[0]["proxy"]["failed_rate"] = value / 4500
                with self.assertRaisesRegex(ValueError, reason):
                    build_report(samples, "before-sha", "after-sha")

    def test_rejects_missing_or_unbounded_workload_metadata(self):
        cases = (
            ("vus", 0, "virtual-user"),
            ("duration", "1s", "duration"),
            ("payload_bytes", -1, "payload byte"),
            ("connection_reuse", "true", "connection-reuse"),
            ("payload_bytes", None, "missing required workload"),
        )
        for field, value, reason in cases:
            with self.subTest(field=field, value=value):
                samples = records()
                if value is None:
                    samples[0]["workload"].pop(field)
                else:
                    samples[0]["workload"][field] = value
                with self.assertRaisesRegex(ValueError, reason):
                    build_report(samples, "before-sha", "after-sha")

    def test_many_paired_rounds_use_conservative_student_t_critical(self):
        from report import _mean_ci, T95
        sample = [0.0] * 15 + [1.0] * 16
        summary = _mean_ci(sample)
        self.assertEqual(summary["count"], 31)
        # The 30-DF critical is not tabulated: keep the conservative 29-DF
        # bound instead of shrinking it to the normal approximation.
        import math
        import statistics
        margin = T95[29] * statistics.stdev(sample) / math.sqrt(len(sample))
        self.assertAlmostEqual(summary["ci95_high"], round(
            statistics.fmean(sample) + margin, 3))

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
            api = source / "control-center/GatewayOpenTelemetry.cs"
            api.parent.mkdir(parents=True)
            api.write_text(OLD_TELEMETRY_HELPER + "\n", encoding="utf-8")
            path.write_text("before\n" + ANCHOR + "after\n" + METRIC_CALL + "\n", encoding="utf-8")
            instrument(source)
            first = path.read_text(encoding="utf-8")
            instrument(source)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            self.assertEqual(first.count(ADDITION), 1)
            self.assertEqual(first.count(METRIC_CALL_WITH_DIMENSIONS), 1)
            self.assertNotIn(METRIC_CALL, first)
            self.assertEqual(api.read_text(encoding="utf-8").count("activity.Stop();"), 1)

    def test_diagnostic_overlay_accepts_native_dimension_call_with_intervening_statements(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            api = source / "control-center/GatewayOpenTelemetry.cs"
            api.parent.mkdir(parents=True)
            api.write_text(STOPPED_TELEMETRY_HELPER + "\n", encoding="utf-8")
            native_call = (
                "var feature = ctx.GetReverseProxyFeature();\n"
                "var destination = feature.ProxiedDestination;\n"
                "GatewayOpenTelemetry.CompleteProxyActivity(activity, ctx, destination?.DestinationId);\n"
                "GatewayOpenTelemetry.RecordProxyResult(ctx, elapsedMs,\n"
                "    feature.Route.Config.RouteId, feature.Cluster.Config.ClusterId,\n"
                "    destination?.DestinationId);\n"
            )
            path.write_text(ANCHOR + native_call, encoding="utf-8")
            instrument(source)
            first = path.read_text(encoding="utf-8")
            instrument(source)
            self.assertEqual(path.read_text(encoding="utf-8"), first)
            self.assertEqual(first.count(ADDITION), 1)
            self.assertEqual(len(DIMENSION_CALL_PATTERN.findall(first)), 1)
            self.assertIn("CompleteProxyActivity", first)
            self.assertIn("destination?.DestinationId", first)
            self.assertEqual(api.read_text(encoding="utf-8").count("activity.Stop();"), 1)

    def test_telemetry_overlay_fails_closed_on_unknown_completion_helper(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            api = source / "control-center/GatewayOpenTelemetry.cs"
            api.parent.mkdir(parents=True)
            api.write_text("public static void CompleteProxyActivity(Activity? activity) {}\n",
                           encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "proxy activity completion helper"):
                instrument_activity_lifecycle(source)

    def test_historical_baseline_without_otel_api_keeps_gc_overlay(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            historical = "before\n" + ANCHOR + "after\n"
            path.write_text(historical, encoding="utf-8")
            instrument(source)
            result = path.read_text(encoding="utf-8")
            self.assertIn(ADDITION, result)
            self.assertNotIn("GatewayOpenTelemetry", result)
            instrument(source)
            self.assertEqual(path.read_text(encoding="utf-8"), result)

    def test_modern_source_with_otel_api_but_missing_metric_call_fails_closed(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            api = source / "control-center/GatewayOpenTelemetry.cs"
            api.parent.mkdir(parents=True)
            api.write_text(OLD_TELEMETRY_HELPER + "\n", encoding="utf-8")
            path.write_text("before\n" + ANCHOR + "after\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "proxy result metric call"):
                instrument(source)

    def test_diagnostic_overlay_fails_closed_on_unrecognized_source(self):
        with TemporaryDirectory() as tmp:
            source = Path(tmp)
            path = source / "tests/L7/GatewayLab/Program.cs"
            path.parent.mkdir(parents=True)
            path.write_text("no known anchor\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "lab stats anchor"):
                instrument(source)

    def test_process_log_is_capped_and_stream_is_drained(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "process.log"
            source = BytesIO(b"x" * 100)
            _drain_bounded_log(source, path, limit=16)
            value = path.read_bytes()
            self.assertTrue(value.startswith(b"x" * 16))
            self.assertIn(b"truncated at 16 bytes", value)
            self.assertEqual(source.read(), b"")

    def test_checkout_resolution_is_absolute_before_child_cwd_changes(self):
        with TemporaryDirectory(dir=Path.cwd()) as tmp:
            checkout = Path(tmp) / "checkout"
            checkout.mkdir()
            relative = checkout.relative_to(Path.cwd())
            resolved = resolve_checkout(relative)
            self.assertEqual(resolved, checkout.resolve())
            self.assertTrue(resolved.is_absolute())

    def test_early_trace_exit_diagnostic_includes_exit_code_target_and_log(self):
        message = format_early_trace_exit("before", 1234, 17, "diagnostic socket denied")
        self.assertIn("exit 17", message)
        self.assertIn("target pid 1234", message)
        self.assertIn("diagnostic socket denied", message)

    @unittest.skipUnless(os.name == "posix", "RLIMIT_FSIZE is a POSIX runner feature")
    def test_trace_size_limit_applies_only_to_its_exec_child(self):
        with TemporaryDirectory() as tmp:
            output = Path(tmp) / "oversized.bin"
            writer = ("from pathlib import Path; import sys; "
                      "Path(sys.argv[1]).write_bytes(b'x' * (2 * 1024 * 1024))")
            result = subprocess.run(
                [sys.executable, str(ISSUE34_DIR / "trace_exec.py"), str(1024 * 1024),
                 sys.executable, "-c", writer, str(output)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(output.stat().st_size, 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
