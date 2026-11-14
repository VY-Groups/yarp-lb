import csv
from pathlib import Path
import tempfile
import unittest
from heartbeat_summary import analyze, EXPECTED_EARLY


def make_samples(folder: Path, role: str, utc: list[int]):
    path = folder / f"heartbeat-{role}.csv"
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["role","pid","utc_unix_ms","monotonic_ticks",
                         "stopwatch_frequency","threadpool_threads",
                         "pending_work_items","cpu_total_ms"])
        for millis in utc:
            # 1 MHz Stopwatch frequency, so 1 ms = 1000 ticks
            writer.writerow([role,44,millis,millis * 1000,1000000,5,0,1.0])


class HeartbeatContract(unittest.TestCase):
    def test_correlated_shared_pause_is_only_a_hypothesis(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for role in EXPECTED_EARLY:
                if role == "ha-harness":
                    make_samples(root,role,[1000,1100,1600,1700])
                elif role == "gateway-1":
                    make_samples(root,role,[1000,1100,1610,1710])
                else:
                    make_samples(root,role,[1000,1100,1200,1300,1400])
            report = analyze(root)
            self.assertTrue(report["diagnostics_complete"])
            self.assertEqual(report["clocks"]["ha-harness"]["samples"],4)
            self.assertEqual(report["clocks"]["ha-harness"]["maximum_gap_ms"],500)
            self.assertTrue(any(
                e["role"]=="gateway-1" and
                "ha-harness" in e["overlap_roles"]
                for e in report["cross_process_gap_candidates"]))
            self.assertIn("Neither alone proves cause",report["interpretation"])

    def test_wired_harness_filename_matches_recorded_role(self):
        # Regression for the first executed Ubuntu artifact, where a file named
        # heartbeat-harness.csv contained role=ha-harness and was treated as
        # missing even though the underlying 100ms samples existed.
        program = (Path(__file__).parent / "Acceptance" / "Program.cs").read_text()
        self.assertIn('Path.Combine(artifacts,"heartbeat-ha-harness.csv"),"ha-harness"',program)

    def test_independent_heartbeat_does_not_use_threadpool(self):
        source = (Path(__file__).parent / "Heartbeat" / "HaProcessHeartbeat.cs").read_text()
        self.assertIn("new Thread(Pump)", source)
        self.assertIn("stopping.Wait(100)", source)
        self.assertNotIn("Task.Run", source)

    def test_isolated_harness_gap_flagged_without_claiming_runner_pause(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            for role in EXPECTED_EARLY:
                times=[1000,1100,1700,1800] if role=="ha-harness" else [
                    1000,1100,1200,1300,1400,1500,1600,1700,1800]
                make_samples(root,role,times)
            report=analyze(root)
            self.assertTrue(report["diagnostics_complete"])
            self.assertEqual(report["cross_process_gap_candidates"],[])
            isolated=report["isolated_gap_candidates"]
            self.assertEqual(len(isolated),1)
            self.assertEqual(isolated[0]["role"],"ha-harness")
            self.assertEqual(isolated[0]["duration_ms"],600)

    def test_no_data_is_never_diagnostic_success(self):
        with tempfile.TemporaryDirectory() as t:
            report = analyze(Path(t))
            self.assertFalse(report["diagnostics_complete"])
            self.assertGreater(len(report["expected_early_missing"]),0)

    def test_failed_http_sample_survives(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            make_samples(root,"ha-harness",[1000,1100,1200])
            with (root/"prekill-request-timeline.csv").open("w",newline="") as fh:
                w=csv.writer(fh)
                w.writerow(["phase","start_utc_ms","end_utc_ms","status","error"])
                w.writerow(["post-slow-healthy",1000,1200,502,""])
                w.writerow(["post-slow-healthy",1200,1300,0,"timeout:TaskCanceledException"])
            report=analyze(root)
            self.assertEqual(report["prekill_requests_recorded"],2)
            self.assertEqual(report["prekill_request_failures"],2)
            self.assertFalse(report["diagnostics_complete"])


if __name__ == "__main__":
    unittest.main()
