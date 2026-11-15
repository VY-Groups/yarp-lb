import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

P = Path(__file__).with_name("aggregate_windows_10x.py")
SPEC = importlib.util.spec_from_file_location("aggregate_windows_10x", P)
MOD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MOD)


def write_run(base, n, *, passed=True, last=900, failed=3, complete=True, role=True):
    folder = base / f"ha-windows-repeat-{n}"
    folder.mkdir()
    fault = {
        "faultType":"gateway-process-kill",
        "lastFailureAfterKillUnder2s":True,
        "beforeRequests":300, "afterRequests":210, "afterFailures":failed,
        "lastObservedFailureOffsetMs":last if failed else None,
        "p99LatencyMs":28.5,
    }
    (folder/"ha-results.json").write_text(json.dumps({
        "passed":passed, "checks":[{"description":"continuous-load-failover",
                                    "evidence":fault}]}))
    roles = ("ha-harness", "backend-a", "backend-b", "gateway-1",
             "gateway-2", "health-aware-ingress")
    clocks = {k: {"maximum_gap_ms":127.5} for k in roles}
    if not role:
        clocks.pop("backend-b")
    (folder/"heartbeat-summary.json").write_text(json.dumps({
        "diagnostics_complete":complete,"parse_failures":[],
        "clocks":clocks,"prekill_request_failures":4 if n == 5 else 0
    }))


class WindowsTenMatrixEvidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for n in range(1, 11):
            write_run(self.root, n, last=1000 + n, failed=3)

    def read(self):
        return MOD.analyze(self.root, "abcd1234", "123456")

    def test_complete_matrix_reports_true_worst_and_warmup_failures(self):
        result = self.read()
        self.assertEqual(result["runs_verified"], 10)
        self.assertEqual(result["worst_recorded_last_failure_after_kill_ms"],1010)
        self.assertEqual(result["total_failed_requests_after_kill"],30)
        self.assertEqual(result["prekill_failures_recorded"],4)
        self.assertFalse(result["production_physical_ha_certified"])

    def test_missing_artifact_rejected(self):
        import shutil
        shutil.rmtree(self.root/"ha-windows-repeat-10")
        with self.assertRaisesRegex(MOD.EvidenceFailure, "Exactly 10"):
            self.read()

    def test_extra_duplicate_name_rejected(self):
        (self.root/"ha-windows-repeat-11").mkdir()
        with self.assertRaisesRegex(MOD.EvidenceFailure, "Exactly 10"):
            self.read()

    def test_failed_run_not_silently_overridden(self):
        write_run = self.root/"ha-windows-repeat-3"/"ha-results.json"
        obj=json.loads(write_run.read_text());obj["passed"]=False
        write_run.write_text(json.dumps(obj))
        with self.assertRaisesRegex(MOD.EvidenceFailure, "not passed"):
            self.read()

    def test_missing_fault_result_rejected(self):
        p=self.root/"ha-windows-repeat-1"/"ha-results.json"
        obj=json.loads(p.read_text());obj["checks"]=[]
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(MOD.EvidenceFailure, "precisely one"):
            self.read()

    def test_failure_window_over_two_seconds_rejected(self):
        p=self.root/"ha-windows-repeat-1"/"ha-results.json"
        obj=json.loads(p.read_text());obj["checks"][0]["evidence"]["lastObservedFailureOffsetMs"]=2100
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(MOD.EvidenceFailure, "exceeds 2000ms"):
            self.read()

    def test_missing_heartbeat_rejected(self):
        (self.root/"ha-windows-repeat-8"/"heartbeat-summary.json").unlink()
        with self.assertRaisesRegex(MOD.EvidenceFailure, "missing result or heartbeat"):
            self.read()

    def test_missing_role_rejected(self):
        p=self.root/"ha-windows-repeat-2"/"heartbeat-summary.json"
        obj=json.loads(p.read_text());obj["clocks"].pop("gateway-1")
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(MOD.EvidenceFailure, "roles absent"):
            self.read()

    def test_nonfinite_or_negative_metric_rejected(self):
        p=self.root/"ha-windows-repeat-1"/"ha-results.json"
        obj=json.loads(p.read_text());obj["checks"][0]["evidence"]["afterFailures"]=-1
        p.write_text(json.dumps(obj))
        with self.assertRaisesRegex(MOD.EvidenceFailure, "nonnegative"):
            self.read()

    def test_no_post_kill_errors_not_fabricated_as_window(self):
        for n in range(1,11):
            p=self.root/f"ha-windows-repeat-{n}"/"ha-results.json"
            obj=json.loads(p.read_text())
            obj["checks"][0]["evidence"]["afterFailures"]=0
            obj["checks"][0]["evidence"]["lastObservedFailureOffsetMs"]=None
            p.write_text(json.dumps(obj))
        report=self.read()
        self.assertIsNone(report["worst_recorded_last_failure_after_kill_ms"])
        self.assertEqual(report["runs_with_no_post_kill_failure"],10)


if __name__ == "__main__":
    unittest.main()
