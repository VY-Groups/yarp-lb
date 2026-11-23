"""Regression tests for the issue #51 WAF corpus evidence gate."""
import csv
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("waf_gate", pathlib.Path(__file__).with_name("corpus_evidence_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

POLICY = {"mode": "block", "routes": {"/api": {"max_fp": 0, "max_fn": 0}}}


def row(case, expected, observed, mode="block", route="/api"):
    return {"case_id": case, "route": route, "expected": expected,
            "observed": observed, "mode": mode, "severity": "high"}


class EvidenceGateTests(unittest.TestCase):
    def check_cli_fails_cleanly(self, policy_json):
        with tempfile.TemporaryDirectory(prefix="waf-evidence-policy-negative-") as scratch:
            root = pathlib.Path(scratch)
            policy_file = root / "policy.json"
            csv_file = root / "cases.csv"
            output_file = root / "report.json"
            policy_file.write_text(policy_json, encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=sorted(gate.FIELDS))
                writer.writeheader()
                writer.writerow(row("benign", "benign", "allow"))
                writer.writerow(row("attack", "malicious", "block"))
            process = subprocess.run(
                [sys.executable, str(pathlib.Path(gate.__file__)), "--corpus",
                 str(csv_file), "--policy", str(policy_file), "--out", str(output_file)],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(process.returncode, 1)
            self.assertNotIn("Traceback", process.stdout + process.stderr)
            self.assertTrue(output_file.is_file())
            report = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "FAIL")
            self.assertTrue(report["failures"])

    def test_cli_rejects_non_object_policy_and_non_object_route_limits(self):
        invalid = [
            [], None, 42, "text",
            {"mode": [], "routes": {"/api": {"max_fp": 0, "max_fn": 0}}},
            {"mode": "block", "routes": {"/api": None}},
            {"mode": "block", "routes": {"/api": ["max_fp", "max_fn"]}},
            {"mode": "block", "routes": {"/api": 10}},
            {"mode": "block", "routes": []},
        ]
        for policy in invalid:
            with self.subTest(policy=policy):
                self.check_cli_fails_cleanly(json.dumps(policy))

    def test_cli_rejects_duplicate_thresholds_and_non_json_constants(self):
        for policy_json in (
            '{"mode":"block","routes":{"/api":{"max_fp":0,"max_fp":100,"max_fn":0}}}',
            '{"mode":"block","routes":{"/api":{"max_fp":NaN,"max_fn":0}}}',
        ):
            with self.subTest(policy_json=policy_json):
                self.check_cli_fails_cleanly(policy_json)

    def test_clean_corpus(self):
        report = gate.evaluate([row("benign", "benign", "allow"),
                                row("attack", "malicious", "block")], POLICY)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["routes"]["/api"], {"tp": 1, "tn": 1, "fp": 0, "fn": 0})

    def test_false_negative_fails(self):
        result = gate.evaluate([row("benign", "benign", "allow"),
                                row("attack", "malicious", "allow")], POLICY)
        self.assertEqual(result["status"], "FAIL")

    def test_false_positive_fails(self):
        result = gate.evaluate([row("benign", "benign", "block"),
                                row("attack", "malicious", "block")], POLICY)
        self.assertEqual(result["status"], "FAIL")

    def test_unapproved_route_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate([row("one", "benign", "allow", route="/other")], POLICY)

    def test_duplicate_evidence_rejected(self):
        with self.assertRaises(ValueError):
            gate.evaluate([row("same", "benign", "allow"),
                           row("same", "malicious", "block")], POLICY)

    def test_detect_mode_must_not_block(self):
        policy = {"mode": "detect", "routes": POLICY["routes"]}
        with self.assertRaises(ValueError):
            gate.evaluate([row("one", "benign", "block", mode="detect")], policy)

    def test_unrepresented_route_rejected(self):
        policy = {"mode": "block", "routes": {**POLICY["routes"], "/admin": {"max_fp": 0, "max_fn": 0}}}
        with self.assertRaises(ValueError):
            gate.evaluate([row("benign", "benign", "allow"),
                           row("attack", "malicious", "block")], policy)

    def test_no_malicious_ground_truth_fails(self):
        self.assertEqual(gate.evaluate([row("one", "benign", "allow")], POLICY)["status"], "FAIL")

    def test_non_integer_threshold_rejected(self):
        policy = {"mode": "block", "routes": {"/api": {"max_fp": True, "max_fn": 0}}}
        with self.assertRaises(ValueError):
            gate.evaluate([row("one", "benign", "allow")], policy)


if __name__ == "__main__":
    unittest.main()
