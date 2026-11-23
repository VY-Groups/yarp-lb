"""Regression tests for the issue #51 WAF corpus evidence gate."""
import importlib.util
import pathlib
import unittest

spec = importlib.util.spec_from_file_location("waf_gate", pathlib.Path(__file__).with_name("corpus_evidence_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

POLICY = {"mode": "block", "routes": {"/api": {"max_fp": 0, "max_fn": 0}}}


def row(case, expected, observed, mode="block", route="/api"):
    return {"case_id": case, "route": route, "expected": expected,
            "observed": observed, "mode": mode, "severity": "high"}


class EvidenceGateTests(unittest.TestCase):
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
