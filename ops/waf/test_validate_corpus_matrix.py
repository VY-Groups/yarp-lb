"""Offline negative acceptance for the redacted WAF confusion-matrix gate."""
import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("waf_matrix", Path(__file__).with_name("validate_corpus_matrix.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"/api": {"high": {"max_fp_rate": 0.0, "max_fn_rate": 0.0,
                                          "min_benign": 1, "min_attack": 1}}}
        self.cases = [
            {"case_id": "benign-1", "route": "/api", "severity": "high",
             "expected_attack": False, "blocked": False, "mode": "block"},
            {"case_id": "attack-1", "route": "/api", "severity": "high",
             "expected_attack": True, "blocked": True, "mode": "block"},
        ]

    def test_clean_pass(self):
        result = module.evaluate(self.cases, self.policy)
        self.assertTrue(result["pass"])
        self.assertEqual(result["matrix"][0]["tp"], 1)

    def test_false_positive_fails(self):
        self.cases[0]["blocked"] = True
        self.assertFalse(module.evaluate(self.cases, self.policy)["pass"])

    def test_false_negative_fails(self):
        self.cases[1]["blocked"] = False
        self.assertFalse(module.evaluate(self.cases, self.policy)["pass"])

    def test_missing_attack_coverage_fails(self):
        self.assertFalse(module.evaluate(self.cases[:1], self.policy)["pass"])

    def test_detect_only_never_counts_as_block_proof(self):
        for case in self.cases:
            case["mode"] = "detect"
            case["blocked"] = False
        self.assertFalse(module.evaluate(self.cases, self.policy)["pass"])

    def test_detect_only_block_fails_closed(self):
        self.cases[1]["mode"] = "detect"
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)

    def test_duplicate_id_rejected(self):
        self.cases[1]["case_id"] = "benign-1"
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)

    def test_unknown_route_rejected(self):
        self.cases[1]["route"] = "/admin"
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)

    def test_extra_private_fields_rejected(self):
        self.cases[0]["request_body"] = "secret"
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)

    def test_invalid_threshold_rejected(self):
        self.policy["/api"]["high"]["max_fp_rate"] = float("nan")
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)

    def test_missing_policy_class_rejected(self):
        del self.policy["/api"]["high"]["min_attack"]
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, self.policy)


if __name__ == "__main__":
    unittest.main()
