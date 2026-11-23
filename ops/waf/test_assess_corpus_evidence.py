"""Deterministic negative and positive tests for WAF corpus evidence gate."""
import csv
import importlib.util
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("assess_corpus_evidence.py")
spec = importlib.util.spec_from_file_location("waf_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "corpus.csv"

    def write(self, rows):
        with self.path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(gate.FIELDS)
            writer.writerows(rows)

    def test_exact_per_route_pass(self):
        self.write([("/a", "1", "benign", "allowed", "block"),
                    ("/a", "2", "malicious", "blocked", "block"),
                    ("/b", "3", "benign", "allowed", "block"),
                    ("/b", "4", "malicious", "blocked", "block")])
        result = gate.assess(self.path, 0, 0, 1, 1)
        self.assertTrue(result["pass"])
        self.assertEqual(result["routes"]["/a"]["tp"], 1)

    def test_false_positive_and_negative_fail(self):
        self.write([("/a", "1", "benign", "blocked", "block"),
                    ("/a", "2", "malicious", "allowed", "block")])
        result = gate.assess(self.path, 0, 0, 1, 1)
        self.assertFalse(result["pass"])
        self.assertEqual(result["routes"]["/a"]["fp"], 1)
        self.assertEqual(result["routes"]["/a"]["fn"], 1)

    def test_aggregate_success_cannot_mask_weak_route(self):
        self.write([("/good", "1", "benign", "allowed", "block"),
                    ("/good", "2", "malicious", "blocked", "block"),
                    ("/bad", "3", "benign", "blocked", "block"),
                    ("/bad", "4", "malicious", "blocked", "block")])
        self.assertFalse(gate.assess(self.path, .1, .1, 1, 1)["pass"])

    def test_missing_class_fails(self):
        self.write([("/a", "1", "benign", "allowed", "block")])
        self.assertFalse(gate.assess(self.path, 0, 0, 1, 1)["pass"])

    def test_shadow_mode_rejected(self):
        self.write([("/a", "1", "benign", "allowed", "detect")])
        with self.assertRaisesRegex(ValueError, "enforcement"):
            gate.assess(self.path, 0, 0, 1, 1)

    def test_duplicate_case_rejected(self):
        self.write([("/a", "1", "benign", "allowed", "block"),
                    ("/a", "1", "malicious", "blocked", "block")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            gate.assess(self.path, 0, 0, 1, 1)

    def test_invalid_threshold_rejected(self):
        self.write([("/a", "1", "benign", "allowed", "block")])
        with self.assertRaises(ValueError):
            gate.assess(self.path, -1, 0, 1, 1)

    def test_unknown_csv_columns_rejected(self):
        self.path.write_text("route,case_id,expected,observed,mode,secret\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "header"):
            gate.assess(self.path, 0, 0, 1, 1)


if __name__ == "__main__":
    unittest.main()
