"""Offline negative acceptance for the redacted WAF confusion-matrix gate."""
import importlib.util
import unittest
import tempfile
import json
import os
import stat
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

    def test_oversized_corpus_rejected(self):
        with self.assertRaises(ValueError):
            module.evaluate([self.cases[0]] * (module.MAX_CORPUS_CASES + 1), self.policy)

    def test_policy_class_budget_rejected(self):
        policy = {f"/route-{i}": {"high": dict(self.policy["/api"]["high"])}
                  for i in range(module.MAX_POLICY_CLASSES + 1)}
        with self.assertRaises(ValueError):
            module.evaluate(self.cases, policy)

    def test_bounded_json_reader_rejects_oversized_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.json"
            with path.open("wb") as stream:
                stream.truncate(module.MAX_INPUT_BYTES + 1)
            with self.assertRaises(ValueError):
                module._read_bounded_json(path)

    def test_duplicate_policy_and_corpus_json_fields_rejected(self):
        # Duplicate properties must never override an operator-approved
        # threshold or the ground-truth classification of a WAF test case.
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.json"
            for raw in (
                '{"route":{"high":{"max_fp_rate":0,"max_fp_rate":1}}}',
                '[{"case_id":"case-1","expected_attack":true,"expected_attack":false}]',
                '{"a":{"nested":1,"nested":2}}',
            ):
                with self.subTest(raw=raw):
                    path.write_text(raw, encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "duplicate JSON property"):
                        module._read_bounded_json(path)


    @unittest.skipUnless(os.name == "posix", "0600 mode is a POSIX permission contract")
    def test_private_report_atomically_replaces_broad_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "matrix.json"
            report.write_text("old-public-summary", encoding="utf-8")
            os.chmod(report, 0o644)
            expected = module.evaluate(self.cases, self.policy)
            module.write_private_report(report, expected)
            self.assertEqual(json.loads(report.read_text(encoding="utf-8")), expected)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
            self.assertFalse((Path(directory) / "matrix.json.tmp").exists())

    def test_private_report_rejects_symlink_destination_without_touching_target(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "keep-private.txt"
            target.write_text("DO_NOT_REPLACE", encoding="utf-8")
            destination = Path(directory) / "matrix.json"
            try:
                destination.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this test host")
            with self.assertRaises(ValueError):
                module.write_private_report(destination, module.evaluate(self.cases, self.policy))
            self.assertEqual(target.read_text(encoding="utf-8"), "DO_NOT_REPLACE")

    def test_private_report_rejects_existing_temporary_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "keep-private.txt"
            target.write_text("DO_NOT_REPLACE", encoding="utf-8")
            temporary = Path(directory) / "matrix.json.tmp"
            try:
                temporary.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this test host")
            with self.assertRaises((FileExistsError, OSError)):
                module.write_private_report(Path(directory) / "matrix.json",
                                            module.evaluate(self.cases, self.policy))
            self.assertEqual(target.read_text(encoding="utf-8"), "DO_NOT_REPLACE")
            self.assertFalse((Path(directory) / "matrix.json").exists())

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
