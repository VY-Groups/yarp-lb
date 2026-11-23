"""Regression tests for the issue #51 WAF corpus evidence gate."""
import csv
import importlib.util
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("waf_gate", pathlib.Path(__file__).with_name("corpus_evidence_gate.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

POLICY = {"schemaVersion": 2, "mode": "block", "routes": {"/api": {"max_fp": 0, "max_fn": 0}}}


def row(case, expected, observed, mode="block", route="/api", would_block=None):
    if would_block is None:
        would_block = observed == "block"
    return {"case_id": case, "route": route, "expected": expected,
            "observed": observed, "would_block": "true" if would_block else "false",
            "mode": mode, "severity": "high"}


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
            {"schemaVersion": 2, "mode": [], "routes": {"/api": {"max_fp": 0, "max_fn": 0}}},
            {"schemaVersion": 2, "mode": "block", "routes": {"/api": None}},
            {"schemaVersion": 2, "mode": "block", "routes": {"/api": ["max_fp", "max_fn"]}},
            {"schemaVersion": 2, "mode": "block", "routes": {"/api": 10}},
            {"schemaVersion": 2, "mode": "block", "routes": []},
        ]
        for policy in invalid:
            with self.subTest(policy=policy):
                self.check_cli_fails_cleanly(json.dumps(policy))

    def test_cli_rejects_duplicate_thresholds_and_non_json_constants(self):
        for policy_json in (
            '{"schemaVersion":2,"mode":"block","routes":{"/api":{"max_fp":0,"max_fp":100,"max_fn":0}}}',
            '{"schemaVersion":2,"mode":"block","routes":{"/api":{"max_fp":NaN,"max_fn":0}}}',
        ):
            with self.subTest(policy_json=policy_json):
                self.check_cli_fails_cleanly(policy_json)

    def test_success_cli_redacts_route_identifiers_and_seals_private_report(self):
        with tempfile.TemporaryDirectory(prefix="waf-evidence-private-") as scratch:
            root = pathlib.Path(scratch)
            private_route = "/customer-route-secret-canary"
            policy_file, csv_file, output_file = (root / name for name in
                ("policy.json", "cases.csv", "report.json"))
            policy_file.write_text(json.dumps({"schemaVersion": 2, "mode": "block", "routes": {
                private_route: {"max_fp": 0, "max_fn": 0}
            }}), encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=sorted(gate.FIELDS))
                writer.writeheader()
                writer.writerow(row("customer-benign-id", "benign", "allow",
                                    route=private_route))
                writer.writerow(row("customer-attack-id", "malicious", "block",
                                    route=private_route))
            p = subprocess.run(
                [sys.executable, str(pathlib.Path(gate.__file__)), "--corpus",
                 str(csv_file), "--policy", str(policy_file), "--out", str(output_file)],
                capture_output=True, text=True, timeout=10, check=False)
            self.assertEqual(p.returncode, 0)
            self.assertEqual(json.loads(p.stdout), {"status": "PASS", "cases": 2})
            self.assertNotIn("customer-", p.stdout + p.stderr)
            private = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertIn(private_route, private["routes"])
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(output_file.stat().st_mode), 0o600)
            self.assertFalse(output_file.with_name(output_file.name + ".tmp").exists())

    def test_cli_refuses_symlink_report_and_preexisting_temp_alias(self):
        if os.name != "posix":
            self.skipTest("POSIX local report and symlink permissions test")
        with tempfile.TemporaryDirectory(prefix="waf-evidence-symlink-") as scratch:
            root = pathlib.Path(scratch)
            policy_file, csv_file, out_file = (root / name for name in
                ("policy.json", "cases.csv", "report.json"))
            policy_file.write_text(json.dumps(POLICY), encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=sorted(gate.FIELDS))
                writer.writeheader()
                writer.writerow(row("benign", "benign", "allow"))
                writer.writerow(row("attack", "malicious", "block"))
            sentinel = root / "do-not-overwrite"
            sentinel.write_text("unchanged", encoding="utf-8")
            command = [sys.executable, str(pathlib.Path(gate.__file__)),
                       "--corpus", str(csv_file), "--policy", str(policy_file),
                       "--out", str(out_file)]
            out_file.symlink_to(sentinel)
            response = subprocess.run(command, capture_output=True, text=True,
                                      timeout=10, check=False)
            self.assertEqual(response.returncode, 2)
            self.assertNotIn("Traceback", response.stdout + response.stderr)
            self.assertEqual(sentinel.read_text(), "unchanged")
            out_file.unlink()
            alias = out_file.with_name(out_file.name + ".tmp")
            alias.symlink_to(sentinel)
            response = subprocess.run(command, capture_output=True, text=True,
                                      timeout=10, check=False)
            self.assertEqual(response.returncode, 2)
            self.assertNotIn("Traceback", response.stdout + response.stderr)
            self.assertEqual(sentinel.read_text(), "unchanged")
            self.assertTrue(alias.is_symlink())

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

    def test_shadow_mode_counts_rule_verdict_without_blocking_requests(self):
        policy = {"schemaVersion": 2, "mode": "detect", "routes": POLICY["routes"]}
        report = gate.evaluate([
            row("benign", "benign", "allow", mode="detect", would_block=False),
            row("attack", "malicious", "allow", mode="detect", would_block=True)
        ], policy)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["mode"], "detect")
        self.assertEqual(report["schemaVersion"], 2)
        self.assertEqual(report["routes"]["/api"],
                         {"tp": 1, "tn": 1, "fp": 0, "fn": 0})

    def test_shadow_false_positive_and_negative_still_fail(self):
        policy = {"schemaVersion": 2, "mode": "detect", "routes": POLICY["routes"]}
        report = gate.evaluate([
            row("benign", "benign", "allow", mode="detect", would_block=True),
            row("attack", "malicious", "allow", mode="detect", would_block=False)
        ], policy)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["routes"]["/api"]["fp"], 1)
        self.assertEqual(report["routes"]["/api"]["fn"], 1)

    def test_block_mode_rejects_unverifiable_or_inconsistent_decisions(self):
        with self.assertRaises(ValueError):
            gate.evaluate([row("inconsistent", "benign", "allow", would_block=True)], POLICY)
        invalid = row("unknown", "benign", "allow")
        invalid["would_block"] = "yes"
        with self.assertRaises(ValueError):
            gate.evaluate([invalid], POLICY)
        legacy = row("legacy", "benign", "allow")
        legacy.pop("would_block")
        with self.assertRaises(ValueError):
            gate.evaluate([legacy], POLICY)

    def test_detect_mode_must_not_block(self):
        policy = {"schemaVersion": 2, "mode": "detect", "routes": POLICY["routes"]}
        with self.assertRaises(ValueError):
            gate.evaluate([row("one", "benign", "block", mode="detect")], policy)

    def test_unrepresented_route_rejected(self):
        policy = {"schemaVersion": 2, "mode": "block", "routes": {**POLICY["routes"], "/admin": {"max_fp": 0, "max_fn": 0}}}
        with self.assertRaises(ValueError):
            gate.evaluate([row("benign", "benign", "allow"),
                           row("attack", "malicious", "block")], policy)

    def test_no_malicious_ground_truth_fails(self):
        self.assertEqual(gate.evaluate([row("one", "benign", "allow")], POLICY)["status"], "FAIL")

    def test_non_integer_threshold_rejected(self):
        policy = {"schemaVersion": 2, "mode": "block", "routes": {"/api": {"max_fp": True, "max_fn": 0}}}
        with self.assertRaises(ValueError):
            gate.evaluate([row("one", "benign", "allow")], policy)


if __name__ == "__main__":
    unittest.main()
