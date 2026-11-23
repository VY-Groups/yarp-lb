"""Additive v3 acceptance for the existing authoritative WAF corpus gate."""
import csv
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

FILE = Path(__file__).with_name("corpus_evidence_gate.py")
spec = importlib.util.spec_from_file_location("existing_waf_corpus_gate", FILE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def policy(mode="block", routes=None):
    if routes is None:
        routes = {"/api": {"max_fp": 0, "max_fn": 0, "max_fp_rate": 0.0,
                           "max_fn_rate": 0.0, "min_benign": 1, "min_malicious": 1}}
    return {"schemaVersion": 3, "mode": mode, "routes": routes,
            "approvedRulesetSha256": "A" * 64,
            "corpusManifestSha256": "B" * 64,
            "gatewaySha": "c" * 40, "platform": "linux"}


def row(name, truth, observed, *, route="/api", mode="block",
        decision=None, audit=None):
    if decision is None:
        decision = observed == "block"
    return {"case_id": name, "route": route, "expected": truth,
            "observed": observed, "would_block": str(decision).lower(),
            "mode": mode, "severity": "high",
            "audit_sha256": audit or hashlib.sha256(
                (route + ":" + name).encode("ascii")).hexdigest().upper()}


class CorpusV3Tests(unittest.TestCase):
    def good(self, mode="block"):
        return [row("benign", "benign", "allow", mode=mode),
                row("malicious", "malicious", "allow" if mode == "detect" else "block",
                    mode=mode, decision=True)]

    def test_enforcement_v3_with_preapproved_per_route_rates(self):
        result = gate.evaluate(self.good(), policy())
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["schemaVersion"], 3)
        self.assertEqual(result["rates"]["/api"]["fn_rate"], 0.0)
        self.assertEqual(result["rates"]["/api"]["fp_rate"], 0.0)
        self.assertEqual(result["pinnedEvidence"]["approvedRulesetSha256"], "A" * 64)

    def test_detect_mode_preserves_would_block_true_positive(self):
        report = gate.evaluate(self.good("detect"), policy("detect"))
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["routes"]["/api"], {"tp": 1, "tn": 1, "fp": 0, "fn": 0})
        self.assertEqual(report["rates"]["/api"]["fn_rate"], 0.0)

    def test_rate_gate_blocks_weak_route_even_if_count_gate_passes(self):
        limits = {"max_fp": 1, "max_fn": 1, "max_fp_rate": .1,
                  "max_fn_rate": .1, "min_benign": 2, "min_malicious": 2}
        cases = [
            row("one", "benign", "block"),
            row("two", "benign", "allow"),
            row("three", "malicious", "allow", decision=False),
            row("four", "malicious", "block")]
        report = gate.evaluate(cases, policy(routes={"/api": limits}))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["rates"]["/api"]["fp_rate"], .5)
        self.assertEqual(report["rates"]["/api"]["fn_rate"], .5)
        self.assertTrue(any("rate" in x for x in report["failures"]))

    def test_preapproved_per_route_minimum_is_not_cli_overridable(self):
        v = policy()
        v["routes"]["/api"]["min_benign"] = 20
        report = gate.evaluate(self.good(), v)
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("insufficient", " ".join(report["failures"]))

    def test_untested_approved_route_never_passes(self):
        v = policy()
        v["routes"]["/critical"] = dict(v["routes"]["/api"])
        with self.assertRaisesRegex(ValueError, "untested approved route"):
            gate.evaluate(self.good(), v)

    def test_duplicate_native_audit_reuse_across_different_cases_rejected(self):
        cases = self.good()
        cases[1]["audit_sha256"] = cases[0]["audit_sha256"]
        with self.assertRaisesRegex(ValueError, "reused native WAF"):
            gate.evaluate(cases, policy())

    def test_case_identity_or_native_hash_alias_rejected(self):
        cases = self.good()
        cases[1]["audit_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "native WAF"):
            gate.evaluate(cases, policy())
        cases = self.good()
        cases[1]["case_id"] = "case with spaces"
        with self.assertRaisesRegex(ValueError, "case identity"):
            gate.evaluate(cases, policy())

    def test_policy_route_aliases_and_invalid_approval_limits_rejected(self):
        for route in ("/api//admin", "/api/../admin", "/api/%61",
                      "/api;admin", "/api/:route", "/ümlaut"):
            with self.subTest(route=route):
                v = policy(routes={route: dict(policy()["routes"]["/api"])})
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    gate.evaluate([row("x", "benign", "allow", route=route)], v)
        for value in (math.nan, math.inf, -1, 1.1, True):
            v = policy()
            v["routes"]["/api"]["max_fp_rate"] = value
            with self.subTest(rate=value), self.assertRaisesRegex(ValueError, "rates"):
                gate.evaluate(self.good(), v)

    def test_blocked_http_without_waf_rule_verdict_not_accepted(self):
        cases = self.good()
        cases[1]["would_block"] = "false"
        with self.assertRaisesRegex(ValueError, "enforcement disagrees"):
            gate.evaluate(cases, policy())

    def test_v3_cli_checks_private_report_without_printing_route_names(self):
        with tempfile.TemporaryDirectory(prefix="waf-rate-v3-") as temp:
            root = Path(temp)
            route = "/private-customer-name"
            approved = policy(routes={route: dict(policy()["routes"]["/api"])})
            rows = [row("one", "benign", "allow", route=route),
                    row("two", "malicious", "block", route=route)]
            approved_file = root / "preapproved-policy.json"
            csv_file = root / "native-correlated.csv"
            output = root / "private-report.json"
            approved_file.write_text(json.dumps(approved), encoding="utf-8")
            with csv_file.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=sorted(gate.V3_FIELDS))
                writer.writeheader()
                writer.writerows(rows)
            done = subprocess.run([sys.executable, str(FILE), "--corpus",
                                   str(csv_file), "--policy", str(approved_file),
                                   "--out", str(output)], capture_output=True, text=True,
                                  timeout=15, check=False)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertNotIn(route, done.stdout + done.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "PASS")
            self.assertEqual(report["schemaVersion"], 3)
            self.assertEqual(report["rates"][route]["benign"], 1)
            self.assertEqual(report["rates"][route]["malicious"], 1)


if __name__ == "__main__":
    unittest.main()
