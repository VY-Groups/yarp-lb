#!/usr/bin/env python3
"""Deterministic privacy-safe native CRS transaction binding regression tests."""
import json
from pathlib import Path
import tempfile
import unittest

import correlate_native_audit as gate


def transcript(name, family, tx, prefixed=True, with_case=True, phase="detection"):
    marker = (f"X-GatewayCore-CI-Case: {phase}-{name}\n" if with_case else "")
    lines = [
        f"--{tx}-A--",
        "synthetic-native-WAF-test",
        f"--{tx}-B--",
        "GET /?q=synthetic HTTP/1.1",
        "Host: localhost",
        marker.rstrip(),
        f"--{tx}-H--",
        "Message: Warning. Pattern match detected [id \"" +
        family + "100\"] [msg \"Synthetic CRS test\"]",
        f"--{tx}-Z--",
    ]
    return "\n".join("waf-1  | " + line if prefixed else line
                     for line in lines if line) + "\n"


def fixture():
    return "".join(transcript(name, family, "aabbcc" + str(i) + "dd")
                   for i, (name, family) in
                   enumerate(gate.CASE_FAMILIES.items(), 1))


class NativeAuditCorrelationTests(unittest.TestCase):
    def test_each_case_rule_matches_same_audit_transaction(self):
        self.assertEqual(gate.correlate(fixture()), gate.CASE_FAMILIES)
        self.assertEqual(gate.correlate(fixture().replace("waf-1  | ", "")),
                         gate.CASE_FAMILIES)

    def test_rule_for_other_case_is_not_global_positive(self):
        broken = fixture().replace(
            "Message: Warning. Pattern match detected [id \"941100\"]",
            "Message: Warning. Pattern match detected [id \"942100\"]")
        with self.assertRaisesRegex(ValueError, "case-specific"):
            gate.correlate(broken)

    def test_unattributed_or_duplicate_cases_fail_closed(self):
        with self.assertRaises(ValueError):
            gate.correlate(fixture() + transcript("xss", "941", "11223344"))
        with self.assertRaises(ValueError):
            gate.correlate(fixture().replace("X-GatewayCore-CI-Case: detection-xss", ""))
        with self.assertRaises(ValueError):
            gate.correlate(fixture().replace(
                "X-GatewayCore-CI-Case: detection-sqli",
                "X-GatewayCore-CI-Case: detection-xss"))

    def test_header_and_rules_must_share_complete_transaction(self):
        broken = fixture().replace("--aabbcc1dd-Z--", "--aabbcc1dd-Q--")
        with self.assertRaises(ValueError):
            gate.correlate(broken)
        only_global_rule = fixture() + transcript("xss", "941", "22222222",
                                                  with_case=False)
        self.assertEqual(gate.correlate(only_global_rule), gate.CASE_FAMILIES)

    def test_report_is_redacted_and_requires_all_origin_200(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "audit.log"
            audit.write_text(fixture(), encoding="utf-8")
            for case in gate.CASE_FAMILIES:
                (root / ("detection-" + case + "-status.txt")).write_text(
                    "200\n", encoding="ascii")
            report = gate.build_report(audit, root)
            self.assertEqual(report["schemaVersion"], 2)
            self.assertEqual(len(report["attackClasses"]), 3)
            serialized = json.dumps(report)
            self.assertNotIn("aabbcc", serialized)
            self.assertNotIn("GET /", serialized)
            self.assertNotIn("Host: localhost", serialized)
            (root / "detection-sqli-status.txt").write_text("403", encoding="ascii")
            with self.assertRaises(ValueError):
                gate.build_report(audit, root)

    def test_blocking_http_requires_matching_native_crs_transaction(self):
        names = gate.BLOCKING_CASE_FAMILIES
        transcript_text = "".join(
            transcript(name, family, "bbccdd" + str(i) + "ee", phase="blocking")
            for i, (name, family) in enumerate(names.items(), 1))
        self.assertEqual(gate.correlate(transcript_text, "blocking"), names)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "blocking.log"
            audit.write_text(transcript_text, encoding="utf-8")
            for name in names:
                (root / (name + "-http-status.txt")).write_text("403\n", encoding="ascii")
            report = gate.build_report(audit, root, "blocking")
            self.assertEqual(set(report["attackClasses"]), set(names))
            self.assertTrue(all(not case["forwarded"]
                                for case in report["attackClasses"].values()))
            (root / "xss-http-status.txt").write_text("200\n", encoding="ascii")
            with self.assertRaisesRegex(ValueError, "disagrees"):
                gate.build_report(audit, root, "blocking")
            (root / "xss-http-status.txt").write_text("403\n", encoding="ascii")
            audit.write_text(transcript_text.replace(
                'Message: Warning. Pattern match detected [id "941100"]',
                'Message: Warning. Pattern match detected [id "942100"]', 1),
                encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "case-specific"):
                gate.build_report(audit, root, "blocking")
            audit.write_text(transcript_text + transcript(
                "xss", "941", "11223344", phase="blocking"), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "case-specific"):
                gate.build_report(audit, root, "blocking")

    def test_malformed_or_oversized_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            audit = root / "audit.log"
            audit.write_bytes(b"x" * (gate.MAX_AUDIT_BYTES + 1))
            with self.assertRaises(ValueError):
                gate.build_report(audit, root)


if __name__ == "__main__":
    unittest.main()
