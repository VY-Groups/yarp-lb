"""Per-route WAF audit-bound confusion evidence positive/negative acceptance."""
import csv
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).with_name("assess_corpus_evidence.py")
spec = importlib.util.spec_from_file_location("waf_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest().upper()


def case(route, name, expected, observed, mode="block", action=None, audit=None):
    if action is None:
        action = "block" if observed == "blocked" else "pass"
    return (route, name, expected, observed, mode,
            action, audit if audit is not None else digest(route + ":" + name))


class EvidenceGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "corpus.csv"
        self.manifest = Path(self.tmp.name) / "approved-routes.json"
        self.routes(["/a"])

    def routes(self, routes):
        obj = {"schemaVersion": 1, "approvedRulesetSha256": "A" * 64,
               "corpusManifestSha256": "B" * 64, "gatewaySha": "c" * 40,
               "platform": "linux", "evidenceBinding": "native-waf-audit-per-request",
               "routes": routes}
        self.manifest.write_text(json.dumps(obj), encoding="utf-8")

    def write(self, rows):
        with self.path.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(gate.FIELDS)
            writer.writerows(rows)

    def run_gate(self, max_fp=0, max_fn=0, benign=1, malicious=1):
        return gate.assess(self.path, max_fp, max_fn, benign, malicious,
                           self.manifest)

    def test_exact_per_route_pass_with_matching_waf_verdicts(self):
        self.routes(["/a", "/b"])
        self.write([case("/a", "a1", "benign", "allowed"),
                    case("/a", "a2", "malicious", "blocked"),
                    case("/b", "b1", "benign", "allowed"),
                    case("/b", "b2", "malicious", "blocked")])
        result = self.run_gate()
        self.assertTrue(result["pass"])
        self.assertEqual(result["routes"]["/a"]["tp"], 1)
        self.assertRegex(result["evidenceSha256"], r"^[A-F0-9]{64}$")
        self.assertNotIn("a1", json.dumps(result))

    def test_false_positive_and_negative_fail(self):
        self.write([case("/a", "a1", "benign", "blocked"),
                    case("/a", "a2", "malicious", "allowed")])
        result = self.run_gate()
        self.assertFalse(result["pass"])
        self.assertEqual(result["routes"]["/a"]["fp"], 1)
        self.assertEqual(result["routes"]["/a"]["fn"], 1)

    def test_aggregate_success_cannot_mask_weak_route(self):
        self.routes(["/good", "/bad"])
        self.write([case("/good", "a", "benign", "allowed"),
                    case("/good", "b", "malicious", "blocked"),
                    case("/bad", "c", "benign", "blocked"),
                    case("/bad", "d", "malicious", "blocked")])
        self.assertFalse(self.run_gate(.1, .1)["pass"])

    def test_missing_or_surprise_route_does_not_pass(self):
        self.routes(["/a", "/important"])
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        with self.assertRaisesRegex(ValueError, "omit or exceed"):
            self.run_gate()
        self.routes(["/a"])
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked"),
                    case("/surprise", "c", "malicious", "blocked")])
        with self.assertRaisesRegex(ValueError, "omit or exceed"):
            self.run_gate()

    def test_empty_class_and_insufficient_minimum_fail(self):
        self.write([case("/a", "a", "benign", "allowed")])
        self.assertFalse(self.run_gate()["pass"])
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        self.assertFalse(self.run_gate(0, 0, 2, 2)["pass"])

    def test_shadow_mode_and_unmatched_waf_action_rejected(self):
        self.write([case("/a", "a", "benign", "allowed", "detect")])
        with self.assertRaisesRegex(ValueError, "enforcement"):
            self.run_gate()
        self.write([case("/a", "a", "malicious", "blocked", action="pass")])
        with self.assertRaisesRegex(ValueError, "HTTP status"):
            self.run_gate()
        self.write([case("/a", "a", "malicious", "allowed", action="block")])
        with self.assertRaisesRegex(ValueError, "HTTP status"):
            self.run_gate()

    def test_reused_native_audit_digest_or_duplicate_case_rejected(self):
        reused = digest("one-shared-audit")
        self.write([case("/a", "a", "benign", "allowed", audit=reused),
                    case("/a", "b", "malicious", "blocked", audit=reused)])
        with self.assertRaisesRegex(ValueError, "reused"):
            self.run_gate()
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "a", "malicious", "blocked")])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_gate()

    def test_ambiguous_route_and_case_spellings_rejected(self):
        for bad in ("/api//x", "/api/../admin", "/api/%61",
                    "/api;parameter", "/api/:route", "/api?q=x",
                    "/api/./x", " //a", "/api\\admin", "/ümlaut"):
            with self.subTest(route=bad):
                self.write([case(bad, "a", "malicious", "blocked")])
                with self.assertRaisesRegex(ValueError, "noncanonical"):
                    self.run_gate()
        self.write([case("/a", "bad id", "malicious", "blocked")])
        with self.assertRaisesRegex(ValueError, "case"):
            self.run_gate()

    def test_missing_audit_digest_invalid_or_bom_provenance(self):
        self.write([case("/a", "a", "malicious", "blocked", audit="not-a-digest")])
        with self.assertRaisesRegex(ValueError, "digest"):
            self.run_gate()
        self.write([case("/a", "a", "malicious", "blocked", audit="a" * 64)])
        with self.assertRaisesRegex(ValueError, "digest"):
            self.run_gate()

    def test_invalid_threshold_and_nonfinite_rate_rejected(self):
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        for x in (-1.0, 1.1, math.nan, math.inf, -math.inf, True):
            with self.subTest(rate=x), self.assertRaisesRegex(ValueError, "rates"):
                self.run_gate(x, 0)
        with self.assertRaises(ValueError):
            self.run_gate(0, 0, True, 1)

    def test_manifest_rejects_ambiguous_duplicate_or_missing_routes(self):
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        for invalid in (["/a", "/a"], ["/a", "/a/../admin"], [],
                        ["/a", "/api//admin"]):
            with self.subTest(routes=invalid):
                self.routes(invalid)
                with self.assertRaises(ValueError):
                    self.run_gate()
        self.routes(["/a"])
        malformed = {"schemaVersion": 1}
        self.manifest.write_text(json.dumps(malformed), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_unexpected_csv_column_or_duplicate_header_rejected(self):
        self.path.write_text("route,case_id,expected,observed,mode,waf_action,audit_sha256,secret\n",
                             encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "header"):
            self.run_gate()
        self.path.write_text("route,route,expected,observed,mode,waf_action,audit_sha256\n",
                             encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "header"):
            self.run_gate()

    def test_symlink_or_hardlink_evidence_rejected(self):
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        original = Path(self.tmp.name) / "real.csv"
        self.path.rename(original)
        try:
            self.path.symlink_to(original)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("Windows symlink creation is not permitted on this runner")
        with self.assertRaisesRegex(ValueError, "single-linked"):
            self.run_gate()
        self.path.unlink()
        os.link(original, self.path)
        with self.assertRaisesRegex(ValueError, "single-linked"):
            self.run_gate()

    def test_empty_truncated_or_oversized_evidence_rejected(self):
        self.path.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.run_gate()
        self.path.write_bytes(b"x" * (gate.MAX_BYTES + 1))
        with self.assertRaises(ValueError):
            self.run_gate()

    def test_manifest_duplicate_json_keys_rejected(self):
        self.write([case("/a", "a", "benign", "allowed"),
                    case("/a", "b", "malicious", "blocked")])
        text = self.manifest.read_text(encoding="utf-8")
        self.manifest.write_text(text.replace('"schemaVersion": 1',
                            '"schemaVersion": 1, "schemaVersion": 1'), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.run_gate()


if __name__ == "__main__":
    unittest.main()
