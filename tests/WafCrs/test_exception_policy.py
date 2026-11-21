#!/usr/bin/env python3
"""No Docker required: negative governance tests for the disposable WAF carve-out."""
import datetime as dt
import json
from pathlib import Path
import tempfile
import unittest

from exception_policy import COMPOSE, POLICY, RULE, validate

FIXED_NOW = dt.datetime(2026, 11, 22, tzinfo=dt.timezone.utc)


class WafLabPolicyTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="waf-lab-policy-")
        self.addCleanup(self.scratch.cleanup)
        root = Path(self.scratch.name)
        self.policy = root / "exception-policy.lab.json"
        self.rule = root / "rule.conf"
        self.compose = root / "compose.yml"
        for path, original in ((self.policy, POLICY), (self.rule, RULE),
                               (self.compose, COMPOSE)):
            path.write_bytes(original.read_bytes())

    def check(self):
        return validate(self.policy, self.rule, self.compose, FIXED_NOW)

    def update(self, **changes):
        data = json.loads(self.policy.read_text(encoding="utf-8"))
        data.update(changes)
        self.policy.write_text(json.dumps(data), encoding="utf-8")

    def test_valid_scoped_fixture(self):
        result = self.check()
        self.assertEqual(result["scope"], "disposable-lab-only")
        self.assertFalse(result["productionApproved"])

    def test_expired_or_not_yet_active(self):
        for changes in ({"expiresAtUtc": "2026-11-21T00:00:00Z"},
                        {"issuedAtUtc": "2026-11-23T00:00:00Z"}):
            self.update(**changes)
            with self.assertRaises(ValueError):
                self.check()
            self.policy.write_bytes(POLICY.read_bytes())

    def test_rejects_long_lived_exception(self):
        self.update(expiresAtUtc="2027-12-31T00:00:00Z")
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_production_marking_or_wrong_owner(self):
        for changes in ({"approvedForProduction": True},
                        {"owner": "any-operator"}):
            self.update(**changes)
            with self.assertRaises(ValueError):
                self.check()
            self.policy.write_bytes(POLICY.read_bytes())

    def test_rejects_widened_path_method_and_rule_id(self):
        for changes in ({"path": "/*"}, {"httpMethod": "GET"},
                        {"removedRuleId": 920350}):
            self.update(**changes)
            with self.assertRaises(ValueError):
                self.check()
            self.policy.write_bytes(POLICY.read_bytes())

    def test_rejects_aliased_duplicate_json(self):
        original = self.policy.read_text(encoding="utf-8")
        self.policy.write_text(original.replace('"schemaVersion": 1,',
            '"schemaVersion": 1, "SCHEMAVERSION": 1,'))
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_modified_or_broad_waf_rule(self):
        original = self.rule.read_text(encoding="utf-8")
        self.rule.write_text(original.replace("@streq /acceptance", "@rx .*"),
                             encoding="utf-8")
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_disabled_or_rw_rule_mount(self):
        compose = self.compose.read_text(encoding="utf-8")
        self.compose.write_text(compose.replace(
            "REQUEST-900-GATEWAYCORE-LAB-PKIX.conf:ro",
            "REQUEST-900-GATEWAYCORE-LAB-PKIX.conf:rw"), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_missing_or_unknown_fields(self):
        data = json.loads(self.policy.read_text(encoding="utf-8"))
        data.pop("owner")
        self.policy.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.check()
        data["owner"] = "gatewaycore-ci-waf-fixture"
        data["unknown"] = True
        self.policy.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.check()

    def test_rejects_waf_engine_policy_and_anomaly_changes(self):
        original = self.compose.read_text(encoding="utf-8")
        changes = (
            ('MODSEC_RULE_ENGINE: "${WAF_MODE:-On}"',
             'MODSEC_RULE_ENGINE: "Off"'),
            ('ANOMALY_INBOUND: "5"', 'ANOMALY_INBOUND: "100"'),
            ('MODSEC_REQ_BODY_LIMIT_ACTION: "Reject"',
             'MODSEC_REQ_BODY_LIMIT_ACTION: "ProcessPartial"'),
            ('MODSEC_AUDIT_ENGINE: "On"', 'MODSEC_AUDIT_ENGINE: "Off"'),
        )
        for current, replacement in changes:
            with self.subTest(current=current):
                self.assertIn(current, original)
                self.compose.write_text(original.replace(current, replacement),
                                        encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "WAF lab engine"):
                    self.check()

    def test_rejects_extra_rule_mount_or_environment_override(self):
        original = self.compose.read_text(encoding="utf-8")
        changes = (
            ('    environment:\n',
             '    environment:\n      MODSEC_RULE_ENGINE: "Off"\n'),
            ('    volumes:\n      # Loaded before CRS rule 920420.',
             '    volumes:\n      - ./override.conf:/etc/modsecurity.d/override.conf:ro\n'
             '      # Loaded before CRS rule 920420.'),
            ('    depends_on:\n      - protected-app',
             '    env_file: ./untrusted.env\n    depends_on:\n      - protected-app'),
        )
        for current, replacement in changes:
            with self.subTest(replacement=replacement):
                self.assertIn(current, original)
                self.compose.write_text(original.replace(current, replacement),
                                        encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "WAF lab engine"):
                    self.check()

    def test_rejects_public_waf_listener_or_published_backend(self):
        original = self.compose.read_text(encoding="utf-8")
        changes = (
            ('127.0.0.1:18888:8080', '0.0.0.0:18888:8080',
             "WAF lab engine"),
            ('    expose: ["8000"]',
             '    expose: ["8000"]\n    ports: ["8000:8000"]',
             "backend isolation"),
        )
        for current, replacement, error in changes:
            with self.subTest(replacement=replacement):
                self.assertIn(current, original)
                self.compose.write_text(original.replace(current, replacement),
                                        encoding="utf-8")
                with self.assertRaisesRegex(ValueError, error):
                    self.check()


if __name__ == "__main__":
    unittest.main()
