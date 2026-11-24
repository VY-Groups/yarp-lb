"""Synthetic signed exception renderer acceptance, with real P-256 verification."""
import copy
import datetime as dt
import os
from pathlib import Path
import stat
import tempfile
import unittest

import render_signed_exceptions as renderer
import test_verify_signed_policy as fixtures

NOW = fixtures.NOW


class SignedExceptionRendererTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SignedPolicyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = Path(self.fixture.temp.name)
        self.private = self.root / "private-render"
        self.private.mkdir(mode=0o700)
        self.output = self.private / "approved-0007.conf"

    def call(self):
        return renderer.verify_and_render(
            self.fixture.policy_file, self.fixture.approvals, self.fixture.keys,
            self.fixture.min_file, fixtures.RULESET, "detect", self.output,
            now=NOW)

    def test_two_real_p256_approvals_allow_only_private_candidate(self):
        revision, digest = self.call()
        self.assertEqual(revision, 7)
        self.assertRegex(digest, r"^[A-F0-9]{64}$")
        text = self.output.read_text(encoding="ascii")
        self.assertIn('REQUEST_URI_RAW "@streq /cert"', text)
        self.assertIn('REQUEST_METHOD "@streq POST"', text)
        self.assertIn('REQUEST_HEADERS:Content-Type "@streq application/pkix-cert"', text)
        self.assertIn("ctl:ruleRemoveById=920420", text)
        self.assertIn("TIME_EPOCH", text)
        self.assertIn("until=2026-11-30T09:00:00Z", text)
        self.assertNotIn("SecRuleRemoveById", text)
        self.assertNotIn("ruleRemoveById=941", text)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o600)
        # A second request must never overwrite an existing approved candidate.
        with self.assertRaises(FileExistsError):
            self.call()
        self.assertEqual(self.output.read_text(encoding="ascii"), text)

    def test_invalid_signer_fails_before_any_output(self):
        self.fixture.policy["exceptions"][0]["path"] = "/new-path"
        self.fixture.policy_file.write_text(
            __import__("json").dumps(self.fixture.policy), encoding="utf-8")
        with self.assertRaises(ValueError):
            self.call()
        self.assertFalse(self.output.exists())

    def test_unsafe_scope_and_duplicate_effective_scope_rejected_even_if_signed(self):
        for edit in ({"ruleId": 941100}, {"path": "/"},
                     {"path": "/cert\"bad"}, {"path": "/cert;param=1"},
                     {"path": "/cert/%63"}, {"path": "/cert:alias"},
                     {"contentType": "application/json"}, {"httpMethod": "GET"}):
            original = copy.deepcopy(self.fixture.policy)
            self.fixture.policy["exceptions"][0].update(edit)
            self.fixture.sign()
            with self.subTest(edit=edit), self.assertRaises(ValueError):
                self.call()
            self.assertFalse(self.output.exists())
            self.fixture.policy = original
        duplicate = dict(self.fixture.policy["exceptions"][0])
        duplicate["exceptionId"] = "second-signer-approved-id"
        self.fixture.policy["exceptions"].append(duplicate)
        self.fixture.sign()
        with self.assertRaisesRegex(ValueError, "duplicate effective"):
            self.call()
        self.assertFalse(self.output.exists())

    def test_request_time_expiry_and_future_start_fail_closed(self):
        valid = copy.deepcopy(self.fixture.policy)
        for observed in (dt.datetime(2026, 11, 21, tzinfo=dt.timezone.utc),
                         dt.datetime(2026, 11, 30, 9, tzinfo=dt.timezone.utc)):
            with self.subTest(time=str(observed)), self.assertRaises(ValueError):
                renderer.render(valid, observed)
        self.assertIn(b"@lt 179603", renderer.render(valid, NOW))

    def test_private_directory_and_link_or_existing_output_are_rejected(self):
        self.private.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "owner-only"):
            self.call()
        self.private.chmod(0o700)
        sentinel = self.private / "preserve.txt"
        sentinel.write_text("unchanged", encoding="ascii")
        try:
            self.output.symlink_to(sentinel)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks unavailable")
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual(sentinel.read_text(), "unchanged")


if __name__ == "__main__":
    unittest.main()
