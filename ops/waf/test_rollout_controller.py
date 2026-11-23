#!/usr/bin/env python3
"""Scoped signed WAF mode controller transaction and failure injection tests."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import rollout_controller as subject


class FakeWaf:
    def __init__(self, mode="detect"):
        self.mode = mode
        self.image = "sha256:" + "a" * 64
        self.requests = []
        self.fail_apply = False
        self.fail_smoke = None
        self.swap_image = False
        self.rollback_fails = False

    def inspect(self):
        return {"mode": self.mode, "imageId": self.image}

    def image_and_config(self, mode):
        self.requests.append(("verify", mode))
        if mode not in subject.MODES:
            raise ValueError("unapproved")
        return self.image

    def smoke(self, mode):
        self.requests.append(("smoke", mode))
        if self.fail_smoke == mode:
            raise ValueError("synthetic local failure")

    def apply(self, mode):
        self.requests.append(("apply", mode))
        if self.fail_apply or (self.rollback_fails and mode == "detect"):
            raise ValueError("synthetic WAF restart failed")
        self.mode = mode
        if self.swap_image and mode == "block":
            self.image = "sha256:" + "b" * 64


class RolloutSafetyTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory()
        self.addCleanup(self.root.cleanup)
        self.output = Path(self.root.name) / "intent.json"
        os.chmod(self.root.name, 0o700)
        self.hash = "A" * 64

    def read(self):
        return json.loads(self.output.read_text(encoding="utf-8"))

    def test_approved_single_node_apply_creates_private_nonoverwriting_receipt(self):
        gateway = FakeWaf()
        self.assertEqual(subject.transaction(gateway, "block", 31, self.output,
                                              self.hash), "applied")
        self.assertEqual(gateway.mode, "block")
        self.assertEqual(gateway.requests, [("verify", "block"),
            ("smoke", "detect"), ("apply", "block"), ("smoke", "block")])
        result = self.read()
        self.assertEqual(result["result"], "applied")
        self.assertFalse(result["fleetAtomic"])
        self.assertFalse(result["trustedRevisionFloorAdvanced"])
        self.assertFalse(result["rollbackVerified"])
        self.assertEqual(self.output.stat().st_mode & 0o077, 0)
        with self.assertRaises(ValueError):
            subject.transaction(gateway, "block", 31, self.output, self.hash)

    def test_smoke_failure_rolls_back_to_original_mode_and_records_it(self):
        gateway = FakeWaf()
        gateway.fail_smoke = "block"
        with self.assertRaisesRegex(ValueError, "rollout unsuccessful"):
            subject.transaction(gateway, "block", 32, self.output, self.hash)
        self.assertEqual(gateway.mode, "detect")
        result = self.read()
        self.assertEqual(result["result"], "rolled_back")
        self.assertTrue(result["rollbackVerified"])
        self.assertIn(("apply", "detect"), gateway.requests)

    def test_changed_container_image_is_rejected_and_attempts_recovery(self):
        gateway = FakeWaf()
        gateway.swap_image = True
        with self.assertRaises(ValueError):
            subject.transaction(gateway, "block", 33, self.output, self.hash)
        self.assertEqual(self.read()["result"], "rollback_failed")

    def test_failed_rollback_is_never_reported_as_success(self):
        gateway = FakeWaf()
        gateway.fail_smoke = "block"
        gateway.rollback_fails = True
        with self.assertRaises(ValueError):
            subject.transaction(gateway, "block", 34, self.output, self.hash)
        self.assertEqual(self.read()["result"], "rollback_failed")
        self.assertFalse(self.read()["rollbackVerified"])

    def test_bad_image_revision_digest_or_replayed_mode_do_not_mutate(self):
        gateway = FakeWaf(mode="block")
        for requested, rev, digest in (
                ("block", 35, self.hash), ("Off", 35, self.hash),
                ("detect", 0, self.hash), ("detect", 35, "bad")):
            with self.subTest(mode=requested, revision=rev), self.assertRaises(ValueError):
                subject.transaction(gateway, requested, rev, self.output, digest)
        self.assertFalse(self.output.exists())

    def test_existing_receipt_cannot_be_overwritten(self):
        self.output.write_text("original", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            subject.receipt(self.output, {"schemaVersion": 1})
        self.assertEqual(self.output.read_text(), "original")

    def test_external_output_symlink_and_permissive_directory_refused(self):
        self.output.symlink_to(Path(self.root.name) / "elsewhere")
        with self.assertRaises(FileExistsError):
            subject.receipt(self.output, {"schemaVersion": 1})
        self.output.unlink()
        os.chmod(self.root.name, 0o750)
        with self.assertRaises(ValueError):
            subject.receipt(self.output, {"schemaVersion": 1})

    def test_operator_lock_refuses_symlinked_lock_and_simultaneous_agent(self):
        with subject.operator_lock(Path(self.root.name)):
            with self.assertRaises(OSError):
                with subject.operator_lock(Path(self.root.name)):
                    pass
        lock = Path(self.root.name) / ".signed-waf-rollout.lock"
        lock.unlink()
        lock.symlink_to(self.output)
        with self.assertRaises(OSError):
            with subject.operator_lock(Path(self.root.name)):
                pass

    def test_compose_adapter_requires_pinned_image_and_literal_loopback(self):
        manifest = Path(self.root.name) / "compose.yml"
        manifest.write_text("services: {}", encoding="ascii")
        image = "owasp/modsecurity-crs@sha256:" + "a" * 64
        valid = subject.DockerComposeProvider(manifest, image,
                         "http://127.0.0.1:18888/")
        self.assertEqual(valid.health, "http://127.0.0.1:18888/")
        for url in ("http://localhost:18888/", "https://127.0.0.1:18888/",
                    "http://127.0.0.1:18888/admin", "http://127.0.0.1:18888/?x=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                subject.DockerComposeProvider(manifest, image, url)
        with self.assertRaises(ValueError):
            subject.DockerComposeProvider(manifest, "owasp/modsecurity-crs:latest",
                                          "http://127.0.0.1:18888/")

    def test_docker_compose_inspection_rejects_origin_bypass_or_off_mode(self):
        manifest = Path(self.root.name) / "compose.yml"
        manifest.write_text("services: {}", encoding="ascii")
        image = "owasp/modsecurity-crs@sha256:" + "a" * 64
        def fake_runner(argv, env=None):
            if argv[1] == "compose":
                return json.dumps({"services": {
                    "waf": {"image": image,
                            "environment": {"MODSEC_RULE_ENGINE": env["WAF_MODE"]}},
                    "protected-app": {"ports": [{"published": "8000"}]}
                }})
            return "sha256:" + "a" * 64
        provider = subject.DockerComposeProvider(manifest, image,
                      "http://127.0.0.1:18888/", runner=fake_runner)
        with self.assertRaisesRegex(ValueError, "bypass"):
            provider.image_and_config("block")

    def test_missing_receipt_after_apply_requires_rollback(self):
        gateway = FakeWaf()
        with mock.patch.object(subject, "receipt", side_effect=OSError("no storage")):
            with self.assertRaises((OSError, ValueError)):
                subject.transaction(gateway, "block", 42, self.output, self.hash)
        self.assertEqual(gateway.mode, "detect",
                         "A missing audit receipt must never leave an applied mode")


if __name__ == "__main__":
    unittest.main()
