"""Failure-injected two-node WAF compensation and fencing contracts."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import two_node_transaction as fleet

DIGEST = "A" * 64
POLICY = "B" * 64
IMAGE = "sha256:" + "d" * 64


class Node:
    def __init__(self, ident, mode="detect"):
        self.ident = ident
        self.mode = mode
        self.image = IMAGE
        self.ruleset = DIGEST
        self.calls = []
        self.fail_apply_to = None
        self.fail_after_mutating_to = None
        self.fail_smoke_on = None
        self.bad_image_on_target = False
        self.wrong_rules_on_target = False

    def inspect(self):
        return {"mode": self.mode, "imageId": self.image}

    def image_and_config(self, mode):
        self.calls.append(("config", mode))
        return self.image

    def observed_rule_digest(self):
        return self.ruleset

    def smoke(self, mode):
        self.calls.append(("smoke", mode))
        if mode == self.fail_smoke_on:
            raise ValueError("injected synthetic smoke failure")

    def apply(self, mode):
        self.calls.append(("apply", mode))
        if mode == self.fail_apply_to:
            raise ValueError("synthetic failure before apply")
        self.mode = mode
        if mode == self.fail_after_mutating_to:
            raise ValueError("synthetic failure after apply")
        if mode == "block" and self.bad_image_on_target:
            self.image = "sha256:" + "e" * 64
        if mode == "block" and self.wrong_rules_on_target:
            self.ruleset = "C" * 64


class Fence:
    def __init__(self):
        self.calls = []
        self.expire_phase = None

    def assert_current(self, names, rev, digest, phase):
        self.calls.append((names, rev, digest, phase))
        return phase != self.expire_phase


class FleetTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        os.chmod(self.folder, 0o700)
        self.output = self.folder / "fleet-rev17.json"
        self.nodes = {"waf-b": Node("b"), "waf-a": Node("a")}
        self.fence = Fence()

    def call(self, **changes):
        args = dict(nodes=self.nodes, target="block", revision=17,
                    policy_digest=POLICY, ruleset_digest=DIGEST,
                    output=self.output, fence=self.fence)
        args.update(changes)
        return fleet.coordinate(**args)

    def receipt(self, name=None):
        location = self.output if name is None else self.folder / name
        return json.loads(location.read_text(encoding="utf-8"))

    def test_success_requires_two_checked_nodes_and_durable_journal(self):
        self.assertEqual(self.call(), "applied-uncommitted")
        self.assertEqual({n.mode for n in self.nodes.values()}, {"block"})
        self.assertEqual(self.receipt()["result"], "applied-uncommitted")
        self.assertFalse(self.receipt()["fleetAtomic"])
        self.assertFalse(self.receipt()["trustedRevisionFloorAdvanced"])
        self.assertEqual(self.receipt()["nodesVerified"], ["waf-a", "waf-b"])
        self.assertEqual(
            self.receipt(".fleet-rev17.json.intent")["state"],
            "intent-fsynced-mutation-may-start")
        self.assertEqual(self.output.stat().st_mode & 0o077, 0)
        self.assertEqual(
            (self.folder / ".fleet-rev17.json.intent").stat().st_mode & 0o077, 0)
        self.assertIn(("apply", "block"), self.nodes["waf-a"].calls)
        self.assertIn(("apply", "block"), self.nodes["waf-b"].calls)
        self.assertEqual(self.fence.calls[-1][-1], "before-receipt")

    def test_partial_second_node_failure_restores_both(self):
        self.nodes["waf-b"].fail_apply_to = "block"
        with self.assertRaisesRegex(ValueError, "transaction failed"):
            self.call()
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})
        self.assertFalse(self.output.exists())
        audit = self.receipt(".fleet-rev17.json.failure")
        self.assertEqual(audit["result"], "rolled-back")
        self.assertEqual(audit["rollbackVerified"], {"waf-a": True, "waf-b": True})
        self.assertIn(("apply", "detect"), self.nodes["waf-a"].calls)

    def test_timeout_after_remote_mutation_is_still_compensated(self):
        self.nodes["waf-b"].fail_after_mutating_to = "block"
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})
        self.assertEqual(self.receipt(".fleet-rev17.json.failure")["result"],
                         "rolled-back")

    def test_rollback_failure_never_returns_success(self):
        self.nodes["waf-b"].fail_after_mutating_to = "block"
        self.nodes["waf-a"].fail_apply_to = "detect"
        with self.assertRaises(ValueError):
            self.call()
        audit = self.receipt(".fleet-rev17.json.failure")
        self.assertEqual(audit["result"], "rollback-failed")
        self.assertFalse(audit["rollbackVerified"]["waf-a"])
        self.assertTrue(audit["rollbackVerified"]["waf-b"])
        self.assertFalse(self.output.exists())

    def test_fence_missing_invalid_and_expiring_rejected(self):
        with self.assertRaisesRegex(ValueError, "fencing authority"):
            self.call(fence=None)
        self.assertFalse((self.folder / ".fleet-rev17.json.intent").exists())
        self.fence.expire_phase = "check-waf-b"
        with self.assertRaisesRegex(ValueError, "fencing authority"):
            self.call()
        self.assertFalse((self.folder / ".fleet-rev17.json.intent").exists())
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})
        self.fence.expire_phase = "before-apply-waf-b"
        with self.assertRaisesRegex(ValueError, "transaction failed"):
            self.call()
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})
        self.assertFalse(self.output.exists())

    def test_same_node_duplicate_alias_and_differing_baseline_fail_preflight(self):
        with self.assertRaisesRegex(ValueError, "independent"):
            self.call(nodes={"node-one": self.nodes["waf-a"],
                             "node-two": self.nodes["waf-a"]})
        with self.assertRaisesRegex(ValueError, "exactly two"):
            self.call(nodes={"node-one": self.nodes["waf-a"]})
        with self.assertRaisesRegex(ValueError, "identity"):
            self.call(nodes={"../foo": self.nodes["waf-a"], "other": self.nodes["waf-b"]})
        self.nodes["waf-b"].mode = "block"
        with self.assertRaises(ValueError):
            self.call()
        self.assertFalse((self.folder / ".fleet-rev17.json.intent").exists())
        self.assertNotIn(("apply", "block"), self.nodes["waf-a"].calls)

    def test_unapproved_image_or_crs_preflight_prevents_all_mutations(self):
        self.nodes["waf-a"].image = "sha256:" + "f" * 64
        with self.assertRaises(ValueError):
            self.call()
        self.assertNotIn(("apply", "block"), self.nodes["waf-a"].calls)
        self.assertFalse((self.folder / ".fleet-rev17.json.intent").exists())
        self.nodes["waf-a"].image = IMAGE
        self.nodes["waf-a"].ruleset = "F" * 64
        with self.assertRaises(ValueError):
            self.call()
        self.assertNotIn(("apply", "block"), self.nodes["waf-b"].calls)

    def test_changed_rules_during_apply_forces_partial_restore_failure(self):
        self.nodes["waf-a"].wrong_rules_on_target = True
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual(self.receipt(".fleet-rev17.json.failure")["result"],
                         "rollback-failed")
        self.assertFalse(self.output.exists())

    def test_receipt_failure_compensates_both_nodes(self):
        original = fleet.local.receipt
        def fail_final(path, item):
            if path == self.output:
                raise OSError("injected private fsync failure")
            return original(path, item)
        with mock.patch.object(fleet.local, "receipt", side_effect=fail_final):
            with self.assertRaises(ValueError):
                self.call()
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})
        self.assertFalse(self.output.exists())
        self.assertEqual(self.receipt(".fleet-rev17.json.failure")["result"],
                         "rolled-back")

    def test_old_journal_and_existing_receipt_refuse_replay(self):
        self.call()
        for node in self.nodes.values():
            node.calls.clear()
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual([n.calls for n in self.nodes.values()], [[], []])

    def test_unusable_or_preexisting_private_paths_rejected(self):
        self.output.write_text("prior", encoding="ascii")
        with self.assertRaises(ValueError):
            self.call()
        self.output.unlink()
        self.output.symlink_to(self.folder / "missing")
        with self.assertRaises(ValueError):
            self.call()
        self.output.unlink()
        os.chmod(self.folder, 0o755)
        with self.assertRaises(ValueError):
            self.call()
        self.assertEqual({n.mode for n in self.nodes.values()}, {"detect"})

    def test_explicit_compose_project_identity_cannot_alias_or_inject(self):
        source = self.folder / "compose.yml"
        source.write_text("services: {}", encoding="ascii")
        image = "owasp/modsecurity-crs@sha256:" + "a" * 64
        invocations = []
        def fake_runner(argv, env=None):
            invocations.append(argv)
            return "test"
        for value in ("../alias", "UPPER", "x", "a b", "--force",
                      "a" * 60, ""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fleet.local.DockerComposeProvider(
                    source, image, "http://127.0.0.1:18888/",
                    runner=fake_runner, project_name=value)
        provider = fleet.local.DockerComposeProvider(
            source, image, "http://127.0.0.1:18888/",
            runner=fake_runner, project_name="gatewaycore-waf-node-a")
        self.assertEqual(provider.command("ps", "-q", "waf"), "test")
        self.assertEqual(invocations[-1][4:6],
                         ["--project-name", "gatewaycore-waf-node-a"])

    def test_bad_policy_values_never_create_intent(self):
        for changes in ({"target": "Off"}, {"revision": 0},
                        {"revision": True}, {"policy_digest": "bad"},
                        {"ruleset_digest": "c" * 64}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.call(**changes)
        self.assertFalse((self.folder / ".fleet-rev17.json.intent").exists())


if __name__ == "__main__":
    unittest.main()
