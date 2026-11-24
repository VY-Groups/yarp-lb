"""Mocked process-boundary contract for Linux mTLS -> independent .NET restore.

The real signed P-256 restore is accepted by LinuxKeyProtectionTests; here a
fake subprocess checks refusal/argument isolation ONLY. It is deliberately
NOT represented as a cryptographic DP restore or two-host DR acceptance.
"""
import io
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock
import zipfile

import linux_dp_mtls_transport as wire
import linux_dp_receive_restore as recovery


KEY = "key-11111111-2222-3333-4444-555555555555.xml"


def synthetic_blob():
    stream=io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as z:
        for name, data in (
            ("checkpoint.json", b"NOT-A-VALID-P256-CHECKPOINT"),
            ("ring/"+KEY, b"NOT-A-VALID-ENCRYPTED-DP-XML")
        ):
            meta=zipfile.ZipInfo(name)
            meta.create_system=3
            meta.external_attr=(0o100600)<<16
            z.writestr(meta, data)
    return stream.getvalue()


class SyntheticFence:
    """Phase assertions only; NOT independent authenticated etcd evidence."""

    def __init__(self, *, deny=None, expected=None, remaining=90):
        self.checkpoint_sha = (expected if expected is not None
            else hashlib.sha256(b"NOT-A-VALID-P256-CHECKPOINT"
                                ).hexdigest().upper())
        self.deny = deny
        self.remaining = remaining
        self.phases = []

    def remaining_seconds(self):
        return self.remaining

    def current(self, phase):
        self.phases.append(phase)
        return phase != self.deny


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="dp-offline-receiver-")
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.root.chmod(0o700)
        self.inbox=self.root/"inbox"
        self.state=self.root/"state"
        self.release=self.root/"release"
        self.trust=self.root/"trust"
        for path in (self.inbox,self.state,self.release,self.trust):
            path.mkdir(mode=0o700)
        self.exe=self.release/recovery.RESTORE_APP
        self.exe.write_text("#!/bin/sh\nexit 0\n",encoding="ascii")
        self.exe.chmod(0o700)
        self.public=self.trust/"verifier.pem"
        self.floor=self.trust/"floor.txt"
        self.public.write_text("synthetic TRUST anchor; not actual P256",encoding="ascii")
        self.floor.write_text("7\n",encoding="ascii")
        for file in (self.public,self.floor):
            file.chmod(0o600)
        self.args=SimpleNamespace(
            approved_offline=True,
            destination_root=str(self.inbox),
            state_root=str(self.state),
            restore_bundle=str(self.release),
            restore_bundle_sha256=recovery.tree_hash(self.release),
            trusted_public_key=str(self.public),
            minimum_revision_file=str(self.floor),
            server_url="https://127.0.0.1:17443", label="rev8",
            server_cert_sha256="A"*64,
            ca="/trusted/ca", certificate="/trusted/receiver", private_key="/trusted/key")
        self.calls=[]

    def fake_success(self, command, **kwargs):
        self.calls.append((command,kwargs))
        self.assertEqual(command[0],str(self.exe))
        self.assertEqual(command[1],"restore")
        self.assertEqual(command[2:4],["--archive",str(self.inbox/"rev8"/"ring")])
        self.assertIn("--minimum-revision-file",command)
        self.assertFalse(kwargs["shell"])
        self.assertIs(kwargs["stdin"],recovery.subprocess.DEVNULL)
        self.assertIs(kwargs["stdout"],recovery.subprocess.DEVNULL)
        self.assertIs(kwargs["stderr"],recovery.subprocess.DEVNULL)
        destination=self.state/"data-protection-keys"
        destination.mkdir(mode=0o700)
        (destination/KEY).write_bytes(b"synthetic-test-only; NOT real .NET")
        (destination/KEY).chmod(0o600)
        return SimpleNamespace(returncode=0)

    def test_executable_process_contract_not_cryptographic_acceptance(self):
        blob=synthetic_blob()
        received=recovery.restore_once(self.args,fetch=lambda *_:blob,
                                        invoke=self.fake_success)
        self.assertEqual(received,str(self.inbox/"rev8"))
        self.assertEqual(len(self.calls),1)
        external_checkpoint = self.inbox/".rev8.signed-checkpoint.json"
        self.assertTrue(external_checkpoint.is_file())
        self.assertEqual(external_checkpoint.read_bytes(),
                         b"NOT-A-VALID-P256-CHECKPOINT")
        self.assertEqual(external_checkpoint.stat().st_mode & 0o077, 0)
        self.assertTrue(recovery.disjoint(str(external_checkpoint),
                                         str(self.inbox/"rev8")))
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:blob,
                                  invoke=self.fake_success)
        self.assertEqual(len(self.calls),1)

    def test_ambient_dotnet_root_is_never_implicitly_trusted(self):
        # An attacker may control an inherited service/CI environment.
        # Only an independently approved root can be passed to the child.
        with mock.patch.dict(os.environ, {
            "DOTNET_ROOT": "/tmp/attacker-controlled-runtime",
            "DOTNET_ROOT_X64": "/tmp/other-attacker-runtime"
        }):
            received = recovery.restore_once(
                self.args, fetch=lambda *_:synthetic_blob(),
                invoke=self.fake_success)
        self.assertEqual(received, str(self.inbox/"rev8"))
        child_environment = self.calls[0][1]["env"]
        self.assertNotIn("DOTNET_ROOT", child_environment)
        self.assertNotIn("DOTNET_ROOT_X64", child_environment)

    def test_invalid_explicit_runtime_root_refuses_signed_restore(self):
        # An operator cannot approve a symlink or an untrusted runtime
        # directory, even when a malicious host-shaped executable exists.
        path = self.root/"untrusted-runtime"
        path.mkdir(mode=0o700)
        (path/"dotnet").write_text("fixture-only", encoding="ascii")
        (path/"dotnet").chmod(0o777)
        self.args.dotnet_runtime_root = str(path)
        with self.assertRaises(ValueError):
            recovery.restore_once(
                self.args, fetch=lambda *_:synthetic_blob(),
                invoke=lambda *a, **k:self.fail("unsafe .NET runtime executed"))
        self.assertFalse((self.state/"data-protection-keys").exists())

    def test_explicit_quorum_checked_at_every_real_receiver_boundary(self):
        fence = SyntheticFence()
        received = recovery.restore_once(
            self.args, fetch=lambda *_:synthetic_blob(),
            invoke=self.fake_success, fence=fence)
        self.assertEqual(received,str(self.inbox/"rev8"))
        self.assertEqual(fence.phases,[
            "preflight", "before-transfer", "after-transfer",
            "before-signed-restore", "after-signed-restore"])
        self.assertEqual(len(self.calls),1)
        self.assertLessEqual(self.calls[0][1]["timeout"], 85)
        self.assertGreater(self.calls[0][1]["timeout"], 0)

    def test_remote_fleet_transfer_requires_quorum_before_tls_connect(self):
        self.args.server_url = "https://10.0.0.11:17443"
        with self.assertRaises(ValueError):
            recovery.restore_once(
                self.args, fetch=lambda *_:self.fail("remote unfenced TLS"))
        self.assertFalse((self.inbox/"rev8").exists())

    def test_signed_checkpoint_must_match_pinned_epoch_exactly(self):
        fence = SyntheticFence(expected="0"*64)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:synthetic_blob(),
                                  fence=fence,
                                  invoke=lambda *a,**k:self.fail("wrong checkpoint"))
        self.assertFalse((self.state/"data-protection-keys").exists())
        self.assertEqual(fence.phases,["preflight", "before-transfer"])
        self.assertFalse((self.inbox/"rev8").exists(),
                         "wrong epoch must not reserve the durable archive label")

    def test_quorum_loss_after_download_prevents_durable_publication(self):
        fence = SyntheticFence(deny="after-transfer")
        with self.assertRaises(ValueError):
            recovery.restore_once(
                self.args, fetch=lambda *_:synthetic_blob(), fence=fence,
                stage=lambda *_:self.fail("unauthorized durable archive"),
                invoke=lambda *a,**k:self.fail("unauthorized restore"))
        self.assertEqual(fence.phases,["preflight", "before-transfer",
                                       "after-transfer"])
        self.assertEqual(list(self.inbox.iterdir()), [])

    def test_staged_checkpoint_must_match_inspected_response(self):
        def tampered_stage(root, label, blob):
            path = wire.stage_received(root, label, blob)
            (Path(path)/"checkpoint.json").write_bytes(b"changed")
            return path

        with self.assertRaises(ValueError):
            recovery.restore_once(
                self.args, fetch=lambda *_:synthetic_blob(),
                stage=tampered_stage, fence=SyntheticFence(),
                invoke=lambda *a,**k:self.fail("changed checkpoint"))
        self.assertFalse((self.inbox/".rev8.signed-checkpoint.json").exists())
        self.assertFalse((self.state/"data-protection-keys").exists())

    def test_no_restore_execution_without_sufficient_lease_runway(self):
        fence = SyntheticFence(remaining=8)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:synthetic_blob(),
                fence=fence,invoke=lambda *a,**k:self.fail("late signed restore"))
        self.assertFalse((self.state/"data-protection-keys").exists())
        self.assertEqual(fence.phases[-1],"before-signed-restore")

    def test_expired_lease_before_transfer_denies_network(self):
        fence = SyntheticFence(deny="before-transfer")
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                fetch=lambda *_:self.fail("unfenced network"), fence=fence)
        self.assertEqual(fence.phases,["preflight","before-transfer"])
        self.assertFalse((self.inbox/"rev8").exists())

    def test_lost_lease_after_transfer_or_before_restore_blocks_execution(self):
        for denied in ("after-transfer","before-signed-restore"):
            with self.subTest(phase=denied):
                fence = SyntheticFence(deny=denied)
                with tempfile.TemporaryDirectory(prefix="dp-fenced-receiver-") as d:
                    root = Path(d)
                    root.chmod(0o700)
                    inbox, state = root/"inbox",root/"state"
                    inbox.mkdir(mode=0o700)
                    state.mkdir(mode=0o700)
                    original_inbox,original_state = (
                        self.args.destination_root,self.args.state_root)
                    self.args.destination_root = str(inbox)
                    self.args.state_root = str(state)
                    try:
                        with self.assertRaises(ValueError):
                            recovery.restore_once(
                                self.args,fetch=lambda *_:synthetic_blob(),
                                fence=fence,
                                invoke=lambda *a,**k:self.fail("fenced restore"))
                        self.assertFalse((state/"data-protection-keys").exists())
                    finally:
                        self.args.destination_root = original_inbox
                        self.args.state_root = original_state

    def test_lost_lease_after_restore_never_claims_fleet_admission(self):
        fence = SyntheticFence(deny="after-signed-restore")
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:synthetic_blob(),
                                  invoke=self.fake_success,fence=fence)
        # The explicitly OFFLINE ring remains for independent reconciliation,
        # not an auto-promoted or deleted live node. No success is returned.
        self.assertTrue((self.state/"data-protection-keys").exists())
        self.assertEqual(fence.phases[-1],"after-signed-restore")

    def test_quorum_inventory_requires_complete_external_private_trust(self):
        members = {
            "schemaVersion":1, "fleet":"fleet-ci", "clusterId":"999",
            "endpoints":[{
                "url":f"https://127.0.0.{i}:2379",
                "leafSha256":str(i)*64, "memberId":i
            } for i in (1,2,3)]}
        inventory = self.trust/"approved-etcd.json"
        inventory.write_text(json.dumps(members),encoding="ascii")
        inventory.chmod(0o600)
        ca = self.trust/"root.pem"
        cert = self.trust/"reader.pem"
        secret = self.trust/"reader.key"
        for item in (ca, cert, secret):
            item.write_text("disposable parser fixture, not a TLS key",
                            encoding="ascii")
            item.chmod(0o600)
        self.args.fleet_quorum_inventory = str(inventory)
        self.args.fleet = "fleet-ci"
        self.args.sender_node_id = "gateway-a"
        self.args.receiver_node_id = "gateway-b"
        self.args.recovery_revision = 43
        self.args.checkpoint_sha256 = "A"*64
        self.args.etcd_ca = str(ca)
        self.args.etcd_certificate = str(cert)
        self.args.etcd_private_key = str(secret)
        authority = recovery.build_quorum_authority(self.args)
        self.assertEqual(authority.sender, "gateway-a")
        self.assertEqual(authority.checkpoint_sha, "A"*64)
        self.assertEqual(authority.key_name,
                         "/gatewaycore/linux-dp/recovery/fleet-ci")

        self.args.etcd_private_key = None
        with self.assertRaises(ValueError):
            recovery.build_quorum_authority(self.args)
        self.args.etcd_private_key = str(secret)

        self.args.fleet_quorum_inventory = str(self.inbox/"untrusted.json")
        bad = self.inbox/"untrusted.json"
        bad.write_text(json.dumps(members), encoding="ascii")
        bad.chmod(0o600)
        with self.assertRaises(ValueError):
            recovery.build_quorum_authority(self.args)

        self.args.fleet_quorum_inventory = str(inventory)
        self.args.etcd_private_key = str(self.state/"untrusted.key")
        bad_key = self.state/"untrusted.key"
        bad_key.write_text("untrusted", encoding="ascii")
        bad_key.chmod(0o600)
        with self.assertRaises(ValueError):
            recovery.build_quorum_authority(self.args)

        self.args.etcd_private_key = str(secret)
        inventory.chmod(0o644)
        with self.assertRaises(ValueError):
            recovery.build_quorum_authority(self.args)

    def test_no_operator_approval_fails_before_any_communication(self):
        self.args.approved_offline=False
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                                  fetch=lambda *_:self.fail("unapproved network"))
        self.assertFalse((self.inbox/"rev8").exists())

    def test_release_tamper_or_unapproved_dependency_prevents_transfer(self):
        self.exe.write_text("#!/bin/sh\nexit 3\n",encoding="ascii")
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                                  fetch=lambda *_:self.fail("unapproved network"))
        self.exe.write_text("#!/bin/sh\nexit 0\n",encoding="ascii")
        extra=self.release/"extra-library.dll"
        extra.write_bytes(b"unreviewed dynamic dependency")
        extra.chmod(0o600)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                                  fetch=lambda *_:self.fail("unapproved network"))

    def test_restore_process_failure_does_not_claim_restored_state(self):
        blob=synthetic_blob()
        def fail(command,**kwargs):
            self.assertIn("restore",command)
            return SimpleNamespace(returncode=2)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:blob,invoke=fail)
        self.assertFalse((self.state/"data-protection-keys").exists())
        self.assertTrue((self.inbox/"rev8"/"checkpoint.json").exists())

    def test_zero_exit_without_private_ring_cannot_claim_success(self):
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,fetch=lambda *_:synthetic_blob(),
                                  invoke=lambda *a,**k:SimpleNamespace(returncode=0))
        self.assertFalse((self.state/"data-protection-keys").exists())

    def test_restore_into_existing_ring_is_never_allowed(self):
        ring=self.state/"data-protection-keys"
        ring.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                                  fetch=lambda *_:self.fail("unapproved network"))
        self.assertEqual(list(ring.iterdir()),[])

    def test_trust_or_state_overlap_refuses_without_side_effects(self):
        self.args.minimum_revision_file=str(self.inbox/"floor.txt")
        (self.inbox/"floor.txt").write_text("7",encoding="ascii")
        (self.inbox/"floor.txt").chmod(0o600)
        with self.assertRaises(ValueError):
            recovery.restore_once(self.args,
                                  fetch=lambda *_:self.fail("unapproved network"))
        self.assertFalse((self.inbox/"rev8").exists())

    def test_publisher_symlinks_and_unsafe_modes_refuse(self):
        bad=self.release/"untrusted"
        bad.symlink_to(self.exe)
        with self.assertRaises(ValueError):
            recovery.verify_restore_app(str(self.release),
                                        self.args.restore_bundle_sha256)
        bad.unlink()
        self.exe.chmod(0o777)
        with self.assertRaises(ValueError):
            recovery.verify_restore_app(str(self.release),
                                        self.args.restore_bundle_sha256)


if __name__=="__main__":
    unittest.main()
