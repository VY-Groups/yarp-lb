"""Operator orchestration contracts; real signatures and disposable mTLS are separate suites."""
from argparse import Namespace
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import waf_fleet_rollout as cli

DIGEST = "A" * 64
IMAGE = "sha256:" + "b" * 64


class OperatorTests(unittest.TestCase):
    def test_signature_digest_and_revision_bound_before_remote_calls(self):
        raw = b'{"mode":"detect","revision":7,"exceptions":[]}'
        digest = hashlib.sha256(raw).hexdigest().upper()
        args = Namespace(policy=Path("/private/policy.json"), approval=[],
            reviewer_key=["reviewerA=/trust/a.pem","reviewerB=/trust/b.pem"],
            minimum_revision_file=Path("/trust/floor"), observed_ruleset_sha256=DIGEST,
            shadow_evidence_file=None, confirm_revision=7, confirm_policy_sha256=digest)
        with mock.patch.object(cli.signed,"_read_file",return_value=raw), \
             mock.patch.object(cli.signed,"verify",return_value=(7,digest)) as verify:
            self.assertEqual(cli.approved_policy(args),("detect",7,digest))
            self.assertTrue(verify.call_args.kwargs["return_digest"])
            args.confirm_revision=6
            with self.assertRaises(ValueError):
                cli.approved_policy(args)
            args.confirm_revision=7
            verify.return_value=(7,"B"*64)
            with self.assertRaises(ValueError):
                cli.approved_policy(args)

    def test_preflight_checks_fence_without_mutating_or_writing_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            receipt=Path(root)/"result.json"
            class Provider:
                def __init__(self):
                    self.apply=mock.Mock(side_effect=AssertionError("preflight mutated"))
                def inspect(self): return {"mode":"detect","imageId":IMAGE}
                def image_and_config(self,mode): return IMAGE
                def observed_rule_digest(self): return DIGEST
                def smoke(self,mode): pass
            nodes={"node-a":Provider(),"node-b":Provider()}
            fence=mock.Mock(spec=cli.EtcdQuorumFence)
            fence.assert_current.return_value=True
            self.assertEqual(cli.preflight(nodes,fence,"block",7,DIGEST,DIGEST,receipt),"preflight-only")
            self.assertFalse(receipt.exists())
            self.assertEqual(fence.assert_current.call_count,4)
            for node in nodes.values(): node.apply.assert_not_called()
            fence.assert_current.return_value=False
            with self.assertRaises(ValueError):
                cli.preflight(nodes,fence,"block",7,DIGEST,DIGEST,receipt)

    def test_run_uses_coordinator_only_for_explicit_execute(self):
        args=Namespace(node=[["node-a","https://a:443","A"*64],["node-b","https://b:443","B"*64]],
            etcd_members=Path("/trust/members"),etcd_ca="ca",etcd_certificate="cert",
            etcd_private_key="key",node_ca="ca",node_certificate="cert",node_private_key="key",
            observed_ruleset_sha256=DIGEST,receipt=Path("/private/receipt"),execute=False)
        with mock.patch.object(cli.sys,"platform","linux"), \
             mock.patch.object(cli,"approved_policy",return_value=("block",7,DIGEST)), \
             mock.patch.object(cli,"approved_endpoint_file",return_value={"fleet":"fleet-a","endpoints":[],"clusterId":"1"}), \
             mock.patch.object(cli,"EtcdQuorumFence"), mock.patch.object(cli,"RemoteNodeProvider"), \
             mock.patch.object(cli,"preflight",return_value="preflight-only") as pre, \
             mock.patch.object(cli.fleet,"coordinate",return_value="applied-uncommitted") as execute:
            self.assertEqual(cli.run(args),"preflight-only")
            pre.assert_called_once()
            execute.assert_not_called()
            args.execute=True
            self.assertEqual(cli.run(args),"applied-uncommitted")
            execute.assert_called_once()
            self.assertIn("fence",execute.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
