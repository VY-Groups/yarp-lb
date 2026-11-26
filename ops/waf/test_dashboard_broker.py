import argparse
import json
import unittest
from unittest import mock
import dashboard_broker as broker

class DashboardBrokerTests(unittest.TestCase):
    def test_only_exact_policy_and_kernel_identity_dispatched(self):
        approved = argparse.Namespace(confirm_revision=7, confirm_policy_sha256="A"*64, execute=False)
        request = {"operation":"execute","revision":7,"digest":"A"*64}
        raw = json.dumps(request).encode()
        with mock.patch.object(broker.rollout,"run",return_value="applied-uncommitted") as run:
            self.assertEqual(broker.dispatch(raw,approved,1001,1002),"refused-or-failed")
            self.assertEqual(broker.dispatch(json.dumps({**request,"digest":"B"*64}).encode(),approved,1002,1002),"refused-or-failed")
            self.assertEqual(broker.dispatch(json.dumps({**request,"argv":["--execute"]}).encode(),approved,1002,1002),"refused-or-failed")
            run.assert_not_called()
            self.assertEqual(broker.dispatch(raw,approved,1002,1002),"applied-uncommitted")
            self.assertTrue(run.call_args.args[0].execute)
            self.assertFalse(approved.execute)

    def test_preflight_cannot_claim_mutation(self):
        approved = argparse.Namespace(confirm_revision=7, confirm_policy_sha256="A"*64, execute=False)
        raw = json.dumps({"operation":"preflight","revision":7,"digest":"A"*64}).encode()
        with mock.patch.object(broker.rollout,"run",return_value="applied-uncommitted") as run:
            self.assertEqual(broker.dispatch(raw,approved,1002,1002),"refused-or-failed")
            self.assertFalse(run.call_args.args[0].execute)

if __name__ == "__main__":
    unittest.main()
