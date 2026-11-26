import hashlib
import json
from pathlib import Path
import unittest
from unittest import mock
import specialist_tls_broker as broker

class SpecialistBrokerTests(unittest.TestCase):
    def test_peer_pin_is_exact(self):
        connection = mock.Mock()
        connection.getpeercert.return_value = b"leaf"
        self.assertTrue(broker.pinned_peer(connection, hashlib.sha256(b"leaf").hexdigest().upper()))
        self.assertFalse(broker.pinned_peer(connection, "0"*64))
        connection.getpeercert.return_value = None
        self.assertFalse(broker.pinned_peer(connection, "0"*64))

    def test_dns_only_exact_plan_and_explicit_execute(self):
        plan = ([object(), object()], {"example.test": 1}, Path("/private/journal"), 7, "A"*64)
        request = {"operation":"preflight","revision":7,"digest":"A"*64}
        with mock.patch.object(broker.dns,"preflight") as pre, mock.patch.object(broker.dns,"Journal") as journal, mock.patch.object(broker.dns,"execute") as execute:
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"digest":"B"*64}).encode(),plan),"refused-or-failed")
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"path":"/tmp/x"}).encode(),plan),"refused-or-failed")
            pre.assert_not_called()
            self.assertEqual(broker.dispatch_dns(json.dumps(request).encode(),plan),"preflight-only")
            execute.assert_not_called()
            journal.assert_not_called()
            self.assertEqual(broker.dispatch_dns(json.dumps({**request,"operation":"execute"}).encode(),plan),"applied-uncommitted")
            execute.assert_called_once()
            journal.assert_called_once_with(plan[2])

    def test_dns_preflight_failure_never_mutates(self):
        plan = ([], {}, Path("/private/journal"), 7, "A"*64)
        raw = json.dumps({"operation":"execute","revision":7,"digest":"A"*64}).encode()
        with mock.patch.object(broker.dns,"preflight",side_effect=ValueError()), mock.patch.object(broker.dns,"execute") as execute:
            self.assertEqual(broker.dispatch_dns(raw,plan),"refused-or-failed")
            execute.assert_not_called()

if __name__ == "__main__":
    unittest.main()
