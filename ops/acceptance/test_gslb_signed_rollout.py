import unittest
from unittest import mock
from types import SimpleNamespace
import gslb_signed_rollout as rollout

class RolloutTests(unittest.TestCase):
    def fixture(self):
        calls=[]
        nodes=[]
        for i in range(2):
            n=mock.Mock()
            n.pin=str(i)*64
            n.origin=SimpleNamespace(hostname="node-"+str(i),port=443)
            n.host="127.0.0."+str(i+1)
            n.port=53
            n.prepare={"transactionId":"transaction-1","expectedRevision":"A"*64,"sequence":7}
            n.after={"example.test":2}
            n.verify.side_effect=lambda *_, i=i: calls.append((i,"verify"))
            def request(action, body, i=i):
                calls.append((i,action))
                if action=="prepare":
                    return {"state":"prepared","transactionId":"transaction-1","originalRevision":"A"*64,"preparedRevision":"B"*64}
                return {"state":"activated-file-only" if action=="activate" else "restarted-revision-confirmed","revision":"B"*64}
            n.request.side_effect=request
            nodes.append(n)
        return nodes,calls

    def test_both_prepared_and_first_verified_before_second_restart(self):
        nodes,calls=self.fixture()
        rollout.preflight(nodes,{"example.test":1})
        self.assertEqual(calls,[(0,"verify"),(1,"verify")])
        calls.clear()
        journal=mock.Mock()
        rollout.execute(nodes,{"example.test":1},journal)
        self.assertEqual(calls[:2],[(0,"prepare"),(1,"prepare")])
        self.assertLess(calls.index((0,"restart")),calls.index((1,"activate")))
        self.assertEqual(journal.record.call_args.args,("both-verified-independent-authority-commit-required",))

    def test_failure_stops_second_node(self):
        nodes,calls=self.fixture()
        original=nodes[0].request.side_effect
        def fail(action,body):
            if action=="restart":
                raise TimeoutError()
            return original(action,body)
        nodes[0].request.side_effect=fail
        journal=mock.Mock()
        with self.assertRaises(TimeoutError):
            rollout.execute(nodes,{"example.test":1},journal)
        self.assertNotIn((1,"activate"),calls)
        self.assertEqual(journal.record.call_args.args,("unconfirmed-stop-and-reconcile",))

    def test_serial_rewind_refused_before_remote_mutation(self):
        nodes,calls=self.fixture()
        with self.assertRaises(ValueError):
            rollout.preflight(nodes,{"example.test":3})
        self.assertEqual(calls,[])

if __name__=="__main__":
    unittest.main()
