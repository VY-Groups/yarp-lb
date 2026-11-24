"""Fail-closed quorum fence contract; synthetic etcd JSON, no production lease.

Integration with a genuine external three-member etcd cluster, lease
writer and remote node-side fencing remains an independent gate.
"""
import base64
import copy
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import etcd_quorum_fence as fence

NAMES=("node-a","node-b")
P="A"*64
H="a"*32


def endpoints():
    return [
        {"url":f"https://127.0.0.{n}:2379",
         "leafSha256":str(n)*64}
        for n in (1,2,3)
    ]


def value():
    return {
        "schemaVersion":1,"kind":"waf",
        "nodeIds":list(NAMES),"revision":7,
        "policySha256":P,"holder":H
    }


def range_response(member, *, mod=50, lease=123, revision=70, cluster=999,
                   changed=None, key="/gatewaycore/waf/fence/fleet-a"):
    body=changed if changed is not None else value()
    return {
        "header":{"cluster_id":str(cluster),"member_id":str(member),
                  "revision":str(revision)},
        "count":"1",
        "kvs":[{"key":base64.b64encode(key.encode("ascii")).decode("ascii"),
                "value":base64.b64encode(json.dumps(body).encode("ascii")).decode("ascii"),
                "mod_revision":str(mod),"version":"1","lease":str(lease)}]
    }


def ttl_response(*, lease=123, ttl=10, granted=12):
    return {"ID":str(lease), "TTL":str(ttl),"grantedTTL":str(granted)}


class EtcdQuorumTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="waf-quorum-fence-")
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        root.chmod(0o700)
        self.ca=root/"ca.pem"
        self.cert=root/"client.pem"
        self.key=root/"client.key"
        for f in (self.ca,self.cert,self.key):
            f.write_text("synthetic-not-valid-cert (network method is mocked)",encoding="ascii")
            f.chmod(0o600)
        self.f=fence.EtcdQuorumFence("fleet-a",endpoints(),999,
                                    str(self.ca),str(self.cert),str(self.key))
        self.members={f"127.0.0.{i}":i for i in (1,2,3)}
        self.kvs={}
        self.ttls={}
        self.faults=set()
        self.requests=[]

        def stub(endpoint,resource,payload):
            host=endpoint[0]
            self.requests.append((host,resource,payload))
            if host in self.faults:
                raise OSError("synthetic member partition")
            if resource=="/v3/kv/range":
                self.assertEqual(payload["serializable"],False)
                self.assertEqual(base64.b64decode(payload["key"]).decode("ascii"),
                                 "/gatewaycore/waf/fence/fleet-a")
                return self.kvs.get(host,range_response(self.members[host]))
            if resource=="/v3/lease/timetolive":
                self.assertRegex(payload["ID"],r"^[1-9][0-9]+$")
                self.assertIs(payload["keys"],False)
                return self.ttls.get(host,ttl_response(lease=int(payload["ID"])))
            raise AssertionError("unapproved etcd operation")

        self.patcher=mock.patch.object(self.f,"_post",side_effect=stub)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def check(self,phase="preflight"):
        return self.f.assert_current(NAMES,7,P,phase)

    def test_healthy_quorum_and_fresh_linearizable_read_every_phase(self):
        self.assertTrue(self.check())
        for stage in ("check-node-a","check-node-b","before-journal",
                      "before-apply-node-a","after-apply-node-a",
                      "before-apply-node-b","after-apply-node-b",
                      "before-receipt","rollback-node-b","rollback-node-a"):
            self.assertTrue(self.check(stage))
        self.assertEqual(len(self.requests),3*2*11)
        self.assertEqual(
            {resource for _,resource,_ in self.requests},
            {"/v3/kv/range","/v3/lease/timetolive"})
        self.assertFalse(self.f.assert_current(NAMES,7,P,"unexpected-phase"))
        self.assertFalse(self.f.assert_current(("node-b","node-a"),7,P,"preflight"))
        self.assertFalse(self.f.assert_current(NAMES,7,"0"*64,"preflight"))

    def test_one_unreachable_member_still_has_two_member_quorum(self):
        self.faults.add("127.0.0.3")
        self.assertTrue(self.check())
        self.assertTrue(self.check("before-apply-node-a"))
        self.faults.add("127.0.0.2")
        self.assertFalse(self.check("before-apply-node-b"))

    def test_stale_split_brain_or_duplicate_member_identity_never_votes(self):
        for scenario in ("replaced-lease","different-epoch","wrong-cluster",
                         "duplicate-member","old-header","unverified-policy"):
            with self.subTest(scenario=scenario):
                self.f._identity=None
                self.kvs={}
                if scenario=="replaced-lease":
                    self.kvs["127.0.0.3"]=range_response(3,lease=124)
                if scenario=="different-epoch":
                    self.kvs["127.0.0.3"]=range_response(3,mod=51)
                if scenario=="wrong-cluster":
                    self.kvs["127.0.0.3"]=range_response(3,cluster=1000)
                if scenario=="duplicate-member":
                    self.kvs["127.0.0.3"]=range_response(2)
                if scenario=="old-header":
                    self.kvs["127.0.0.3"]=range_response(3,revision=49)
                if scenario=="unverified-policy":
                    wrong=value()
                    wrong["policySha256"]="B"*64
                    self.kvs["127.0.0.3"]=range_response(3,changed=wrong)
                if scenario in ("wrong-cluster","old-header","unverified-policy"):
                    # One member is rejected -> two honest member quorum still
                    # safe, never a third vote from stale/wrong cluster.
                    self.assertTrue(self.check())
                else:
                    self.assertFalse(self.check())

    def test_epoch_change_after_first_phase_fences_even_valid_new_lease(self):
        self.assertTrue(self.check())
        self.kvs={
            f"127.0.0.{n}":range_response(n,mod=51,lease=123)
            for n in (1,2,3)
        }
        self.assertFalse(self.check("before-apply-node-a"))
        self.kvs={}
        self.assertTrue(self.check("rollback-node-a"))

    def test_late_member_cannot_resurrect_earlier_expiring_majority(self):
        # Each early member reports TTL=4, which appears valid at receipt.
        # A third honest but slow member costs >1 s: by the FINAL quorum
        # decision the earlier leases have <3 s runway and must be refused.
        self.ttls={
            "127.0.0.1":ttl_response(ttl=4,granted=12),
            "127.0.0.2":ttl_response(ttl=4,granted=12),
            "127.0.0.3":ttl_response(ttl=12,granted=12),
        }
        original=self.f._read_member
        def slow_third(endpoint,*args):
            if endpoint[0]=="127.0.0.3":
                time.sleep(1.25)
            return original(endpoint,*args)
        with mock.patch.object(self.f,"_read_member",side_effect=slow_third):
            self.assertFalse(self.check())
            self.assertIsNone(self.f._identity)
            # A genuinely long enough lease may still be accepted after
            # the same network delay; do not make quorum permanently dead.
            self.ttls={f"127.0.0.{n}":ttl_response(ttl=12,granted=12)
                       for n in (1,2,3)}
            self.assertTrue(self.check())
            self.assertTrue(self.check("before-apply-node-a"))

    def test_expired_or_short_ttl_fails_closed_and_never_uses_cached_approval(self):
        self.assertTrue(self.check())
        for remaining in (-1,0,1,2,121):
            self.ttls={f"127.0.0.{n}":ttl_response(ttl=remaining,granted=121)
                       for n in (1,2,3)}
            with self.subTest(remaining=remaining):
                self.assertFalse(self.check("before-apply-node-a"))
        self.ttls={f"127.0.0.{n}":ttl_response(ttl=8,granted=12)
                   for n in (1,2,3)}
        self.assertTrue(self.check("before-apply-node-a"))

    def test_invalid_static_config_and_untrusted_cert_key_refuse_start(self):
        for bad in (
            [{"url":"http://127.0.0.1:2379","leafSha256":"1"*64},
             *endpoints()[1:]],
            [endpoints()[0],endpoints()[0],endpoints()[2]],
            [endpoints()[0],{"url":"https://127.0.0.2:2379",
                             "leafSha256":"1"*64},endpoints()[2]],
            endpoints()[:2],
        ):
            with self.subTest(bad=bad),self.assertRaises(ValueError):
                fence.EtcdQuorumFence("fleet-a",bad,999,
                    str(self.ca),str(self.cert),str(self.key))
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            fence.EtcdQuorumFence("fleet-a",endpoints(),999,
                                 str(self.ca),str(self.cert),str(self.key))

    def test_invalid_response_schema_not_a_valid_member_vote(self):
        for change in (
            lambda x: x.update({"count":"2"}),
            lambda x: x["kvs"][0].update({"lease":"0"}),
            lambda x: x["kvs"][0].update({"version":"0"}),
            lambda x: x["kvs"][0].update({"key":"invalid#base64"}),
            lambda x: x["kvs"][0].update({"mod_revision":"999"}),
            lambda x: x.pop("kvs"),
        ):
            self.kvs={}
            self.f._identity=None
            a=range_response(3)
            change(a)
            self.kvs["127.0.0.3"]=a
            # Only member 3 is rejected; two healthy constitute quorum.
            self.assertTrue(self.check())
            self.faults={"127.0.0.2"}
            self.assertFalse(self.check("before-journal"))
            self.faults=set()

    def test_strict_json_and_lease_policy(self):
        for raw in (b'{"a":1,"a":2}',b'{"n":NaN}',b'',
                    b"{" + b"a"*fence.MAX_REPLY + b"}"):
            with self.subTest(raw=raw[:32]),self.assertRaises(ValueError):
                fence.strict_json(raw)
        val=value()
        val["revision"]=8
        with self.assertRaises(ValueError):
            fence.valid_value(json.dumps(val).encode("ascii"),NAMES,7,P)
        with self.assertRaises(ValueError):
            fence.integer("00")


if __name__ == "__main__":
    unittest.main()
