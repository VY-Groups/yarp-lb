"""Synthetic failure contracts for independently pinned etcd WAF CAS authority.

Real three-process Raft/TLS CAS and expiry acceptance is separately executed
by tests/WafEtcd/real_quorum.py. No live customer credentials are used.
"""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import etcd_cas_writer as cas


NODES=("node-a","node-b")
POLICY="A"*64


class CasTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(prefix="etcd-cas-writer-")
        self.addCleanup(tmp.cleanup)
        root=Path(tmp.name)
        root.chmod(0o700)
        ca, cert, key=[root/n for n in ("ca.pem","writer.pem","writer.key")]
        for item in (ca,cert,key):
            item.write_text("synthetic identity; mocked network",encoding="ascii")
            item.chmod(0o600)
        members=[{"url":f"https://127.0.0.{n}:2379",
                  "leafSha256":str(n)*64,"memberId":n} for n in (1,2,3)]
        self.writer=cas.EtcdCasWriter("fleet-a",members,999,
                                    str(ca),str(cert),str(key),
                                    NODES,7,POLICY)
        self.active=False
        self.contested=False
        self.wrong_member=False
        self.revoked=False
        self.bad_holder=False
        self.fail_member=set()
        self.txns=0
        self.grants=0
        self.holder=None
        self.expected_key=base64.b64encode(b"/gatewaycore/waf/fence/fleet-a").decode("ascii")

        def stub(endpoint,resource,body):
            member=endpoint[3]
            if member in self.fail_member:
                raise OSError("synthetic etcd minority")
            if resource=="/v3/kv/range":
                self.assertIs(body["serializable"],False)
                self.assertEqual(body["key"],self.expected_key)
                data={"header":{"cluster_id":"999",
                                "member_id":str(1 if self.wrong_member and member==3
                                                else member),"revision":"100"}}
                if self.active:
                    value={"schemaVersion":1,"kind":"waf","nodeIds":list(NODES),
                           "revision":7,"policySha256":POLICY,
                           "holder":"f"*32 if self.bad_holder else self.holder}
                    data.update({"count":"1","kvs":[{
                        "key":self.expected_key,
                        "value":base64.b64encode(json.dumps(value).encode("ascii")
                                                ).decode("ascii"),
                        "mod_revision":"90","version":"1","lease":"456"}]})
                return data
            if resource=="/v3/lease/grant":
                self.grants+=1
                self.assertEqual(body["TTL"],"120")
                return {"ID":"456","TTL":"120"}
            if resource=="/v3/kv/txn":
                self.txns+=1
                self.assertEqual(body["compare"][0]["createRevision"],"0")
                if self.contested:
                    return {"header":{"cluster_id":"999"},"succeeded":False}
                encoded=body["success"][0]["requestPut"]["value"]
                self.assertEqual(body["success"][0]["requestPut"]["lease"],"456")
                self.holder=json.loads(base64.b64decode(encoded))["holder"]
                self.active=True
                return {"header":{"cluster_id":"999"},"succeeded":True}
            if resource=="/v3/lease/timetolive":
                self.assertEqual(body["ID"],"456")
                return {"ID":"456","TTL":"100","grantedTTL":"120"}
            if resource=="/v3/lease/revoke":
                self.assertEqual(body["ID"],"456")
                self.revoked=True
                self.active=False
                return {}
            raise AssertionError("unexpected etcd mutation API")
        self.patch=mock.patch.object(self.writer.client,"_post",side_effect=stub)
        self.patch.start()
        self.addCleanup(self.patch.stop)

    def test_fresh_absent_quorum_cas_and_verify_exact_holder(self):
        receipt=self.writer.issue_once()
        self.assertTrue(self.active)
        self.assertEqual(receipt["nodeIds"],list(NODES))
        self.assertEqual(receipt["leaseId"],456)
        self.assertEqual(receipt["modRevision"],90)
        self.assertEqual(receipt["holder"],self.holder)
        self.assertEqual(self.txns,1)
        self.assertFalse(self.revoked)

    def test_existing_authority_is_never_stolen(self):
        self.active=True
        self.holder="a"*32
        with self.assertRaises(ValueError):
            self.writer.issue_once()
        self.assertEqual(self.grants,0)
        self.assertEqual(self.txns,0)
        self.assertFalse(self.revoked)

    def test_cas_competition_revokes_only_new_lease(self):
        self.contested=True
        with self.assertRaises(ValueError):
            self.writer.issue_once()
        self.assertTrue(self.revoked)
        self.assertEqual(self.txns,1)

    def test_distinct_member_quorum_required_before_grant(self):
        self.fail_member.update({2,3})
        with self.assertRaises(ValueError):
            self.writer.issue_once()
        self.assertEqual(self.grants,0)
        self.fail_member.clear()
        self.wrong_member=True
        with self.assertRaises(ValueError):
            self.writer.issue_once()
        self.assertEqual(self.grants,0)

    def test_post_cas_holder_mismatch_fails_closed_and_revokes(self):
        self.bad_holder=True
        with self.assertRaises(ValueError):
            self.writer.issue_once()
        self.assertTrue(self.revoked)

    def test_invalid_policy_or_lease_duration_refuse_constructor(self):
        cfg=self.writer.client
        for bad in (0,2,121,False):
            with self.assertRaises(ValueError):
                cas.EtcdCasWriter("fleet-a",[
                    {"url":f"https://127.0.0.{n}:2379",
                     "leafSha256":str(n)*64,"memberId":n} for n in (1,2,3)],
                    999,cfg.ca,cfg.cert,cfg.key,NODES,7,POLICY,ttl=bad)


if __name__=="__main__":
    unittest.main()
