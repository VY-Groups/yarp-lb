"""Fail-closed disposable etcd authority contracts for signed Linux DP recovery.

Mocked etcd network; real three-member TLS/partition and actual .NET signed
restore remain separate software acceptance gates. No production identities.
"""
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from ops.fleet import linux_dp_quorum_authority as dp

SENDER, RECEIVER = "gateway-a", "gateway-b"
CHECKPOINT = "A" * 64


class RecoveryAuthorityTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="dp-fleet-fence-test-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        root.chmod(0o700)
        tls = [root / name for name in ("ca.pem", "client.pem", "client.key")]
        for path in tls:
            path.write_text("DISPOSABLE MOCK TLS TEST ONLY", encoding="ascii")
            path.chmod(0o600)
        self.endpoints = [
            {"url":f"https://127.0.0.{i}:2379",
             "leafSha256":str(i)*64, "memberId":i}
            for i in (1, 2, 3)]
        self.params = ("fleet-ci", self.endpoints, 999,
                       *map(str, tls), SENDER, RECEIVER, 43, CHECKPOINT)
        self.issuer = dp.RecoveryLeaseIssuer(*self.params)
        self.disconnected = set()
        self.forge_member = None
        self.active = False
        self.cas_competition = False
        self.changed_checkpoint = False
        self.wrong_key = False
        self.ttl = 101
        self.lease = 456
        self.holder = None
        self.grants = self.txns = self.revocations = 0
        self.issued = None
        self.pointer = None
        self.pointer_mod = 0
        self.publication_race = False
        self.publication_count = 0

        def fake_post(endpoint, resource, body):
            m = endpoint[3]
            if m in self.disconnected:
                raise OSError("synthetic partition")
            header = {"cluster_id":"999", "member_id":str(
                1 if self.forge_member == m else m), "revision":"100"}
            if resource == "/v3/kv/range":
                self.assertIs(body["serializable"], False)
                if body["key"] != self.issuer.key:
                    self.assertEqual(body["key"], dp.as_base64(
                        b"/gatewaycore/linux-dp/published/fleet-ci"))
                    data = {"header": dict(header, revision=str(max(100,self.pointer_mod)))}
                    if self.pointer is not None:
                        data.update(count="1", kvs=[{
                            "key": body["key"], "value": self.pointer,
                            "mod_revision": str(self.pointer_mod), "version": "1"
                        }])
                    return data
                data = {"header": header}
                if self.active:
                    value = dict(self.issued)
                    if self.changed_checkpoint and m == 3:
                        value["checkpointSha256"] = "B" * 64
                    data["count"] = "1"
                    data["kvs"] = [{
                        "key": dp.as_base64((
                            "/gatewaycore/waf/fence/fleet-ci" if self.wrong_key
                            else self.issuer.key_name).encode("ascii")),
                        "value":dp.as_base64(json.dumps(
                            value, separators=(",", ":")).encode("ascii")),
                        "mod_revision":"90","version":"1",
                        "lease":str(self.lease)
                    }]
                return data
            if resource == "/v3/lease/grant":
                self.grants += 1
                self.assertEqual(body["TTL"], "120")
                return {"ID":str(self.lease), "TTL":"120"}
            if resource == "/v3/kv/txn":
                if len(body["compare"]) == 3:
                    self.publication_count += 1
                    lease_mod, lease_id, previous = body["compare"]
                    self.assertEqual(lease_mod, {"result":"EQUAL", "target":"MOD",
                        "key":self.issuer.key, "modRevision":"90"})
                    self.assertEqual(lease_id, {"result":"EQUAL", "target":"LEASE",
                        "key":self.issuer.key, "lease":str(self.lease)})
                    put = body["success"][0]["requestPut"]
                    self.assertEqual(put["key"], previous["key"])
                    self.assertNotIn("lease", put)
                    if self.publication_race:
                        self.active = False
                    if not self.active or self.pointer_mod != int(previous.get(
                            "modRevision",previous.get("createRevision"))):
                        return {"header":header,"succeeded":False}
                    self.pointer = put["value"]
                    self.pointer_mod = 101
                    return {"header":dict(header, revision="101"),"succeeded":True}
                self.txns += 1
                self.assertEqual(body["compare"][0]["createRevision"],"0")
                self.assertEqual(body["success"][0]["requestPut"]["lease"],
                                 str(self.lease))
                self.assertEqual(body["success"][0]["requestPut"]["key"],
                                 self.issuer.key)
                if self.cas_competition:
                    return {"header":header, "succeeded":False}
                self.issued = json.loads(base64.b64decode(
                    body["success"][0]["requestPut"]["value"]))
                self.holder = self.issued["holder"]
                self.active = True
                return {"header":header, "succeeded":True}
            if resource == "/v3/lease/timetolive":
                self.assertEqual(body["ID"],str(self.lease))
                return {"ID":str(self.lease),"TTL":str(self.ttl),
                        "grantedTTL":"120"}
            if resource == "/v3/lease/revoke":
                self.revocations += 1
                self.assertEqual(body["ID"],str(self.lease))
                self.active = False
                return {}
            raise AssertionError("unexpected etcd RPC")
        patch = mock.patch.object(self.issuer.client, "_post",
                                  side_effect=fake_post)
        patch.start()
        self.addCleanup(patch.stop)

    def test_one_shot_lease_issues_only_for_exact_signed_checkpoint(self):
        result = self.issuer.issue_once()
        self.assertEqual(result["checkpointSha256"], CHECKPOINT)
        self.assertEqual(result["leaseId"],456)
        self.assertEqual(result["senderNodeId"],SENDER)
        self.assertEqual(result["receiverNodeId"],RECEIVER)
        self.assertEqual(result["holder"], self.holder)
        self.assertEqual(self.grants,1)
        self.assertTrue(self.issuer.current("before-transfer"))
        self.assertTrue(self.issuer.current("before-signed-restore"))
        self.assertTrue(self.issuer.current("after-signed-restore"))
        self.assertEqual(self.issuer.key_name,
                         "/gatewaycore/linux-dp/recovery/fleet-ci")
        self.assertNotIn("waf", self.issuer.key_name)
        self.assertEqual(self.revocations,0)

    def test_existing_epoch_never_overwritten_or_stolen(self):
        self.active = True
        self.issued = {"schemaVersion":1,"kind":"linux-dp",
                       "senderNodeId":SENDER,"receiverNodeId":RECEIVER,
                       "revision":43,"checkpointSha256":CHECKPOINT,
                       "holder":"f"*32}
        with self.assertRaises(ValueError):
            self.issuer.issue_once()
        self.assertEqual(self.grants,0)
        self.assertEqual(self.txns,0)
        self.assertEqual(self.revocations,0)

    def test_competing_cas_failure_revokes_only_new_lease(self):
        self.cas_competition = True
        with self.assertRaises(ValueError):
            self.issuer.issue_once()
        self.assertEqual(self.txns,1)
        self.assertEqual(self.revocations,1)

    def test_missing_quorum_fails_closed_before_any_write(self):
        self.disconnected.update({2,3})
        with self.assertRaises(ValueError):
            self.issuer.issue_once()
        self.assertEqual(self.grants,0)
        self.assertFalse(self.issuer.current("preflight"))

    def test_authenticated_member_spoof_vetoes_even_with_two_good(self):
        self.forge_member = 3
        with self.assertRaises(ValueError):
            self.issuer.issue_once()
        self.assertEqual(self.grants,0)

    def test_mutation_after_initial_epoch_revocation_is_refused(self):
        self.issuer.issue_once()
        self.assertTrue(self.issuer.current("before-transfer"))
        self.active = False
        self.assertFalse(self.issuer.current("before-signed-restore"))
        self.assertFalse(self.issuer.current("after-signed-restore"))

    def test_conflicting_checkpoint_or_waf_namespace_fails_closed(self):
        self.issuer.issue_once()
        self.changed_checkpoint = True
        self.assertFalse(self.issuer.current("before-signed-restore"))
        self.changed_checkpoint = False
        self.wrong_key = True
        self.assertFalse(self.issuer.current("after-signed-restore"))

    def test_short_remaining_lease_does_not_authorize_restore(self):
        self.issuer.issue_once()
        self.ttl = 3
        self.assertFalse(self.issuer.current("before-signed-restore"))
        self.assertFalse(self.issuer.current("after-signed-restore"))

    def publisher(self):
        publisher = dp.RecoveryRevisionPublisher(*self.params)
        publisher.client._post = self.issuer.client._post
        return publisher

    def test_durable_publication_is_atomically_bound_to_live_epoch(self):
        self.issuer.issue_once()
        publisher = self.publisher()
        result = publisher.publish_once()
        self.assertEqual(result["revision"],43)
        self.assertEqual(result["checkpointSha256"],CHECKPOINT)
        self.assertEqual(result["recoveryModRevision"],90)
        self.assertEqual(self.publication_count,1)
        self.assertEqual(json.loads(base64.b64decode(self.pointer)),result)
        with self.assertRaises(ValueError):
            publisher.publish_once()
        self.assertEqual(self.publication_count,1)

    def test_revocation_between_last_observation_and_cas_cannot_publish(self):
        self.issuer.issue_once()
        self.publication_race = True
        with self.assertRaises(ValueError):
            self.publisher().publish_once()
        self.assertEqual(self.publication_count,1)
        self.assertIsNone(self.pointer)

    def test_partition_before_publication_never_calls_cas(self):
        self.issuer.issue_once()
        self.disconnected.update({2,3})
        with self.assertRaises(ValueError):
            self.publisher().publish_once()
        self.assertEqual(self.publication_count,0)

    def test_runtime_append_is_atomic_and_create_only(self):
        name = "key-11111111-2222-3333-4444-555555555555.xml"
        raw = ('<key id="11111111-2222-3333-4444-555555555555">'
               '<encryptedSecret xmlns="http://schemas.asp.net/2015/03/dataProtection" '
               'decryptorType="Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor, Microsoft.AspNetCore.DataProtection">'
               '<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">'
               '<CipherData><CipherValue>fixture-only</CipherValue></CipherData>'
               '</EncryptedData></encryptedSecret></key>').encode()
        writer = dp.RuntimeEncryptedRingWriter(*self.params, node_id=SENDER)
        self.assertNotEqual(writer.key_name,self.issuer.key_name)
        with self.assertRaises(ValueError):
            dp.RuntimeEncryptedRingWriter(*self.params,node_id=RECEIVER)
        writer._identity = (999,90,456,"a"*32)
        with mock.patch.object(writer,"current",return_value=True), \
                mock.patch.object(writer,"remaining_seconds",return_value=90), \
                mock.patch.object(writer.client,"_post",return_value={
                    "header":{"cluster_id":"999","member_id":"1","revision":"101"},
                    "succeeded":True}) as post:
            self.assertEqual(writer.append_once(name,raw),101)
            body=post.call_args.args[2]
            self.assertEqual([x["target"] for x in body["compare"]],
                             ["MOD","LEASE","CREATE"])
            self.assertEqual(body["compare"][1]["lease"],"456")
            put=body["success"][0]["requestPut"]
            self.assertEqual(base64.b64decode(put["value"]),raw)
            self.assertNotIn("lease",put)
            post.return_value={"header":{"cluster_id":"999","member_id":"1"},
                               "succeeded":False}
            with self.assertRaises(ValueError):
                writer.append_once(name,raw)
            calls=post.call_count
            with self.assertRaises(ValueError):
                writer.append_once(name,b"<key><masterKey>plaintext</masterKey></key>")
            self.assertEqual(post.call_count,calls)

    def test_runtime_handoff_atomically_replaces_exact_old_epoch(self):
        old=dp.RuntimeWriterLeaseIssuer(*self.params)
        successor=dp.RuntimeWriterLeaseIssuer(*self.params[:6],
            RECEIVER,SENDER,44,CHECKPOINT)
        receipt={"schemaVersion":1,"kind":"linux-dp","senderNodeId":SENDER,
                 "receiverNodeId":RECEIVER,"revision":43,
                 "checkpointSha256":CHECKPOINT,"holder":"a"*32,
                 "leaseId":456,"raftModRevision":90,"ttlSeconds":120}
        old._identity=(999,90,456,"a"*32)
        def post(endpoint,resource,body):
            if resource=="/v3/lease/grant":
                return {"ID":"789","TTL":"120"}
            self.assertEqual(resource,"/v3/kv/txn")
            self.assertEqual([x["target"] for x in body["compare"]],["MOD","LEASE"])
            self.assertEqual(body["compare"][0]["modRevision"],"90")
            self.assertEqual(body["compare"][1]["lease"],"456")
            put=body["success"][0]["requestPut"]
            self.assertEqual(put["lease"],"789")
            record=json.loads(base64.b64decode(put["value"]))
            successor._identity=(999,101,789,record["holder"])
            return {"header":{"cluster_id":"999","member_id":"1","revision":"101"},
                    "succeeded":True}
        with mock.patch.object(old,"current",return_value=True), \
                mock.patch.object(old,"remaining_seconds",return_value=90), \
                mock.patch.object(successor,"current",return_value=True), \
                mock.patch.object(successor.client,"_post",side_effect=post):
            result=dp.RuntimeWriterHandoff(old,successor,receipt).replace_once()
            self.assertEqual(result["senderNodeId"],RECEIVER)
            self.assertEqual(result["leaseId"],789)
            self.assertEqual(result["raftModRevision"],101)
        with self.assertRaises(ValueError):
            dp.RuntimeWriterHandoff(old,successor,dict(receipt,holder="wrong"))

    def test_runtime_handoff_contest_only_revokes_new_grant(self):
        old=dp.RuntimeWriterLeaseIssuer(*self.params)
        successor=dp.RuntimeWriterLeaseIssuer(*self.params[:6],
            SENDER,RECEIVER,44,CHECKPOINT)
        receipt={"schemaVersion":1,"kind":"linux-dp","senderNodeId":SENDER,
                 "receiverNodeId":RECEIVER,"revision":43,
                 "checkpointSha256":CHECKPOINT,"holder":"a"*32,
                 "leaseId":456,"raftModRevision":90}
        old._identity=(999,90,456,"a"*32)
        with mock.patch.object(old,"current",return_value=True), \
                mock.patch.object(old,"remaining_seconds",return_value=90), \
                mock.patch.object(successor.client,"_post",side_effect=[
                    {"ID":"789","TTL":"120"},
                    {"header":{"cluster_id":"999","member_id":"1","revision":"101"},
                     "succeeded":False}]), \
                mock.patch.object(successor,"_revoke") as revoke:
            with self.assertRaises(ValueError):
                dp.RuntimeWriterHandoff(old,successor,receipt).replace_once()
            revoke.assert_called_once_with(successor.client.endpoints[0],789)

    def test_disallowed_phase_and_identity_fail_without_network(self):
        self.assertFalse(self.issuer.current("before-transfer"))
        self.assertFalse(self.issuer.current("emergency-override"))
        for names in ((SENDER,SENDER),("UNSAFE",RECEIVER)):
            with self.assertRaises(ValueError):
                dp.RecoveryLeaseIssuer("fleet-ci", self.endpoints,999,
                    *self.params[3:6], names[0],names[1],43,CHECKPOINT)
        with self.assertRaises(ValueError):
            dp.RecoveryLeaseIssuer(*self.params, ttl=2)


if __name__ == "__main__":
    unittest.main()
