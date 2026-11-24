"""Real localhost pinned mutual TLS WAF node enforcement and compensation.

Disposable OpenSSL identities, fake local WAF provider; no production cluster
or Docker/site traffic. The independent node agent rejects a vanished lease.
"""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

import mtls_fenced_node as remote
import two_node_transaction as tx


IMAGE = "sha256:" + "a" * 64
RULES = "A" * 64
POLICY = "B" * 64
NODES = ("node-a", "node-b")


class FakeFence:
    def __init__(self):
        self.calls = []
        self.denied = set()

    def assert_current(self, names, revision, digest, phase):
        self.calls.append(phase)
        return (names == NODES and revision == 7 and digest == POLICY
                and phase not in self.denied)


class FakeWaf:
    def __init__(self):
        self.mode = "detect"
        self.applies = []
        self.fail_after = None

    def inspect(self):
        return {"mode": self.mode, "imageId": IMAGE}

    def image_and_config(self, mode):
        if mode not in ("detect", "block"):
            raise ValueError("invalid mode")
        return IMAGE

    def observed_rule_digest(self):
        return RULES

    def smoke(self, mode):
        if mode != self.mode:
            raise ValueError("wrong local smoke state")

    def apply(self, mode):
        self.mode = mode
        self.applies.append(mode)
        if self.fail_after == mode:
            raise ValueError("injected post-mutation failure")


def openssl(*cmd):
    response = subprocess.run(["openssl", *cmd], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, check=False, timeout=30)
    if response.returncode:
        raise RuntimeError("disposable OpenSSL certificate generation failed")


class NodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="waf-node-mtls-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.ca, self.cert = self.identities()
        self.servers = []

    def identities(self):
        ca, ca_key = self.root / "root.pem", self.root / "root.key"
        openssl("req", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-sha256", "-days", "1", "-subj", "/CN=Disposable WAF Node CA",
                "-keyout", str(ca_key), "-out", str(ca))
        certs = {}
        for name in ("server-a", "server-b", "client", "intruder"):
            key, csr = self.root / (name+".key"), self.root / (name+".csr")
            pem, ext = self.root / (name+".pem"), self.root / (name+".ext")
            usage = "serverAuth" if name.startswith("server-") else "clientAuth"
            ext.write_text("extendedKeyUsage="+usage+"\n"+
                           ("subjectAltName=IP:127.0.0.1\n"
                            if usage == "serverAuth" else "")+
                           "keyUsage=digitalSignature,keyEncipherment\n",
                           encoding="ascii")
            openssl("req", "-new", "-nodes", "-newkey", "rsa:2048",
                    "-subj", "/CN="+name, "-keyout", str(key), "-out", str(csr))
            openssl("x509", "-req", "-in", str(csr), "-CA", str(ca),
                    "-CAkey", str(ca_key), "-CAcreateserial", "-out",
                    str(pem), "-days", "1", "-sha256", "-extfile", str(ext))
            key.chmod(0o600)
            raw = subprocess.run(["openssl", "x509", "-in", str(pem),
                                  "-outform", "DER"], check=True,
                                 capture_output=True, timeout=10).stdout
            certs[name] = (str(pem), str(key),
                           hashlib.sha256(raw).hexdigest().upper())
        ca_key.chmod(0o600)
        return str(ca), certs

    def node(self, name):
        idx = "a" if name == "node-a" else "b"
        folder = self.root / name
        folder.mkdir(mode=0o700)
        fence, waf = FakeFence(), FakeWaf()
        agent = remote.FencedAgent(name, NODES, 7, POLICY, RULES, "block",
                                  waf, fence, folder)
        server_cert, server_key, server_pin = self.cert["server-"+idx]
        client_cert, client_key, client_pin = self.cert["client"]
        server = remote.serve(agent, "127.0.0.1", 0, self.ca,
                              server_cert, server_key, client_pin)
        thread = threading.Thread(target=server.serve_forever,
                                  kwargs={"poll_interval":.02}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(),
                                 thread.join(4)))
        url = "https://127.0.0.1:" + str(server.server_port)
        client = remote.RemoteNodeProvider(name, url, server_pin, self.ca,
                                           client_cert, client_key)
        return agent, client, fence, waf, url

    def test_real_mtls_node_side_lease_and_replay(self):
        agent, client, fence, waf, url = self.node("node-a")
        self.assertEqual(client.inspect(), {"mode":"detect", "imageId":IMAGE})
        self.assertEqual(client.observed_rule_digest(), RULES)
        self.assertEqual(client.image_and_config("block"), IMAGE)
        client.smoke("detect")
        fence.denied.add("before-apply-node-a")
        with self.assertRaises(ValueError):
            client.apply("block")
        self.assertEqual(waf.applies, [])
        fence.denied.clear()
        client.apply("block")
        self.assertEqual(waf.mode, "block")
        self.assertTrue((agent.dir/"rev-7-activate.intent").exists())
        self.assertTrue((agent.dir/"rev-7-activate.receipt").exists())
        with self.assertRaises(ValueError):
            client.apply("block")
        fence.denied.add("rollback-node-a")
        with self.assertRaises(ValueError):
            client.apply("detect")
        self.assertEqual(waf.mode, "block")
        fence.denied.clear()
        client.apply("detect")
        self.assertEqual(waf.mode, "detect")
        self.assertEqual(waf.applies, ["block", "detect"])
        self.assertIn("before-apply-node-a", fence.calls)
        self.assertIn("rollback-node-a", fence.calls)

    def test_second_process_operator_lock_refuses_concurrent_mutation(self):
        agent, client, fence, waf, _ = self.node("node-a")
        with remote.local.operator_lock(agent.dir):
            with self.assertRaises(ValueError):
                client.apply("block")
        self.assertEqual(waf.applies, [])
        self.assertFalse((agent.dir/"rev-7-activate.intent").exists())
        client.apply("block")
        self.assertEqual(waf.applies, ["block"])

    def test_wrong_tls_pin_client_cert_and_node_identity_rejected(self):
        _, client, _, waf, url = self.node("node-a")
        client_cert, client_key, _ = self.cert["client"]
        with self.assertRaises(ValueError):
            remote.RemoteNodeProvider("node-a",url,"0"*64,self.ca,
                                      client_cert,client_key).inspect()
        with self.assertRaises(ValueError):
            remote.RemoteNodeProvider("node-b",url,self.cert["server-a"][2],
                                      self.ca,client_cert,client_key).inspect()
        intruder_cert,intruder_key,_ = self.cert["intruder"]
        with self.assertRaises((ValueError,OSError)):
            remote.RemoteNodeProvider("node-a",url,self.cert["server-a"][2],
                                      self.ca,intruder_cert,intruder_key).inspect()
        self.assertEqual(waf.applies, [])

    def test_two_real_https_agents_compensate_after_other_node_fence_loss(self):
        _, a, af, aw, _ = self.node("node-a")
        _, b, bf, bw, _ = self.node("node-b")
        bf.denied.add("before-apply-node-b")
        output = self.root/"fleet-receipt.json"
        with self.assertRaises(ValueError):
            tx.coordinate({"node-a":a,"node-b":b}, "block", 7,
                          POLICY, RULES, output, fence=FakeFence())
        self.assertEqual(aw.mode, "detect")
        self.assertEqual(bw.mode, "detect")
        self.assertEqual(aw.applies, ["block", "detect"])
        self.assertFalse(output.exists())
        self.assertTrue((self.root/".fleet-receipt.json.failure").exists())
        self.assertIn("rollback-node-a", af.calls)
        self.assertIn("before-apply-node-b", bf.calls)

    def test_alias_remote_endpoint_and_forged_node_mapping_refused(self):
        _, client, _, _, _ = self.node("node-a")
        other_cert, other_key, _ = self.cert["client"]
        duplicate = remote.RemoteNodeProvider(
            "node-b", "https://"+client.host+":"+str(client.port),
            client.server_pin, self.ca, other_cert, other_key)
        with self.assertRaisesRegex(ValueError, "independent"):
            tx.coordinate({"node-a":client,"node-b":duplicate}, "block", 7,
                          POLICY, RULES, self.root/"dup.json", fence=FakeFence())
        with self.assertRaisesRegex(ValueError, "identity"):
            tx.coordinate({"node-a":duplicate,"node-b":client}, "block", 7,
                          POLICY, RULES, self.root/"wrong.json", fence=FakeFence())


if __name__ == "__main__":
    unittest.main()
