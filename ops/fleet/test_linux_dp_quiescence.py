"""Real P-256 signed two-node systemd service-quiescence contracts (#48).

Disposable OpenSSL keys exercise actual cryptography. A deterministic
systemctl boundary simulates active/stop/mask/show fault injection; it does
not claim to be a real independently housed systemd service acceptance.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

import linux_dp_quiescence as gate

NOW = 1700000000
HOLDER = "a" * 32


class FakeFence:
    sender = "gateway-a"
    receiver = "gateway-b"
    revision = 43
    checkpoint_sha = "A"*64
    client = SimpleNamespace(fleet="fleet-ci")
    _identity = (999, 90, 456, HOLDER)

    def __init__(self):
        self.allowed = True
        self.remaining = 95

    def remaining_seconds(self):
        return self.remaining

    def current(self, phase):
        return self.allowed and phase in ("preflight", "before-transfer")


class TwoNodeQuiescenceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="dp-writer-quiescence-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.root.chmod(0o700)
        self.keys = {}
        for node in ("gateway-a","gateway-b"):
            private = self.root/(node+".key")
            public = self.root/(node+".pub")
            subprocess.run(["openssl","ecparam","-name","prime256v1",
                            "-genkey","-noout","-out",str(private)],
                           check=True, timeout=15, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            subprocess.run(["openssl","pkey","-in",str(private),
                            "-pubout","-out",str(public)],
                           check=True, timeout=15, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            private.chmod(0o600)
            public.chmod(0o600)
            self.keys[node]=(str(private),str(public))
        self.fence=FakeFence()
        self.state="masked-inactive"
        self.commands=[]

    def run_child(self, args, **kwargs):
        if args[0] != gate.SYSTEMCTL:
            return subprocess.run(args, **kwargs)
        self.commands.append(args)
        if args[-2] == "show":
            raise AssertionError("unexpected systemd argument order")
        if "show" in args:
            data=("LoadState=masked\nActiveState="+(
                "active" if self.state=="active" else "inactive")+
                "\nSubState="+("running" if self.state=="active" else "dead")+
                "\nMainPID="+("123" if self.state=="active" else "0")+
                "\nUnitFileState=masked-runtime\n")
            return SimpleNamespace(returncode=0,stdout=data.encode("ascii"))
        return SimpleNamespace(returncode=0,stdout=b"")

    def receipt(self, node):
        return gate.issue(self.fence,node,("gatewaycore.service",),
                          self.keys[node][0], runner=self.run_child,
                          clock=lambda:NOW)

    def test_actual_distinct_P256_quiescence_signatures_bound_to_one_epoch(self):
        a,b=self.receipt("gateway-a"),self.receipt("gateway-b")
        self.assertTrue(gate.verify_two_receipts(
            self.fence,a,b,
            sender_key=self.keys["gateway-a"][1],
            receiver_key=self.keys["gateway-b"][1],
            sender_units=("gatewaycore.service",),
            receiver_units=("gatewaycore.service",),
            clock=lambda:NOW,runner=self.run_child))
        self.assertEqual(len(self.commands),6)
        self.assertIn("stop",self.commands[0])
        self.assertIn("mask",self.commands[1])
        self.assertIn("show",self.commands[2])

    def test_no_quorum_refuses_before_any_systemd_change(self):
        self.fence.allowed=False
        with self.assertRaises(ValueError):
            self.receipt("gateway-a")
        self.assertEqual(self.commands,[])

    def test_active_writer_cannot_sign_receipt(self):
        self.state="active"
        with self.assertRaises(ValueError):
            self.receipt("gateway-a")
        self.assertTrue(any("show" in command for command in self.commands))

    def test_forged_or_replayed_node_identity_is_refused(self):
        a,b=self.receipt("gateway-a"),self.receipt("gateway-b")
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,a,
                sender_key=self.keys["gateway-a"][1],
                receiver_key=self.keys["gateway-b"][1],
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW,runner=self.run_child)
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,b,
                sender_key=self.keys["gateway-b"][1],
                receiver_key=self.keys["gateway-a"][1],
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW,runner=self.run_child)

    def test_expired_and_changed_epoch_refuse_before_restore(self):
        a,b=self.receipt("gateway-a"),self.receipt("gateway-b")
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,b,
                sender_key=self.keys["gateway-a"][1],
                receiver_key=self.keys["gateway-b"][1],
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW+120,runner=self.run_child)
        self.fence._identity=(999,91,987,"b"*32)
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,b,
                sender_key=self.keys["gateway-a"][1],
                receiver_key=self.keys["gateway-b"][1],
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW,runner=self.run_child)

    def test_duplicate_p256_public_key_cannot_act_as_both_nodes(self):
        a,b=self.receipt("gateway-a"),self.receipt("gateway-b")
        copy=self.root/"copied.pub"
        copy.write_bytes(Path(self.keys["gateway-a"][1]).read_bytes())
        copy.chmod(0o600)
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,b,
                sender_key=self.keys["gateway-a"][1],
                receiver_key=str(copy),
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW,runner=self.run_child)

    def test_unapproved_unit_or_command_rejected(self):
        with self.assertRaises(ValueError):
            gate.issue(self.fence,"gateway-a",
                ("../any.service",), self.keys["gateway-a"][0],
                runner=self.run_child,clock=lambda:NOW)
        with self.assertRaises(ValueError):
            gate.issue(self.fence,"gateway-a",
                ("z.service","a.service"), self.keys["gateway-a"][0],
                runner=self.run_child,clock=lambda:NOW)
        self.assertEqual(self.commands,[])


if __name__=="__main__":
    unittest.main()
