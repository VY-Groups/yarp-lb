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
        self.assertEqual(len(self.commands),8)
        self.assertIn("stop",self.commands[0])
        self.assertIn("mask",self.commands[1])
        self.assertIn("daemon-reload",self.commands[2])
        self.assertIn("show",self.commands[3])

    def test_remote_receiver_requires_two_real_signed_node_receipts(self):
        from types import SimpleNamespace
        import linux_dp_receive_restore as receiver
        inbox, state, app = (self.root/"inbox",self.root/"state",self.root/"app")
        for directory in (inbox,state,app):
            directory.mkdir(mode=0o700)
        first = gate.issue(self.fence,"gateway-a",("gatewaycore.service",),
                           self.keys["gateway-a"][0],
                           runner=self.run_child)
        second = gate.issue(self.fence,"gateway-b",("gatewaycore.service",),
                            self.keys["gateway-b"][0],
                            runner=self.run_child)
        sender_receipt=self.root/"sender.receipt"
        receiver_receipt=self.root/"receiver.receipt"
        for path,payload in ((sender_receipt,first),
                             (receiver_receipt,second)):
            path.write_bytes(payload)
            path.chmod(0o600)
        args=SimpleNamespace(
            destination_root=str(inbox),state_root=str(state),
            restore_bundle=str(app),
            sender_quiescence_receipt=str(sender_receipt),
            receiver_quiescence_receipt=str(receiver_receipt),
            sender_quiescence_public_key=self.keys["gateway-a"][1],
            receiver_quiescence_public_key=self.keys["gateway-b"][1],
            sender_writer_units=["gatewaycore.service"],
            receiver_writer_units=["gatewaycore.service"])
        proof=receiver.signed_node_quiescence(args,self.fence,loopback=False)
        receiver.require_signed_node_quiescence(proof,self.fence)
        receiver_receipt.write_bytes(b"forged signed witness")
        receiver_receipt.chmod(0o600)
        with self.assertRaises(ValueError):
            # Proof files are read afresh at the actual request boundary;
            # never accept stale already-read data for a NEW restore.
            bad=receiver.signed_node_quiescence(args,self.fence,loopback=False)
            receiver.require_signed_node_quiescence(bad,self.fence)
        args.receiver_quiescence_receipt=None
        with self.assertRaises(ValueError):
            receiver.signed_node_quiescence(args,self.fence,loopback=False)

    def test_wrong_rsa_signer_refused_before_any_service_stop(self):
        private = self.root/"wrong-rsa.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048",
                        "-out", str(private)], check=True, timeout=15,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        private.chmod(0o600)
        with self.assertRaises(ValueError):
            gate.issue(self.fence, "gateway-a", ("gatewaycore.service",),
                       str(private), runner=self.run_child, clock=lambda:NOW)
        self.assertEqual(self.commands, [],
                         "unapproved signing algorithm cannot stop service")

    def test_identical_p256_spki_with_different_pem_encoding_refused(self):
        a,b=self.receipt("gateway-a"),self.receipt("gateway-b")
        source=Path(self.keys["gateway-a"][1])
        reformatted=self.root/"different-newlines.pub"
        reformatted.write_bytes(source.read_bytes().replace(b"\n", b"\r\n"))
        reformatted.chmod(0o600)
        # The new file is a different inode and byte sequence, but the
        # same elliptic-curve public key. No duplicate witness authority.
        self.assertNotEqual(reformatted.read_bytes(), source.read_bytes())
        with self.assertRaises(ValueError):
            gate.verify_two_receipts(
                self.fence,a,b,
                sender_key=str(source),receiver_key=str(reformatted),
                sender_units=("gatewaycore.service",),
                receiver_units=("gatewaycore.service",),
                clock=lambda:NOW,runner=self.run_child)

    def test_non_p256_oid_inside_foreign_spki_never_counts_as_identity(self):
        # A non-P256 public-key SubjectPublicKeyInfo can contain P-256 OID
        # bytes in arbitrary public-key material. Scanning for OID substrings
        # (instead of strict DER AlgorithmIdentifier) falsely accepts it.
        p384 = self.root/"wrong-curve.key"
        subprocess.run(["openssl","ecparam","-name","secp384r1",
                        "-genkey","-noout","-out",str(p384)],
                       check=True,timeout=15,stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL)
        p384.chmod(0o600)
        output = subprocess.run([gate.OPENSSL,"pkey","-in",str(p384),
                                 "-pubout","-outform","DER"],
                                check=True,capture_output=True,timeout=15).stdout
        self.assertNotEqual(len(output), 91)
        oid=bytes.fromhex("06082A8648CE3D030107")
        # Even artificially embedding a second curve OID in a foreign
        # point's material cannot satisfy the canonical P-256 structure.
        contaminated=output[:-len(oid)]+oid
        self.assertIn(oid, contaminated)
        with self.assertRaises(ValueError):
            gate._validated_p256_spki(
                SimpleNamespace(returncode=0,stdout=contaminated))
        with self.assertRaises(ValueError):
            gate.issue(self.fence,"gateway-a",("gatewaycore.service",),
                       str(p384),runner=self.run_child,clock=lambda:NOW)
        self.assertEqual(self.commands,[],
                         "foreign-curve keys cannot stop production units")

    def test_malformed_spki_and_duplicate_point_encoding_refused(self):
        private=self.keys["gateway-a"][0]
        generated=subprocess.run([gate.OPENSSL,"pkey","-in",private,
                                  "-pubout","-outform","DER"],
                                 check=True,capture_output=True,timeout=15).stdout
        self.assertEqual(len(generated), 91)
        self.assertEqual(
            gate._validated_p256_spki(
                SimpleNamespace(returncode=0,stdout=generated)),
            __import__("hashlib").sha256(generated).digest())
        for untrusted in (generated + bytes([0]), generated[1:],
                          generated.replace(bytes.fromhex("03420004"),
                                            bytes.fromhex("03420104"), 1)):
            with self.subTest(value=len(untrusted)):
                with self.assertRaises(ValueError):
                    gate._validated_p256_spki(
                        SimpleNamespace(returncode=0,stdout=untrusted))

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
