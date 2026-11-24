"""Real localhost mutual-TLS and bounded offline ciphertext-transfer acceptance.

All certificates are generated solely within a disposable private tempdir.
No live fleet, plaintext DP key, production backup, or production network.
"""
import hashlib
import io
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import subprocess
import tempfile
import threading
import unittest
import zipfile

import linux_dp_mtls_transport as tx

DUMMY_KEY = "key-11111111-2222-3333-4444-555555555555.xml"
DUMMY_XML = b'<key id="11111111-2222-3333-4444-555555555555"><encryptedSecret xmlns="http://schemas.asp.net/2015/03/dataProtection" decryptorType="Dummy Test Only">ciphertext</encryptedSecret></key>'
DUMMY_CHECKPOINT = b'{"Version":1,"Revision":9,"InventorySha256":"fixture-only"}'


def run(*args):
    result = subprocess.run(["openssl", *args], check=False,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL, timeout=20)
    if result.returncode != 0:
        raise AssertionError("disposable OpenSSL identity creation failed")


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dp-mtls-acceptance-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.source = self.root/"source"
        self.source.mkdir(mode=0o700)
        self.snapshot = self.source/"rev9"
        self.snapshot.mkdir(mode=0o700)
        self.key = self.snapshot/DUMMY_KEY
        self.key.write_bytes(DUMMY_XML)
        self.key.chmod(0o600)
        self.checkpoint_dir = self.root/"signed-source"
        self.checkpoint_dir.mkdir(mode=0o700)
        self.checkpoint = self.checkpoint_dir/"checkpoint.json"
        self.checkpoint.write_bytes(DUMMY_CHECKPOINT)
        self.checkpoint.chmod(0o600)
        self.destination = self.root/"destination"
        self.destination.mkdir(mode=0o700)

    def identities(self):
        ca = self.root/"ca.pem"
        ca_key = self.root/"ca.key"
        run("req","-x509","-new","-nodes","-newkey","rsa:2048",
            "-sha256","-days","1","-subj","/CN=Disposable Data Protection Transfer CA",
            "-keyout",str(ca_key),"-out",str(ca))
        certs={}
        for name, usage in (("server","serverAuth"),("client","clientAuth"),
                            ("other-client","clientAuth")):
            key=self.root/(name+".key")
            csr=self.root/(name+".csr")
            crt=self.root/(name+".pem")
            ext=self.root/(name+".ext")
            ext.write_text(("extendedKeyUsage="+usage+"\n"+
                           ("subjectAltName=IP:127.0.0.1\n" if usage=="serverAuth" else "")+
                           "keyUsage=digitalSignature,keyEncipherment\n"),encoding="ascii")
            run("req","-new","-nodes","-newkey","rsa:2048",
                "-subj","/CN="+name,"-keyout",str(key),"-out",str(csr))
            run("x509","-req","-in",str(csr),"-CA",str(ca),"-CAkey",
                str(ca_key),"-CAcreateserial","-out",str(crt),"-days","1",
                "-sha256","-extfile",str(ext))
            key.chmod(0o600)
            der=subprocess.run(["openssl","x509","-in",str(crt),"-outform","DER"],
                               check=True,capture_output=True,timeout=10).stdout
            certs[name]=(str(crt),str(key),hashlib.sha256(der).hexdigest().upper())
        ca_key.chmod(0o600)
        return str(ca),certs

    def test_private_source_and_nonoverwriting_atomic_transfer(self):
        bundle = tx.build_bundle(str(self.source),"rev9",str(self.checkpoint))
        self.assertEqual(tx.verify_bundle(bundle)["ring/"+DUMMY_KEY],DUMMY_XML)
        self.assertEqual(tx.verify_bundle(bundle)["checkpoint.json"],DUMMY_CHECKPOINT)
        path=tx.stage_received(str(self.destination),"rev9",bundle)
        self.assertEqual((Path(path)/"ring"/DUMMY_KEY).read_bytes(),DUMMY_XML)
        self.assertEqual((Path(path)/"checkpoint.json").read_bytes(),DUMMY_CHECKPOINT)
        self.assertEqual(stat.S_IMODE((Path(path)/"ring"/DUMMY_KEY).stat().st_mode),0o600)
        self.assertEqual(stat.S_IMODE((Path(path)/"ring").stat().st_mode),0o700)
        with self.assertRaises(ValueError):
            tx.stage_received(str(self.destination),"rev9",bundle)
        self.assertEqual((Path(path)/"ring"/DUMMY_KEY).read_bytes(),DUMMY_XML)
        self.assertEqual(list(self.destination.glob(".dp-recv-*")),[])
        self.assertTrue(tx.HEX_SHA.fullmatch(hashlib.sha256(bundle).hexdigest().upper()))

    def test_reject_symlink_and_nonprivate_source_and_noncanonical_label(self):
        for label in ("..","../rev9","X","a b","rev/9","a"*49):
            with self.subTest(label=label),self.assertRaises(ValueError):
                tx.build_bundle(str(self.source),label,str(self.checkpoint))
        link=self.source/"alias"
        link.symlink_to(self.snapshot, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            tx.build_bundle(str(self.source),"alias",str(self.checkpoint))
        link.unlink()
        self.key.chmod(0o644)
        with self.assertRaises(ValueError):
            tx.build_bundle(str(self.source),"rev9",str(self.checkpoint))
        self.key.chmod(0o600)
        self.checkpoint.chmod(0o644)
        with self.assertRaises(ValueError):
            tx.build_bundle(str(self.source),"rev9",str(self.checkpoint))
        self.checkpoint.chmod(0o600)
        self.assertEqual(len(tx.verify_bundle(tx.build_bundle(
            str(self.source),"rev9",str(self.checkpoint)))),2)

    def test_no_zip_symlinks_duplicate_traversal_compression_or_bomb(self):
        for name in ("ring/../../secret.xml","/root/private.xml",
                     "ring/wrong.JSON","ring/"):
            with self.subTest(name=name):
                stream=io.BytesIO()
                with zipfile.ZipFile(stream,"w") as arch:
                    arch.writestr("checkpoint.json",DUMMY_CHECKPOINT)
                    arch.writestr(name,b"not an approved XML")
                with self.assertRaises(ValueError):
                    tx.verify_bundle(stream.getvalue())
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as arch:
            arch.writestr("checkpoint.json",DUMMY_CHECKPOINT)
            arch.writestr("ring/"+DUMMY_KEY,DUMMY_XML)
            arch.writestr("ring/"+DUMMY_KEY,b"duplicate")
        with self.assertRaises(ValueError):
            tx.verify_bundle(stream.getvalue())
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as arch:
            arch.writestr("checkpoint.json",DUMMY_CHECKPOINT)
            arch.writestr("ring/"+DUMMY_KEY,DUMMY_XML)
            arch.writestr("ring/"+DUMMY_KEY.upper().replace(".XML",".xml"),DUMMY_XML)
        with self.assertRaises(ValueError):
            tx.verify_bundle(stream.getvalue())
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,"w") as arch:
            arch.writestr("checkpoint.json",DUMMY_CHECKPOINT)
            meta=zipfile.ZipInfo("ring/"+DUMMY_KEY)
            meta.create_system=3
            meta.external_attr=(stat.S_IFLNK | 0o777)<<16
            arch.writestr(meta,b"/private/key")
        with self.assertRaises(ValueError):
            tx.verify_bundle(stream.getvalue())
        self.assertRaises(ValueError,tx.verify_bundle,b"x"*(tx.MAX_BUNDLE+1))

    def test_real_tls_client_cert_server_cert_pins_and_read_only_method(self):
        ca, identities=self.identities()
        server_cert,server_key,server_pin=identities["server"]
        client_cert,client_key,client_pin=identities["client"]
        other_cert,other_key,_=identities["other-client"]
        bundle=tx.build_bundle(str(self.source),"rev9",str(self.checkpoint))
        srv=tx.make_server("127.0.0.1",0,bundle,"rev9",client_pin,
                           ca,server_cert,server_key)
        thread=threading.Thread(target=srv.serve_forever,
                                kwargs={"poll_interval":.02},daemon=True)
        thread.start()
        self.addCleanup(lambda: (srv.shutdown(),srv.server_close(),thread.join(5)))
        target="https://127.0.0.1:"+str(srv.server_port)
        exact=tx.fetch_pinned(target,"rev9",server_pin,ca,client_cert,client_key)
        self.assertEqual(exact,bundle)
        staged=tx.stage_received(str(self.destination),"rev9",exact)
        self.assertTrue((Path(staged)/"checkpoint.json").is_file())
        with self.assertRaises(ValueError):
            tx.fetch_pinned(target,"rev9","0"*64,ca,client_cert,client_key)
        with self.assertRaises(ValueError):
            tx.fetch_pinned(target,"rev9",server_pin,ca,other_cert,other_key)
        with self.assertRaises(ValueError):
            tx.fetch_pinned(target,"rev8",server_pin,ca,client_cert,client_key)
        with self.assertRaises(ValueError):
            tx.fetch_pinned("http://127.0.0.1:"+str(srv.server_port),
                            "rev9",server_pin,ca,client_cert,client_key)
        with self.assertRaises(ValueError):
            tx.make_server("0.0.0.0",0,bundle,"rev9",client_pin,
                           ca,server_cert,server_key)

    def test_invalid_cert_key_or_client_pin_cannot_start_relay(self):
        ca, identities=self.identities()
        server_cert,server_key,_=identities["server"]
        client_pin=identities["client"][2]
        bundle=tx.build_bundle(str(self.source),"rev9",str(self.checkpoint))
        with self.assertRaises(ValueError):
            tx.make_server("127.0.0.1",0,bundle,"rev9","INVALID",
                           ca,server_cert,server_key)
        Path(server_key).chmod(0o644)
        with self.assertRaises(ValueError):
            tx.make_server("127.0.0.1",0,bundle,"rev9",client_pin,
                           ca,server_cert,server_key)
        Path(server_key).chmod(0o600)
        srv=tx.make_server("127.0.0.1",0,bundle,"rev9",client_pin,
                           ca,server_cert,server_key)
        srv.server_close()


if __name__ == "__main__":
    unittest.main()
