"""Actual OpenSSL recipient-specific credential delivery; disposable only."""
import os
from pathlib import Path
import tempfile
import unittest

import linux_dp_wrap_delivery as delivery


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="dp-wrap-delivery-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.root.chmod(0o700)
        def identity(name,usage,ec=False):
            key=self.root/(name+".key")
            cert=self.root/(name+".pem")
            alg=["-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1"] if ec else ["-newkey","rsa:2048"]
            delivery.openssl(["req","-x509","-nodes",*alg,"-days","2",
                "-subj","/CN="+name,"-addext","basicConstraints=critical,CA:FALSE",
                "-addext","keyUsage=critical,"+usage,"-keyout",str(key),"-out",str(cert)])
            key.chmod(0o600);cert.chmod(0o600)
            raw=cert.read_bytes()
            pin=delivery.digest(delivery.openssl(["x509","-outform","DER"],raw))
            return raw,key.read_bytes(),pin,cert,key
        self.signer=identity("signer","digitalSignature",True)
        self.receiver=identity("node-a","keyEncipherment")
        self.other=identity("node-b","keyEncipherment")
        self.wrapper=identity("wrapper","keyEncipherment")
        self.password=b"fixture-only-wrapping-password"
        with delivery.memory_files(self.password+b"\n") as (fds,_):
            self.pfx=delivery.openssl(["pkcs12","-export","-in",str(self.wrapper[3]),
                "-inkey",str(self.wrapper[4]),"-passout","fd:"+str(fds[0])],fds=fds)
        self.approval=delivery.metadata("fleet-ci","node-a",43,self.signer[2],
                                       self.receiver[2],self.wrapper[2])

    def sealed(self):
        return delivery.seal(self.approval,self.pfx,self.password,
            self.signer[0],self.signer[1],self.receiver[0])

    def opened(self,envelope,approval=None,recipient=None,key=None):
        return delivery.open_envelope(approval or self.approval,envelope,
            self.signer[0],recipient or self.receiver[0],key or self.receiver[1])

    def test_actual_envelope_recipient_binding_and_atomic_delivery(self):
        envelope=self.sealed()
        self.assertNotIn(self.password,envelope)
        self.assertNotIn(self.pfx,envelope)
        pfx,password=self.opened(envelope)
        self.assertEqual(pfx,self.pfx)
        self.assertEqual(password,self.password)
        destination=self.root/"received";destination.mkdir(mode=0o700)
        entries={"wrapper.pfx":pfx,"wrapper.password":password+b"\n"}
        target=Path(delivery.publish(str(destination),self.approval,entries))
        self.assertEqual((target/"wrapper.pfx").read_bytes(),self.pfx)
        self.assertEqual((target/"wrapper.password").stat().st_mode&0o777,0o600)
        self.assertEqual(target.stat().st_mode&0o777,0o700)
        with self.assertRaises(ValueError):
            delivery.publish(str(destination),self.approval,entries)
        self.assertEqual(list(destination.iterdir()),[target])

    def test_signature_recipient_revision_and_wrapping_pin_fail_closed(self):
        envelope=self.sealed()
        corrupted=bytearray(envelope);corrupted[len(corrupted)//2]^=1
        with self.assertRaises(ValueError):
            self.opened(bytes(corrupted))
        with self.assertRaises(ValueError):
            self.opened(envelope,key=self.other[1])
        wrong=dict(self.approval,recipient="node-b",recipientSha256=self.other[2])
        with self.assertRaises(ValueError):
            self.opened(envelope,approval=wrong,recipient=self.other[0],key=self.other[1])
        for changed in (dict(self.approval,revision=44),
                        dict(self.approval,fleet="another-fleet"),
                        dict(self.approval,wrappingSha256=self.other[2])):
            with self.assertRaises(ValueError):
                self.opened(envelope,approval=changed)
        with self.assertRaises(ValueError):
            delivery.seal(self.approval,self.pfx,b"wrong-password",
                self.signer[0],self.signer[1],self.receiver[0])


if __name__=="__main__":
    unittest.main()
