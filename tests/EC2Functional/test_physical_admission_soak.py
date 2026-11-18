import base64
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import physical_admission_soak as soak


class PhysicalAdmissionSoakTests(unittest.TestCase):
    def test_loopback_http_addresses_are_accepted_and_normalized(self):
        self.assertEqual(soak.parse_loopback_base("http://127.0.0.1:18080/"),
                         ("http://127.0.0.1:18080", "127.0.0.1", 18080))
        self.assertEqual(soak.parse_loopback_base("http://[::1]:80"),
                         ("http://[::1]:80", "::1", 80))

    def test_remote_or_ambiguous_base_is_rejected(self):
        invalid = [
            "https://127.0.0.1:18080",
            "http://127.0.0.1.evil.example:18080",
            "http://localhost:18080",
            "http://192.0.2.10:18080",
            "http://user:secret@127.0.0.1:18080",
            "http://127.0.0.1:18080/admin",
            "http://127.0.0.1:18080/?to=remote",
            "http://127.0.0.1:18080/#fragment",
            "http://127.0.0.1:70000",
        ]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                soak.parse_loopback_base(value)

    def test_admin_client_rejects_remote_base_before_any_request(self):
        with self.assertRaises(ValueError):
            soak.admin_client("http://192.0.2.10:18080", "test", "not-a-real-password")

    def test_signature_verification_requires_exact_document_bytes(self):
        if not shutil.which("openssl"):
            self.skipTest("OpenSSL unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            key = root / "key.pem"
            cert = root / "cert.pem"
            document_path = root / "document.json"
            signature_path = root / "signature.bin"
            document = json.dumps({"instanceId": "i-test123", "region": "ap-south-1"}).encode()
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                            "-keyout", str(key), "-out", str(cert), "-subj", "/CN=test", "-days", "1"],
                           check=True, capture_output=True, timeout=20)
            document_path.write_bytes(document)
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(key), "-out", str(signature_path),
                            str(document_path)], check=True, capture_output=True, timeout=10)
            signature = base64.b64encode(signature_path.read_bytes()).decode("ascii")
            self.assertEqual(soak.verify_instance_identity_document(document, signature, cert.read_text()),
                             {"instance_id": "i-test123", "region": "ap-south-1"})
            with self.assertRaises(subprocess.CalledProcessError):
                soak.verify_instance_identity_document(document + b" ", signature, cert.read_text())


if __name__ == "__main__":
    unittest.main()
