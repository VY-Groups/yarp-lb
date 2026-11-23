"""Synthetic P-256 two-reviewer WAF approval tests. Never use customer keys."""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import verify_signed_policy as gate

NOW = dt.datetime(2026, 11, 23, 10, 0, tzinfo=dt.timezone.utc)
RULESET = "A" * 64


class SignedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.policy_dir = root / "operator-policy"
        self.trust_dir = root / "independent-trust"
        self.policy_dir.mkdir()
        self.trust_dir.mkdir()
        self.policy_file = self.policy_dir / "policy.json"
        self.min_file = self.trust_dir / "min-revision"
        self.min_file.write_text("6\n", encoding="ascii")
        self.keys, self.private = {}, {}
        for who in ("reviewerA", "reviewerB"):
            sk, pk = self.trust_dir / (who + ".key"), self.trust_dir / (who + ".pub")
            subprocess.run(["openssl", "ecparam", "-name", "prime256v1",
                            "-genkey", "-noout", "-out", str(sk)], check=True,
                           capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(sk), "-pubout",
                            "-out", str(pk)], check=True, capture_output=True)
            self.keys[who], self.private[who] = pk, sk
        self.policy = {
            "schemaVersion": 1, "revision": 7, "mode": "detect",
            "rulesetSha256": RULESET, "shadowEvidenceSha256": None,
            "issuedAtUtc": "2026-11-22T09:00:00Z",
            "expiresAtUtc": "2026-12-01T09:00:00Z",
            "exceptions": [{
                "exceptionId": "pkix-case", "owner": "security-reviewer",
                "reason": "Scoped valid public DER upload test",
                "routeId": "cert-upload", "httpMethod": "POST",
                "path": "/cert", "contentType": "application/pkix-cert",
                "ruleId": 920420, "issuedAtUtc": "2026-11-22T09:00:00Z",
                "expiresAtUtc": "2026-11-30T09:00:00Z",
            }],
        }
        self.sign()

    def sign(self):
        raw = json.dumps(self.policy, sort_keys=True).encode("utf-8")
        self.policy_file.write_bytes(raw)
        sha = hashlib.sha256(raw).hexdigest().upper()
        self.approvals = []
        for who in ("reviewerA", "reviewerB"):
            signed_at = "2026-11-23T09:30:00Z"
            result = subprocess.run(
                ["openssl", "dgst", "-sha256", "-sign", str(self.private[who])],
                input=gate._approval_payload(sha, who, signed_at),
                check=True, capture_output=True)
            obj = {"schemaVersion": 1, "reviewer": who,
                   "policySha256": sha, "signedAtUtc": signed_at,
                   "signatureBase64": base64.b64encode(result.stdout).decode("ascii")}
            path = self.policy_dir / (who + ".approval.json")
            path.write_text(json.dumps(obj), encoding="utf-8")
            self.approvals.append(path)

    def check(self, observed=RULESET, mode=None):
        return gate.verify(self.policy_file, self.approvals, self.keys, self.min_file,
                           observed, self.policy["mode"] if mode is None else mode, NOW)

    def test_two_distinct_p256_signers_approve_detect(self):
        self.assertEqual(self.check(), 7)

    def test_block_requires_signed_shadow_evidence(self):
        self.policy["mode"] = "block"
        self.policy["shadowEvidenceSha256"] = "B" * 64
        self.sign()
        self.assertEqual(self.check(), 7)
        self.policy["shadowEvidenceSha256"] = None
        self.sign()
        with self.assertRaises(ValueError):
            self.check()

    def test_actual_mode_or_ruleset_mismatch_fails(self):
        with self.assertRaises(ValueError):
            self.check("B"*64)
        with self.assertRaises(ValueError):
            self.check(mode="block")

    def test_rollback_and_broad_or_expired_exceptions_fail(self):
        self.min_file.write_text("7\n")
        with self.assertRaises(ValueError):
            self.check()
        self.min_file.write_text("6\n")
        for change in ({"path": "/*"}, {"path": "/../admin"},
                       {"expiresAtUtc": "2027-01-01T00:00:00Z"},
                       {"owner": "any*"}, {"httpMethod": "ANY"}):
            before = dict(self.policy["exceptions"][0])
            self.policy["exceptions"][0].update(change)
            self.sign()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check()
            self.policy["exceptions"][0] = before

    def test_changed_policy_or_reused_signer_fails(self):
        self.policy["revision"] = 8
        self.policy_file.write_text(json.dumps(self.policy, sort_keys=True))
        with self.assertRaises(ValueError):
            self.check()
        self.policy["revision"] = 7
        self.sign()
        with self.assertRaises(ValueError):
            gate.verify(self.policy_file, [self.approvals[0]] * 2,
                        self.keys, self.min_file, RULESET, "detect", NOW)
        duplicate_keys = {who: self.keys["reviewerA"] for who in self.keys}
        with self.assertRaises(ValueError):
            gate.verify(self.policy_file, self.approvals, duplicate_keys,
                        self.min_file, RULESET, "detect", NOW)

    def test_same_ec_key_with_different_pem_format_is_not_second_reviewer(self):
        # Both approval identities sign using the SAME EC private key, while
        # their public key files contain different textual line wraps. A raw
        # PEM hash would miss this; canonical SPKI equality must reject it.
        original = self.keys["reviewerA"].read_text(encoding="ascii")
        encoded = "".join(line for line in original.splitlines()
                          if not line.startswith("-----"))
        alternate = ("-----BEGIN PUBLIC KEY-----\n" +
                     "\n".join(encoded[i:i+32] for i in range(0, len(encoded), 32)) +
                     "\n-----END PUBLIC KEY-----\n")
        second = self.trust_dir / "alias-pem-format.pub"
        second.write_text(alternate, encoding="ascii")
        reviewer_b = self.approvals[1]
        record = json.loads(reviewer_b.read_text(encoding="utf-8"))
        same_signer = subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign",
             str(self.private["reviewerA"])],
            input=gate._approval_payload(record["policySha256"],
                                          "reviewerB", record["signedAtUtc"]),
            check=True, capture_output=True)
        record["signatureBase64"] = base64.b64encode(same_signer.stdout).decode("ascii")
        reviewer_b.write_text(json.dumps(record), encoding="utf-8")
        aliased = {**self.keys, "reviewerB": second}
        with self.assertRaisesRegex(ValueError, "share a signing key"):
            gate.verify(self.policy_file, self.approvals, aliased,
                        self.min_file, RULESET, "detect", NOW)

    def test_invalid_signature_fails(self):
        path = self.approvals[0]
        doc = json.loads(path.read_text())
        doc["signatureBase64"] = base64.b64encode(b"invalid").decode()
        path.write_text(json.dumps(doc))
        with self.assertRaises(ValueError):
            self.check()

    def test_aliases_and_invalid_json_fail(self):
        alias = self.policy_dir / "alias.json"
        try:
            alias.symlink_to(self.policy_file)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")
        with self.assertRaises((ValueError, OSError)):
            gate.verify(alias, self.approvals, self.keys, self.min_file,
                        RULESET, "detect", NOW)
        alias.unlink()
        try:
            os.link(self.policy_file, alias)
        except (OSError, NotImplementedError):
            self.skipTest("hardlinks unavailable")
        with self.assertRaises(ValueError):
            self.check()
        alias.unlink()
        self.policy_file.write_text('{"schemaVersion":1,"SCHEMAVERSION":1}')
        with self.assertRaises(ValueError):
            self.check()

    def test_independent_revision_anchor_cannot_be_in_policy_tree(self):
        self.min_file = self.policy_dir / "min-revision"
        self.min_file.write_text("6\n")
        with self.assertRaises(ValueError):
            self.check()


if __name__ == "__main__":
    unittest.main()
