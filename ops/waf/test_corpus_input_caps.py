"""Fail-closed bounds for private WAF corpus and policy file inputs (#51)."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import corpus_evidence_gate as gate


class BoundedCorpusInputTests(unittest.TestCase):
    def test_small_regular_policy_and_corpus_are_read_without_normalization(self):
        with tempfile.TemporaryDirectory() as root:
            policy = Path(root) / "policy.json"
            corpus = Path(root) / "corpus.csv"
            policy.write_bytes(b'{"schemaVersion":3}\n')
            corpus.write_bytes(b"case_id,route\r\none,/api\r\n")
            self.assertEqual(gate.read_bounded_utf8(policy, gate.MAX_POLICY_BYTES),
                             '{"schemaVersion":3}\n')
            self.assertEqual(gate.read_bounded_utf8(corpus, gate.MAX_CORPUS_BYTES),
                             "case_id,route\r\none,/api\r\n")

    def test_oversized_sparse_files_fail_before_loading_into_memory(self):
        with tempfile.TemporaryDirectory() as root:
            for name, cap in (("policy.json", gate.MAX_POLICY_BYTES),
                              ("corpus.csv", gate.MAX_CORPUS_BYTES)):
                path = Path(root) / name
                with path.open("wb") as stream:
                    stream.truncate(cap + 1)
                with self.subTest(name=name), self.assertRaisesRegex(
                        ValueError, "bounded regular file"):
                    gate.read_bounded_utf8(path, cap)

    def test_invalid_utf8_and_symlink_are_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "target.json"
            target.write_bytes(bytes([0xff]))
            with self.assertRaises(UnicodeError):
                gate.read_bounded_utf8(target, gate.MAX_POLICY_BYTES)
            alias = Path(root) / "alias.json"
            try:
                alias.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported by test identity")
            with self.assertRaisesRegex(ValueError, "symlink"):
                gate.read_bounded_utf8(alias, gate.MAX_POLICY_BYTES)

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"),
                         "POSIX nonblocking FIFO opening required")
    def test_fifo_is_not_accepted_as_an_evidence_file(self):
        with tempfile.TemporaryDirectory() as root:
            pipe = Path(root) / "fake-policy.json"
            os.mkfifo(pipe)
            with self.assertRaisesRegex(ValueError, "bounded regular file"):
                gate.read_bounded_utf8(pipe, gate.MAX_POLICY_BYTES)

    def test_cli_refuses_oversized_policy_without_leaking_evidence_path(self):
        with tempfile.TemporaryDirectory() as root:
            work = Path(root)
            policy = work / "secret-tenant-policy.json"
            with policy.open("wb") as stream:
                stream.truncate(gate.MAX_POLICY_BYTES + 1)
            corpus = work / "corpus.csv"
            corpus.write_text("case_id,route,expected,observed,would_block,mode,severity\n",
                              encoding="utf-8")
            output = work / "report.json"
            run = subprocess.run(
                [sys.executable, str(Path(gate.__file__)), "--policy", str(policy),
                 "--corpus", str(corpus), "--out", str(output)],
                capture_output=True, text=True, check=False, timeout=12)
            self.assertEqual(run.returncode, 1, run.stderr)
            self.assertNotIn(str(policy), run.stdout + run.stderr)
            self.assertNotIn("secret-tenant", run.stdout + run.stderr)
            self.assertEqual(__import__("json").loads(
                output.read_text(encoding="utf-8"))["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
