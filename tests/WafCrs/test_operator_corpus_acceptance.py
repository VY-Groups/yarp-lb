#!/usr/bin/env python3
"""Deterministic acceptance tests for the optional private WAF corpus runner."""
import copy
import http.client
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch

import operator_corpus_acceptance as waf


def corpus():
    return {
        "schemaVersion": 1, "maxFalsePositives": 0, "maxFalseNegatives": 0,
        "cases": [
            {"id": "benign-json", "route": "api", "method": "POST",
             "path": "/acceptance", "expected": "benign", "severity": "none",
             "contentType": "application/json", "body": "{\"name\":\"test\"}"},
            {"id": "benign-query", "route": "web", "method": "GET",
             "path": "/?q=ordinary", "expected": "benign", "severity": "none",
             "contentType": "text/plain", "body": ""},
            {"id": "attack-xss", "route": "web", "method": "GET",
             "path": "/blocked?q=<script>alert(1)</script>",
             "expected": "malicious", "severity": "high",
             "contentType": "text/plain", "body": ""},
            {"id": "attack-sqli", "route": "api", "method": "POST",
             "path": "/blocked", "expected": "malicious", "severity": "critical",
             "contentType": "application/json", "body": "{\"id\":\"1' OR 1=1\"}"},
        ],
    }


class LocalWaf(BaseHTTPRequestHandler):
    # Unit-test audit fixtures only; real ModSecurity is exercised by verify.sh.
    observed = []
    request_headers = []

    def handle_case(self):
        self.request_headers.append((self.command, dict(self.headers.items())))
        self.observed.append((self.path, self.headers.get("X-GatewayCore-Corpus-Run"),
                              self.headers.get("X-GatewayCore-Corpus-Case")))
        length = int(self.headers.get("Content-Length", "0"))
        if length > 0:
            self.rfile.read(length)
        if self.path.startswith("/blocked"):
            self.send_response(403)
            payload = b"rejected"
            content_type = "text/plain"
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "https://not-allowed.invalid/")
            payload = b"not-a-validated-result"
            content_type = "text/plain"
        elif self.path.startswith("/spoof"):
            self.send_response(200)
            payload = b"not-origin-YARP-WAF-CI-BENIGN\n"
            content_type = "text/plain; charset=utf-8"
        elif self.path.startswith("/bogus-json"):
            self.send_response(200)
            payload = b'{"accepted":true,"contentType":"application/json","bytes":99999}'
            content_type = "application/json"
        elif self.path.startswith("/unsupported-transfer"):
            # An origin-like marker with a coding that http.client cannot
            # decode must never qualify as verified backend evidence.
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Transfer-Encoding", "gzip")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"YARP-WAF-CI-BENIGN\n")
            self.close_connection = True
            return
        elif self.path.startswith("/incomplete-block"):
            # A 403 with an interrupted declared body is not verified
            # blocking evidence; http.client raises IncompleteRead.
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", "100")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"cut short")
            self.close_connection = True
            return
        elif self.path.startswith("/unsupported-block-transfer"):
            # A 403 with unsupported transfer coding cannot establish a
            # complete WAF decision from the status line alone.
            self.send_response(403)
            self.send_header("Transfer-Encoding", "gzip")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"rejected")
            self.close_connection = True
            return
        elif self.path.startswith("/oversized-block-chunked"):
            # A syntactically valid chunked 403 body bigger than the bounded
            # read cannot count as verified blocking while unread bytes remain.
            self.send_response(403)
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Connection", "close")
            self.end_headers()
            oversized = b"x" * 5000
            self.wfile.write(f"{len(oversized):X}\r\n".encode("ascii"))
            self.wfile.write(oversized + b"\r\n0\r\n\r\n")
            self.close_connection = True
            return
        elif self.path.startswith("/mislength"):
            # A valid origin marker with an inaccurate HTTP length must never
            # qualify as proof that the complete private origin was reached.
            self.send_response(200)
            payload = b"YARP-WAF-CI-BENIGN\n"
            content_type = "text/plain; charset=utf-8"
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload) + 12))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            return
        else:
            self.send_response(200)
            if self.command == "POST":
                content_type = "application/json"
                payload = json.dumps({
                    "accepted": True,
                    "contentType": self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower(),
                    "bytes": length,
                }, separators=(",", ":")).encode("ascii")
            else:
                content_type = "text/plain; charset=utf-8"
                payload = b"YARP-WAF-CI-BENIGN\n"
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = handle_case
    do_POST = handle_case

    def log_message(self, *args):
        pass


class OperatorCorpusTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "private-input.json"

    def tearDown(self):
        self.temp.cleanup()

    def load(self, data):
        self.path.write_text(json.dumps(data), encoding="utf-8")
        return waf.load_corpus(self.path)

    def test_report_is_owner_only_and_atomic_even_under_permissive_umask(self):
        output = Path(self.temp.name) / "private-report.json"
        if os.name == "posix":
            # Exercise a genuinely permissive umask, not just the default
            # CI runner setting; restore it immediately after the write.
            original_umask = os.umask(0)
            try:
                waf.write_private_report({"cases": [{"id": "private-id"}]}, output)
            finally:
                os.umask(original_umask)
        else:
            waf.write_private_report({"cases": [{"id": "private-id"}]}, output)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text())["cases"][0]["id"], "private-id")
        self.assertFalse(output.with_name(output.name + ".tmp").exists())
        waf.write_private_report({"cases": []}, output)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(json.loads(output.read_text())["cases"], [])

    def test_report_symlink_and_predictable_temp_alias_fail_closed(self):
        destination = Path(self.temp.name) / "operator-report.json"
        sentinel = Path(self.temp.name) / "sensitive-sentinel.txt"
        sentinel.write_text("do-not-overwrite", encoding="utf-8")
        try:
            destination.symlink_to(sentinel)
        except OSError as error:
            self.skipTest("symlink creation not supported on test host: " + type(error).__name__)
        with self.assertRaises(ValueError):
            waf.write_private_report({"cases": []}, destination)
        self.assertEqual(sentinel.read_text(), "do-not-overwrite")
        destination.unlink()
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.symlink_to(sentinel)
        with self.assertRaises(FileExistsError):
            waf.write_private_report({"cases": []}, destination)
        self.assertEqual(sentinel.read_text(), "do-not-overwrite")
        self.assertTrue(temporary.is_symlink())

    def test_write_error_removes_only_new_private_temp(self):
        destination = Path(self.temp.name) / "operator-report.json"
        temporary = destination.with_name(destination.name + ".tmp")
        with patch.object(waf.os, "replace", side_effect=OSError("simulated rename error")):
            with self.assertRaises(OSError):
                waf.write_private_report({"cases": [{"id": "private-id"}]}, destination)
        self.assertFalse(destination.exists())
        self.assertFalse(temporary.exists())


    def test_private_corpus_input_rejects_symlink_and_hardlink(self):
        self.path.write_text(json.dumps(corpus()), encoding="utf-8")
        alias = Path(self.temp.name) / "untrusted-alias.json"
        try:
            alias.symlink_to(self.path)
        except (OSError, NotImplementedError):
            self.skipTest("symlink unavailable on CI runner")
        with self.assertRaises((OSError, ValueError)):
            waf.load_corpus(alias)
        alias.unlink()
        try:
            os.link(self.path, alias)
        except (OSError, NotImplementedError):
            self.skipTest("hardlink unavailable on CI runner")
        for candidate in (alias, self.path):
            with self.subTest(candidate=candidate.name):
                with self.assertRaises(ValueError):
                    waf.load_corpus(candidate)
        alias.unlink()
        self.assertEqual(len(waf.load_corpus(self.path)), 4)

    def test_private_corpus_input_rejects_nonregular_and_oversized(self):
        with self.assertRaises(ValueError):
            waf.load_corpus(Path(self.temp.name))
        with self.path.open("wb") as output:
            output.truncate(waf.MAX_INPUT + 1)
        with self.assertRaises(ValueError):
            waf.load_corpus(self.path)
        self.path.write_text(json.dumps(corpus()), encoding="utf-8")
        self.assertEqual(len(waf.load_corpus(self.path)), 4)

    def test_schema_and_privacy(self):
        cases = self.load(corpus())
        self.assertEqual(4, len(cases))
        self.assertEqual("attack-sqli", cases[-1]["id"])
        self.path.write_text('{"schemaVersion":1,"schemaVersion":1}', encoding="utf-8")
        with self.assertRaises(ValueError):
            waf.load_corpus(self.path)
        self.assertRaises(ValueError, self.load, {**corpus(), "unexpected": "field"})
        self.assertRaises(ValueError, self.load, {**corpus(), "maxFalseNegatives": 1})
        self.assertRaises(ValueError, self.load, {**corpus(), "maxFalsePositives": True})
        self.assertRaises(ValueError, self.load, {**corpus(), "cases": []})

    def test_rejects_unsafe_unbounded_requests(self):
        changes = [
            {"path": "http://external.example/"}, {"path": "//external.example/"},
            {"path": "/\r\nx-header:bad"}, {"path": "/where\\isit"},
            {"path": "/search/café"}, {"path": "/search/🐍"},
            {"path": "/invalid-" + "\ud800"}, {"body": "\ud800"},
            {"body": "x" * (waf.MAX_BODY + 1)}, {"method": "DELETE"},
            {"contentType": "text/html"}, {"route": "../path"},
            {"id": "benign-query"}, {"id": "BENIGN-QUERY"},
        ]
        for mutation in changes:
            invalid = corpus()
            invalid["cases"][0].update(mutation)
            with self.subTest(mutation=list(mutation)):
                with self.assertRaises(ValueError):
                    self.load(invalid)

    def test_percent_encoded_unicode_target_and_utf8_body_stay_supported(self):
        private = corpus()
        # Raw UTF-8 in request target is unsafe; correctly escaped URI is fine.
        private["cases"][1]["path"] = "/search?q=caf%C3%A9"
        private["cases"][0]["body"] = '{"name":"café"}'
        accepted = self.load(private)
        self.assertEqual(accepted[1]["path"], "/search?q=caf%C3%A9")
        self.assertEqual(accepted[0]["body"], '{"name":"café"}')

    def test_invalid_private_unicode_diagnostic_is_redacted(self):
        # JSON permits an unpaired surrogate which cannot be UTF-8 encoded.
        # Fail in preflight with a bounded ValueError, not a traceback
        # containing operator-provided request/body fragments.
        private = corpus()
        private["cases"][0]["body"] = "secret-canary-" + "\ud800"
        with self.assertRaises(ValueError) as raised:
            self.load(private)
        self.assertNotIn("secret-canary", str(raised.exception))
        private["cases"][0]["body"] = "{}"
        private["cases"][0]["path"] = "/private-path-canary-" + "\ud800"
        with self.assertRaises(ValueError) as raised:
            self.load(private)
        self.assertNotIn("private-path-canary", str(raised.exception))

    def test_response_framing_rejects_ambiguous_transfer_codings(self):
        def headers(*pairs):
            message = Message()
            for name, value in pairs:
                message.add_header(name, value)
            return message

        payload = b"YARP-WAF-CI-BENIGN\n"
        self.assertTrue(waf.verified_response_framing(
            headers(("Content-Length", str(len(payload)))), payload))
        self.assertTrue(waf.verified_response_framing(
            headers(("Transfer-Encoding", "chunked")), payload))
        self.assertTrue(waf.verified_response_framing(
            headers(("Transfer-Encoding", "CHUNKED")), payload))
        self.assertTrue(waf.verified_response_framing(headers(), payload))
        for bad in (
            (("Transfer-Encoding", "gzip"),),
            (("Transfer-Encoding", "identity"),),
            (("Transfer-Encoding", "gzip, chunked"),),
            (("Transfer-Encoding", "chunked"), ("Transfer-Encoding", "chunked")),
            (("Content-Length", str(len(payload))), ("Transfer-Encoding", "chunked")),
            (("Content-Length", str(len(payload))), ("Content-Length", str(len(payload)))),
        ):
            with self.subTest(headers=bad):
                self.assertFalse(waf.verified_response_framing(headers(*bad), payload))


    def test_native_audit_requires_current_unique_complete_crs_denial(self):
        run_id = "a" * 32
        fixture = (
            "--fixture1-A--\n--fixture1-B--\n"
            f"X-GatewayCore-Corpus-Run: {run_id}\n"
            "X-GatewayCore-Corpus-Case: malicious1\n"
            '--fixture1-H--\nModSecurity: Access denied with code 403 [id "941100"]\n'
            "--fixture1-Z--\n")
        accepted = waf.native_crs_blocks(fixture, run_id, {"malicious1"})
        self.assertEqual({"malicious1"}, accepted)
        for invalid in (
            fixture.replace(run_id, "b" * 32),
            fixture.replace("--fixture1-Z--", ""),
            fixture.replace('[id "941100"]', '[id "100001"]'),
            fixture.replace("Access denied with code 403", "Warning only"),
            fixture.replace("ModSecurity: Access denied with code 403",
                            'ModSecurity: Warning. [data "Access denied with code 403"]'),
        ):
            self.assertEqual(set(), waf.native_crs_blocks(invalid, run_id, {"malicious1"}))
        for ambiguous in (
            fixture + fixture,
            fixture.replace("X-GatewayCore-Corpus-Case: malicious1",
                            "X-GatewayCore-Corpus-Case: malicious1\nX-GatewayCore-Corpus-Case: malicious1"),
            fixture.replace("X-GatewayCore-Corpus-Case: malicious1",
                            "X-GatewayCore-Corpus-Case: unrequested"),
            fixture.replace("Access denied with code 403", "Warning only") + fixture,
        ):
            with self.assertRaises(ValueError):
                waf.native_crs_blocks(ambiguous, run_id, {"malicious1"})

    def test_audit_reader_fails_closed_without_exposing_diagnostics(self):
        with patch.object(waf.subprocess, "run", side_effect=OSError("private-secret")):
            with self.assertRaises(ValueError) as raised:
                waf.read_native_audit("2026-01-01T00:00:00Z")
            self.assertNotIn("private-secret", str(raised.exception))

    def test_no_redirect_or_payload_in_reports(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalWaf)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            factory = lambda: http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2)
            def fake_audit(_since):
                transactions = []
                for index, (path, run_id, case_id) in enumerate(LocalWaf.observed):
                    if not path.startswith("/blocked"):
                        continue
                    txn = f"fixture{index:06d}"
                    transactions.append(
                        f"--{txn}-A--\n--{txn}-B--\n"
                        f"X-GatewayCore-Corpus-Run: {run_id}\n"
                        f"X-GatewayCore-Corpus-Case: {case_id}\n"
                        f'--{txn}-H--\nModSecurity: Access denied with code 403 [id "941100"]\n'
                        f"--{txn}-Z--\n")
                return "".join(transactions)

            expected = self.load(corpus())
            unverified = waf.run_cases(expected, factory, lambda _since: "")
            self.assertEqual(2, unverified["counts"]["ERROR"])
            self.assertEqual(0, unverified["counts"]["TP"])
            self.assertFalse(unverified["passesZeroFalsePositiveNegativeGate"])
            good = waf.run_cases(expected, factory, fake_audit)
            self.assertTrue(good["passesZeroFalsePositiveNegativeGate"])
            for method, headers in LocalWaf.request_headers:
                if method == "GET":
                    self.assertNotIn("Content-Type", headers)
                    self.assertNotIn("Content-Length", headers)
                else:
                    self.assertIn("Content-Type", headers)
            self.assertEqual(
                {"TP": 2, "TN": 2, "FP": 0, "FN": 0, "ERROR": 0},
                good["counts"])
            serialized = json.dumps(good)
            self.assertNotIn("1' OR 1=1", serialized)
            self.assertNotIn("script", serialized)
            self.assertNotIn("/blocked", serialized)
            self.assertEqual(4, len(good["byRouteAndSeverity"]))
            regression = copy.deepcopy(expected)
            regression[2]["path"] = "/"
            missing_detection = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, missing_detection["counts"]["FN"])
            self.assertFalse(missing_detection["passesZeroFalsePositiveNegativeGate"])
            regression = copy.deepcopy(expected)
            regression[0]["path"] = "/blocked"
            false_positive = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, false_positive["counts"]["FP"])
            regression = copy.deepcopy(expected)
            regression[0]["path"] = "/redirect"
            redirect = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, redirect["counts"]["ERROR"])
            self.assertFalse(redirect["passesZeroFalsePositiveNegativeGate"])
            # A response that merely contains the GET marker must NOT
            # masquerade as the bounded private origin's exact response.
            regression = copy.deepcopy(expected)
            regression[1]["path"] = "/spoof"
            spoof = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, spoof["counts"]["ERROR"])
            self.assertFalse(spoof["passesZeroFalsePositiveNegativeGate"])
            # A real-looking origin response with more bytes declared than
            # received must not be counted as benign successful forwarding.
            regression = copy.deepcopy(expected)
            regression[1]["path"] = "/mislength"
            truncated = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, truncated["counts"]["ERROR"])
            self.assertFalse(truncated["passesZeroFalsePositiveNegativeGate"])
            # A truncated 403 must not be counted as a successful attack
            # block after the response reader raises IncompleteRead.
            regression = copy.deepcopy(expected)
            regression[2]["path"] = "/incomplete-block"
            incomplete_block = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, incomplete_block["counts"]["ERROR"])
            self.assertEqual(1, incomplete_block["counts"]["TP"])
            self.assertFalse(incomplete_block["passesZeroFalsePositiveNegativeGate"])
            # Unsupported transfer framing on a 403 is likewise ERROR,
            # never proof that the WAF fully processed the request.
            regression = copy.deepcopy(expected)
            regression[2]["path"] = "/unsupported-block-transfer"
            unsupported_block = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, unsupported_block["counts"]["ERROR"])
            self.assertEqual(1, unsupported_block["counts"]["TP"])
            self.assertFalse(unsupported_block["passesZeroFalsePositiveNegativeGate"])
            # Large chunked 403 bodies are deliberately not drained beyond
            # the bounded read; unread bytes must invalidate the block.
            regression = copy.deepcopy(expected)
            regression[2]["path"] = "/oversized-block-chunked"
            oversized_block = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, oversized_block["counts"]["ERROR"])
            self.assertEqual(1, oversized_block["counts"]["TP"])
            self.assertFalse(oversized_block["passesZeroFalsePositiveNegativeGate"])
            # An unknown transfer coding cannot be accepted merely
            # because the undecoded bytes equal the expected origin marker.
            regression = copy.deepcopy(expected)
            regression[1]["path"] = "/unsupported-transfer"
            unsupported = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, unsupported["counts"]["ERROR"])
            self.assertFalse(unsupported["passesZeroFalsePositiveNegativeGate"])
            # A spoofed POST JSON acceptance with the wrong byte count
            # cannot qualify a benign upload as a reached origin.
            regression = copy.deepcopy(expected)
            regression[0]["path"] = "/bogus-json"
            bogus = waf.run_cases(regression, factory, fake_audit)
            self.assertEqual(1, bogus["counts"]["ERROR"])
            self.assertFalse(bogus["passesZeroFalsePositiveNegativeGate"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
