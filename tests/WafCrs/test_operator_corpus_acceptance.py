#!/usr/bin/env python3
"""Deterministic acceptance tests for the optional private WAF corpus runner."""
import copy
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import unittest

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
    def handle_case(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 0:
            self.rfile.read(length)
        if self.path.startswith("/blocked"):
            self.send_response(403)
            payload = b"rejected"
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "https://not-allowed.invalid/")
            payload = b"not-a-validated-result"
        else:
            self.send_response(200)
            payload = b"YARP-WAF-CI-BENIGN"
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
            {"body": "x" * (waf.MAX_BODY + 1)}, {"method": "DELETE"},
            {"contentType": "text/html"}, {"route": "../path"},
            {"id": "benign-query"},
        ]
        for mutation in changes:
            invalid = corpus()
            invalid["cases"][0].update(mutation)
            with self.subTest(mutation=list(mutation)):
                with self.assertRaises(ValueError):
                    self.load(invalid)

    def test_no_redirect_or_payload_in_reports(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalWaf)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            factory = lambda: http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=2)
            expected = self.load(corpus())
            good = waf.run_cases(expected, factory)
            self.assertTrue(good["passesZeroFalsePositiveNegativeGate"])
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
            missing_detection = waf.run_cases(regression, factory)
            self.assertEqual(1, missing_detection["counts"]["FN"])
            self.assertFalse(missing_detection["passesZeroFalsePositiveNegativeGate"])
            regression = copy.deepcopy(expected)
            regression[0]["path"] = "/blocked"
            false_positive = waf.run_cases(regression, factory)
            self.assertEqual(1, false_positive["counts"]["FP"])
            regression = copy.deepcopy(expected)
            regression[0]["path"] = "/redirect"
            redirect = waf.run_cases(regression, factory)
            self.assertEqual(1, redirect["counts"]["ERROR"])
            self.assertFalse(redirect["passesZeroFalsePositiveNegativeGate"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
