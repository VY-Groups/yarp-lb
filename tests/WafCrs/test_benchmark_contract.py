"""Deterministic proof the WAF benchmark cannot accept forged origin evidence."""
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
import benchmark


def headers(content_type, size=None, transfer_encoding=None):
    result = Message()
    result.add_header("Content-Type", content_type)
    if size is not None:
        result.add_header("Content-Length", str(size))
    if transfer_encoding is not None:
        result.add_header("Transfer-Encoding", transfer_encoding)
    return result


def post_result():
    return json.dumps({"accepted": True, "contentType": "application/json",
                       "bytes": len(benchmark.PAYLOAD)}).encode("ascii")


class BenchmarkOriginEvidence(unittest.TestCase):
    def test_valid_get_and_post_with_declared_lengths(self):
        get = b"YARP-WAF-CI-BENIGN\n"
        post = post_result()
        self.assertTrue(benchmark.verified_origin(0, headers(
            "text/plain; charset=utf-8", len(get)), get))
        self.assertTrue(benchmark.verified_origin(1, headers(
            "application/json", len(post)), post))

    def test_valid_chunked_response_supported_without_length(self):
        payload = post_result()
        self.assertTrue(benchmark.verified_origin(
            1, headers("application/json", transfer_encoding="chunked"), payload))

    def test_duplicate_json_fields_fail_closed(self):
        duplicate = (b'{"accepted":true,"contentType":"application/json",'
                     b'"bytes":999,"bytes":' + str(len(benchmark.PAYLOAD)).encode() + b'}')
        self.assertFalse(benchmark.verified_origin(
            1, headers("application/json", len(duplicate)), duplicate))

    def test_numeric_type_confusion_rejected(self):
        for wrong in (float(len(benchmark.PAYLOAD)),
                      str(len(benchmark.PAYLOAD)), True):
            data = json.dumps({"accepted": True, "contentType": "application/json",
                               "bytes": wrong}).encode("ascii")
            with self.subTest(wrong=wrong):
                self.assertFalse(benchmark.verified_origin(
                    1, headers("application/json", len(data)), data))

    def test_invalid_or_missing_media_type_rejected(self):
        payload = post_result()
        self.assertFalse(benchmark.verified_origin(
            1, headers("text/plain", len(payload)), payload))
        get = b"YARP-WAF-CI-BENIGN\n"
        self.assertFalse(benchmark.verified_origin(
            0, headers("application/json", len(get)), get))

    def test_mismatched_and_ambiguous_http_framing_rejected(self):
        payload = post_result()
        self.assertFalse(benchmark.verified_origin(
            1, headers("application/json", len(payload) + 9), payload))
        ambiguous = headers("application/json", len(payload))
        ambiguous.add_header("Content-Length", str(len(payload)))
        self.assertFalse(benchmark.verified_origin(1, ambiguous, payload))
        both = headers("application/json", len(payload), "chunked")
        self.assertFalse(benchmark.verified_origin(1, both, payload))
        nondecimal = headers("application/json")
        nondecimal.add_header("Content-Length", "+100")
        self.assertFalse(benchmark.verified_origin(1, nondecimal, payload))

    def test_duplicate_transfer_encoding_is_rejected(self):
        payload = post_result()
        duplicate = headers("application/json", transfer_encoding="chunked")
        duplicate.add_header("Transfer-Encoding", "chunked")
        self.assertFalse(benchmark.verified_origin(1, duplicate, payload))
        mixed = headers("application/json", transfer_encoding="chunked")
        mixed.add_header("Transfer-Encoding", "gzip")
        self.assertFalse(benchmark.verified_origin(1, mixed, payload))
        combined = headers("application/json", transfer_encoding="gzip, chunked")
        self.assertFalse(benchmark.verified_origin(1, combined, payload))

    def test_real_http_request_rejects_incomplete_or_ambiguous_origin(self):
        class Fixture(BaseHTTPRequestHandler):
            mode = "valid"
            def do_GET(self):
                body = b"YARP-WAF-CI-BENIGN\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                if self.mode == "duplicate":
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.end_headers()
                    self.wfile.write(("%X\r\n" % len(body)).encode("ascii"))
                    self.wfile.write(body + b"\r\n0\r\n\r\n")
                elif self.mode == "oversized":
                    large = body + b"x" * 5000
                    self.send_header("Content-Length", str(len(large)))
                    self.end_headers()
                    self.wfile.write(large)
                elif self.mode == "truncated":
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(("%X\r\n" % len(body)).encode("ascii"))
                    self.wfile.write(body + b"\r\n")
                else:
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                self.close_connection = True

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for mode, should_pass in (("valid", True), ("duplicate", False),
                                      ("oversized", False), ("truncated", False)):
                with self.subTest(mode=mode):
                    Fixture.mode = mode
                    elapsed, error = benchmark.request(0, "127.0.0.1", server.server_port)
                    self.assertEqual(elapsed is not None and error is None, should_pass)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)

    def test_oversized_or_wrong_get_marker_rejected(self):
        get = b"YARP-WAF-CI-BENIGN\n"
        self.assertFalse(benchmark.verified_origin(
            0, headers("text/plain; charset=utf-8", 4097), b"x" * 4097))
        self.assertFalse(benchmark.verified_origin(
            0, headers("text/plain; charset=utf-8", len(get) + 1), get + b"x"))


if __name__ == "__main__":
    unittest.main()
