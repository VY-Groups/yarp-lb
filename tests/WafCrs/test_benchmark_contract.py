"""Deterministic proof the WAF benchmark cannot accept forged origin evidence."""
from email.message import Message
import json
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

    def test_oversized_or_wrong_get_marker_rejected(self):
        get = b"YARP-WAF-CI-BENIGN\n"
        self.assertFalse(benchmark.verified_origin(
            0, headers("text/plain; charset=utf-8", 4097), b"x" * 4097))
        self.assertFalse(benchmark.verified_origin(
            0, headers("text/plain; charset=utf-8", len(get) + 1), get + b"x"))


if __name__ == "__main__":
    unittest.main()
