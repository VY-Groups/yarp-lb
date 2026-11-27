"""Exercise exact fixture framing with genuine HTTP/1.1 client connections."""
import http.client
import http.server
import io
import threading
import unittest
from email.message import Message
from vip_http_body import read_json_body


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            value = read_json_body(self.headers, self.rfile)
            status = 200 if value == {"epoch": 12, "drain": False} else 422
        except (ValueError, OSError):
            status = 400
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


class FramingTests(unittest.TestCase):
    def test_real_http_fixed_and_chunked(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for body, chunked in [
                (b'{"epoch":12,"drain":false}', False),
                ([b'{"epoch":', b'12,', b'"drain":false}'], True),
            ]:
                client = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                try:
                    client.request("POST", "/", body=body, encode_chunked=chunked)
                    self.assertEqual(client.getresponse().status, 200)
                finally:
                    client.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(3)

    def test_bad_and_oversized_frames(self):
        def decode(body, headers):
            message = Message()
            for k, v in headers:
                message[k] = v
            return read_json_body(message, io.BytesIO(body))
        chunked = [("Transfer-Encoding", "chunked")]
        cases = [
            (b"1001\r\n", chunked),
            (b"3\r\n{}\r\n0\r\n\r\n", chunked),
            (b"0\r\nX: trailer\r\n\r\n", chunked),
            (b"2\r\n{}\r\n0\r\n\r\n", chunked + [("Content-Length", "2")]),
            (b"[]", [("Content-Length", "2")]),
            (b"{}", [("Content-Length", "3")]),
            (b"{}", [("Content-Length", "2"), ("Content-Length", "2")]),
            (b"{}", []),
        ]
        for data, headers in cases:
            with self.subTest(data=data, headers=headers):
                with self.assertRaises(ValueError):
                    decode(data, headers)


if __name__ == "__main__":
    unittest.main()
