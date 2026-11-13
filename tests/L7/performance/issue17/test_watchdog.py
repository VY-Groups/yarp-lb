"""Contract tests for the out-of-process HTTP watchdog, no .NET needed."""
import importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import unittest

module_path = Path(__file__).with_name("watchdog.py")
spec = importlib.util.spec_from_file_location("issue17_watchdog", module_path)
watchdog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watchdog)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/slow":
            time.sleep(0.25)
        self.send_response(503 if self.path == "/bad" else 200)
        self.end_headers()
        self.wfile.write(b"test")

    def log_message(self, *_args):
        pass


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = "http://127.0.0.1:" + str(cls.server.server_port)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_only_loopback_is_allowed(self):
        self.assertTrue(watchdog.local_http(self.url))
        self.assertFalse(watchdog.local_http("https://example.org/"))
        self.assertFalse(watchdog.local_http("http://10.0.0.1:8080/"))

    def test_success_and_non_200(self):
        self.assertTrue(watchdog.probe(self.url + "/ok", 1)["healthy"])
        self.assertEqual(watchdog.probe(self.url + "/bad", 1)["status"], 503)
        self.assertFalse(watchdog.probe(self.url + "/bad", 1)["healthy"])

    def test_timeout_triggers_unhealthy(self):
        failed = watchdog.probe(self.url + "/slow", 0.03)
        self.assertFalse(failed["healthy"])
        self.assertIsNotNone(failed["error"])


if __name__ == "__main__":
    unittest.main()
