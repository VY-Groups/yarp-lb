"""HTTP contract checks for the disposable Alertmanager webhook receiver."""
from http.server import ThreadingHTTPServer
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from receiver import Handler, Receiver


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.events = []
        cls.server.events_lock = threading.Lock()
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        with self.server.events_lock:
            self.server.events.clear()

    def post(self, document, content_type="application/json"):
        body = json.dumps(document).encode("utf-8")
        request = Request(f"{self.base_url}/alerts", data=body, headers={"Content-Type": content_type})
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_readiness_and_valid_alert_delivery(self):
        with urlopen(f"{self.base_url}/ready", timeout=2) as response:
            self.assertEqual(json.load(response), {"ready": True})

        alert = {
            "status": "firing",
            "labels": {"alertname": "GatewayCoreObservabilityDeliveryTest"},
        }
        self.assertEqual(self.post({"version": "4", "alerts": [alert]})[0], 200)
        with urlopen(f"{self.base_url}/events", timeout=2) as response:
            events = json.load(response)
        self.assertEqual(events["count"], 1)
        self.assertEqual(events["events"][0]["alerts"], [alert])

    def test_rejects_non_object_and_invalid_alertmanager_payloads(self):
        self.assertEqual(self.post(["not", "an", "object"])[0], 400)
        self.assertEqual(self.post({"version": "3", "alerts": []})[0], 400)
        self.assertEqual(self.post({"version": "4", "alerts": [{"status": "unknown"}]})[0], 400)

    def test_rejects_wrong_content_type(self):
        self.assertEqual(self.post({"version": "4", "alerts": []}, "text/plain")[0], 415)


if __name__ == "__main__":
    unittest.main()

