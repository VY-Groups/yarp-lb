"""HTTP contract checks for the disposable Alertmanager webhook receiver."""
import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from receiver import Handler, Receiver


class ReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = Receiver(("127.0.0.1", 0), Handler)
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
        self.assertEqual(events["events"][0]["alerts"], [{"status": "firing", "alertname": "GatewayCoreObservabilityDeliveryTest"}])

    def test_events_never_expose_private_alert_metadata(self):
        alert = {
            "status": "firing",
            "labels": {"alertname": "GatewayCorePrivate", "instance": "private-host"},
            "annotations": {"description": "secret-token"},
            "generatorURL": "https://private-host/internal",
        }
        self.assertEqual(self.post({"version": "4", "alerts": [alert], "externalURL": "private"})[0], 200)
        with urlopen(f"{self.base_url}/events", timeout=2) as response:
            evidence = json.load(response)
        self.assertEqual(evidence["events"][0]["alerts"], [
            {"status": "firing", "alertname": "GatewayCorePrivate"}
        ])
        self.assertNotIn("secret-token", json.dumps(evidence))
        self.assertNotIn("private-host", json.dumps(evidence))
        alert["labels"]["alertname"] = "unsafe/private"
        self.assertEqual(self.post({"version": "4", "alerts": [alert]})[0], 200)
        with urlopen(f"{self.base_url}/events", timeout=2) as response:
            evidence = json.load(response)
        self.assertEqual(evidence["events"][-1]["alerts"][0]["alertname"], "redacted")

    def test_independent_receivers_do_not_share_alert_evidence(self):
        other = Receiver(("127.0.0.1", 0), Handler)
        worker = threading.Thread(target=other.serve_forever, daemon=True)
        worker.start()
        try:
            with urlopen(f"http://127.0.0.1:{other.server_port}/events", timeout=2) as response:
                self.assertEqual(json.load(response)["count"], 0)
            self.assertEqual(self.post({"version": "4", "alerts": [
                {"status": "firing", "labels": {"alertname": "GatewayCoreIsolation"}}
            ]})[0], 200)
            with urlopen(f"http://127.0.0.1:{other.server_port}/events", timeout=2) as response:
                self.assertEqual(json.load(response), {"count": 0, "events": []})
        finally:
            other.shutdown()
            other.server_close()
            worker.join(timeout=2)

    def test_rejects_non_object_and_invalid_alertmanager_payloads(self):
        self.assertEqual(self.post(["not", "an", "object"])[0], 400)
        self.assertEqual(self.post({"version": "3", "alerts": []})[0], 400)
        self.assertEqual(self.post({"version": "4", "alerts": [{"status": "unknown"}]})[0], 400)

    def test_rejects_wrong_content_type(self):
        self.assertEqual(self.post({"version": "4", "alerts": []}, "text/plain")[0], 415)


if __name__ == "__main__":
    unittest.main()

