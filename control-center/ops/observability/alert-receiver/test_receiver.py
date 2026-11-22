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

    def test_rejects_ambiguous_http_framing(self):
        import http.client
        for headers in ({"Transfer-Encoding": "chunked"}, {"Content-Length": "2"}):
            with self.subTest(headers=headers):
                connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
                try:
                    connection.putrequest("POST", "/alerts")
                    connection.putheader("Content-Type", "application/json")
                    connection.putheader("Content-Length", "28")
                    for key, value in headers.items():
                        connection.putheader(key, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400)
                    self.assertEqual(json.loads(response.read())["error"], "ambiguous_request_framing")
                    self.assertEqual(response.getheader("Connection"), "close")
                finally:
                    connection.close()

    def test_duplicate_json_keys_fail_closed(self):
        import http.client
        for payload in (
            b'{"version":"4","version":"4","alerts":[]}',
            b'{"version":"4","alerts":[{"status":"firing","status":"resolved"}]}',
            b'{"version":"4","alerts":[{"status":"firing","labels":{"alertname":"ok","alertname":"spoof"}}]}',
        ):
            with self.subTest(payload=payload):
                connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
                try:
                    connection.request("POST", "/alerts", body=payload,
                                       headers={"Content-Type": "application/json"})
                    response = connection.getresponse()
                    self.assertEqual(response.status, 400)
                    response.read()
                finally:
                    connection.close()
        with urlopen(f"{self.base_url}/events", timeout=2) as response:
            self.assertEqual(json.load(response)["count"], 0)

    def test_unread_body_rejections_close_connection(self):
        import http.client
        for headers, expected in (
            ({"Content-Type": "text/plain"}, 415),
            ({"Content-Type": "application/json", "Content-Length": "0"}, 413),
        ):
            with self.subTest(headers=headers):
                connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
                try:
                    connection.putrequest("POST", "/alerts")
                    for key, value in headers.items():
                        connection.putheader(key, value)
                    connection.endheaders()
                    response = connection.getresponse()
                    self.assertEqual(response.status, expected)
                    self.assertEqual(response.getheader("Connection"), "close")
                    response.read()
                finally:
                    connection.close()

    def test_unknown_post_path_closes_unread_body_socket(self):
        import http.client
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.putrequest("POST", "/not-alerts")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "100")
            connection.endheaders()
            # Deliberately send no body: the server must not await it or
            # allow its bytes to be parsed as a subsequent request.
            response = connection.getresponse()
            self.assertEqual(response.status, 404)
            self.assertEqual(response.getheader("Connection"), "close")
            self.assertEqual(json.loads(response.read()), {"error": "not_found"})
            with urlopen(f"{self.base_url}/events", timeout=2) as evidence:
                self.assertEqual(json.load(evidence)["count"], 0)
        finally:
            connection.close()

    def test_incomplete_webhook_body_times_out_and_closes_socket(self):
        import http.client
        import receiver
        previous = receiver.READ_TIMEOUT_SECONDS
        receiver.READ_TIMEOUT_SECONDS = 0.15
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        try:
            connection.putrequest("POST", "/alerts")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "100")
            connection.endheaders()
            connection.send(b"{")
            response = connection.getresponse()
            self.assertEqual(response.status, 408)
            self.assertEqual(response.getheader("Connection"), "close")
            self.assertEqual(json.loads(response.read()), {"error": "request_body_timeout"})
            with urlopen(f"{self.base_url}/events", timeout=2) as evidence:
                self.assertEqual(json.load(evidence)["count"], 0)
        finally:
            receiver.READ_TIMEOUT_SECONDS = previous
            connection.close()

    def test_rejects_wrong_content_type(self):
        self.assertEqual(self.post({"version": "4", "alerts": []}, "text/plain")[0], 415)


if __name__ == "__main__":
    unittest.main()

