"""Bounded in-memory webhook target for the disposable observability Compose stack."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading

MAX_BODY_BYTES = 1_048_576
MAX_EVENTS = 100


class Receiver(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        # Never share delivery evidence across independently started receivers.
        self.events = []
        self.events_lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, _format, *_args):
        # Alert labels and annotations are test data; avoid copying payloads to logs.
        pass

    def _write_json(self, status, document):
        body = json.dumps(document, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/ready":
            self._write_json(200, {"ready": True})
            return
        if self.path == "/events":
            with self.server.events_lock:
                events = list(self.server.events)
            self._write_json(200, {"count": len(events), "events": events})
            return
        self._write_json(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/alerts":
            self._write_json(404, {"error": "not_found"})
            return
        if self.headers.get_content_type() != "application/json":
            self._write_json(415, {"error": "unsupported_media_type"})
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            length = -1
        if length < 1 or length > MAX_BODY_BYTES:
            self._write_json(413, {"error": "invalid_body_size"})
            return
        try:
            document = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._write_json(400, {"error": "invalid_json"})
            return
        if not isinstance(document, dict):
            self._write_json(400, {"error": "invalid_alertmanager_payload"})
            return
        alerts = document.get("alerts")
        if document.get("version") != "4" or not isinstance(alerts, list) or len(alerts) > 20:
            self._write_json(400, {"error": "invalid_alertmanager_payload"})
            return
        if any(not isinstance(alert, dict) or alert.get("status") not in ("firing", "resolved")
               for alert in alerts):
            self._write_json(400, {"error": "invalid_alert"})
            return
        # Retain only bounded delivery evidence. Labels, annotations and URLs
        # can contain credentials or private topology; never echo them at /events.
        safe_alerts = []
        for alert in alerts:
            labels = alert.get("labels")
            name = labels.get("alertname") if isinstance(labels, dict) else None
            safe_name = (name if isinstance(name, str) and 0 < len(name) <= 128
                         and all(ch.isascii() and (ch.isalnum() or ch in "_:-") for ch in name)
                         else "redacted")
            safe_alerts.append({"status": alert["status"], "alertname": safe_name})
        with self.server.events_lock:
            self.server.events.append({"version": "4", "alerts": safe_alerts})
            del self.server.events[:-MAX_EVENTS]
        self._write_json(200, {"accepted": True})


if __name__ == "__main__":
    ThreadingHTTPServer.allow_reuse_address = True
    Receiver(("0.0.0.0", 8080), Handler).serve_forever()

