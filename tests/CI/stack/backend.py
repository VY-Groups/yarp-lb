"""Disposable HTTP backend: unique transaction counts are observable for no-replay tests."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import threading

node = sys.argv[1]
counts = Counter()
lock = threading.Lock()

class Backend(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def respond(self, status, body, kind="application/json"):
        body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_GET(self):
        if self.path == "/health/ready":
            return self.respond(200, {"healthy": True, "node": node})
        if self.path == "/api/identity":
            return self.respond(200, {"node": node})
        if self.path.startswith("/lab/count/"):
            key = self.path.rsplit("/", 1)[-1]
            with lock:
                count = counts[key]
            return self.respond(200, {"node": node, "count": count})
        return self.respond(404, {"error": "not found"})
    def do_POST(self):
        if self.path.startswith("/api/transaction/"):
            key = self.path.rsplit("/", 1)[-1]
            if not (8 <= len(key) <= 80 and key.isascii() and key.isalnum()):
                return self.respond(400, {"error": "invalid id"})
            length = int(self.headers.get("Content-Length", "0"))
            if length > 0:
                self.rfile.read(min(length, 4096))
            with lock:
                counts[key] += 1
                applied = counts[key]
            return self.respond(200, {"node": node, "id": key, "appliedCount": applied})
        return self.respond(404, {"error": "not found"})
    def log_message(self, *_args):
        return

print("backend up", node, flush=True)
ThreadingHTTPServer(("0.0.0.0", 8080), Backend).serve_forever()
