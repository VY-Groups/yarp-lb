#!/usr/bin/env python3
"""Bounded, body-redacting backend used only by the disposable WAF lab."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_BODY_BYTES = 131_072
ALLOWED_CONTENT_TYPES = {
    "application/json",
    "application/xml",
    "application/pkix-cert",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "WafCrsAcceptanceBackend/1"
    sys_version = ""

    def do_GET(self) -> None:
        body = b"YARP-WAF-CI-BENIGN\n"
        self._respond(200, "text/plain; charset=utf-8", body)

    def do_POST(self) -> None:
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            self._respond(400, "application/json", b'{"error":"invalid content length"}')
            return
        if length < 0 or length > MAX_BODY_BYTES:
            self._respond(413, "application/json", b'{"error":"body too large"}')
            return

        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type not in ALLOWED_CONTENT_TYPES:
            self._respond(415, "application/json", b'{"error":"unsupported content type"}')
            return

        payload = self.rfile.read(length)
        if len(payload) != length:
            self._respond(400, "application/json", b'{"error":"incomplete body"}')
            return

        # Never echo or log uploaded content; return only a fixed acceptance
        # marker, normalized media type, and byte count for the CI assertion.
        response = json.dumps(
            {"accepted": True, "contentType": content_type, "bytes": length},
            separators=(",", ":"),
        ).encode("ascii")
        self._respond(200, "application/json", response)

    def _respond(self, status: int, content_type: str, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, _format: str, *_args: object) -> None:
        # Request targets and bodies are intentionally absent from backend logs.
        return


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
