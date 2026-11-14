#!/usr/bin/env python3
"""Offline startup / hot-reload smoke for the actual GatewayCoreYarp.dll.

Uses two local disposable HTTP servers. No EC2 network requests are made.
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import tempfile
from threading import Thread

from ec2_functional import (
    GATEWAY, HOST_A, HOST_B, Gateway, config, curl, write_config, wait_configuration
)


class LocalBackend(BaseHTTPRequestHandler):
    def do_GET(self):
        label = self.server.backend_label
        payload = f"backend {label} 2026-11-14T00:00:00Z\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--dll", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve()
    dll = args.dll.resolve()
    servers = []
    threads = []
    original = {k: os.environ.get(k) for k in (
        "CI", "GITHUB_ACTIONS", "BACKEND_A_HOST", "BACKEND_B_HOST"
    )}
    with tempfile.TemporaryDirectory(prefix="real-gateway-ec2-smoke-") as temp:
        temp = Path(temp)
        cfg = root / "appsettings.json"
        if cfg.exists():
            raise RuntimeError("Refusing to overwrite pre-existing Control Center appsettings.json")
        gateway = None
        try:
            for label in ("test-backend-A", "test-backend-B"):
                server = ThreadingHTTPServer(("127.0.0.1", 0), LocalBackend)
                server.backend_label = label
                servers.append(server)
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            addresses = {
                "A": f"http://127.0.0.1:{servers[0].server_port}/",
                "B": f"http://127.0.0.1:{servers[1].server_port}/",
            }
            os.environ.update({
                "CI": "true", "GITHUB_ACTIONS": "true",
                "BACKEND_A_HOST": HOST_A, "BACKEND_B_HOST": HOST_B,
            })
            write_config(cfg, config(addresses))
            gateway = Gateway(dll, root, temp)
            gateway.start()
            wait_configuration({"A", "B"})
            observed = {curl(GATEWAY + "/ec2/")["backend"] for _ in range(40)}
            if observed != {"test-backend-A", "test-backend-B"}:
                raise AssertionError(f"Real product proxy returned unexpected backends: {observed}")
            print("PASS: real Control Center startup + 40 routed requests to two local backends")
            write_config(cfg, config({"A": addresses["A"]}))
            wait_configuration({"A"})
            after = [curl(GATEWAY + "/ec2/") for _ in range(15)]
            if any(x["status"] != 200 or x["backend"] != "test-backend-A" for x in after):
                raise AssertionError(f"Real Control Center failed live config removal: {after}")
            write_config(cfg, config(addresses))
            wait_configuration({"A", "B"})
            print("PASS: real product config reload removed and re-added a destination without gateway restart")
        finally:
            if gateway:
                gateway.stop()
            for server in servers:
                server.shutdown()
                server.server_close()
            cfg.unlink(missing_ok=True)
            for k, v in original.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


if __name__ == "__main__":
    main()
