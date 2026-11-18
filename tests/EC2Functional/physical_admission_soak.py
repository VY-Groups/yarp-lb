#!/usr/bin/env python3
"""Run a bounded per-destination HTTP soak from an isolated Linux test host.

The caller must start GatewayCore bound to loopback with an opt-in destination
policy. This script starts only a loopback fixture origin and generates traffic
to the local gateway; it never changes Apache, firewall rules, or public listeners.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import os
from pathlib import Path
import socket
import statistics
import threading
import time
from urllib.error import HTTPError
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        time.sleep(0.2)
        body = ("physical-test-origin " + self.path + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def admin_client(base: str, user: str, password: str):
    opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))

    def post(path: str, payload: dict):
        data = json.dumps(payload).encode()
        req = Request(base + path, data=data, method="POST",
                      headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=10) as response:
                return response.status, response.read()
        except HTTPError as error:
            return error.code, error.read()

    status, _ = post("/admin/api/bootstrap", {
        "username": user, "password": password,
        "email": "physical-test@example.invalid"})
    if status == 409:
        status, body = post("/admin/api/login", {"username": user, "password": password})
        if status != 200:
            raise RuntimeError(f"gateway admin login failed: HTTP {status}")
    elif status not in (200, 201):
        raise RuntimeError(f"gateway bootstrap failed: HTTP {status}")
    return opener


def scrape_metrics(opener, url: str):
    request = Request(url, headers={"Accept": "text/plain"})
    with opener.open(request, timeout=10) as response:
        if response.status != 200:
            raise RuntimeError(f"metrics scrape failed: HTTP {response.status}")
        text = response.read().decode("utf-8", "replace")

    values = {}
    for metric in ("inflight_requests", "queued_requests", "rejected_total",
                   "queue_timeouts_total", "waiter_canceled_total"):
        name = "yarp_control_destination_admission_" + metric
        for line in text.splitlines():
            if line.startswith(name + "{"):
                try:
                    values[metric] = float(line.rsplit(" ", 1)[1])
                except (IndexError, ValueError):
                    pass
                break
    return values


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", default="http://127.0.0.1:18080")
    parser.add_argument("--path", default="/admit/hold")
    parser.add_argument("--duration-seconds", type=int, default=3600)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--site", required=True)
    parser.add_argument("--destination", default="fixture/origin")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not 1 <= args.duration_seconds <= 14400 or not 1 <= args.workers <= 128:
        parser.error("duration must be 1..14400 seconds and workers 1..128")
    if not args.path.startswith("/") or "?" in args.path or "#" in args.path:
        parser.error("path must be an absolute path without query or fragment")

    password_file = os.environ.get("GATEWAYCORE_TEST_PASSWORD_FILE")
    password = (Path(password_file).read_text(encoding="utf-8").strip()
                if password_file else os.environ.get("GATEWAYCORE_TEST_PASSWORD"))
    if not password or len(password) < 16:
        parser.error("set GATEWAYCORE_TEST_PASSWORD to a temporary 16+ character password")

    origin = ThreadingHTTPServer(("127.0.0.1", 18081), Origin)
    origin_thread = threading.Thread(target=origin.serve_forever, daemon=True)
    origin_thread.start()
    opener = None
    try:
        opener = admin_client(args.base, "physical_soak_admin", password)
        metrics_url = args.base.rstrip("/") + "/gateway/metrics"
        sample_metrics = scrape_metrics(opener, metrics_url)
        if not {"inflight_requests", "queued_requests"}.issubset(sample_metrics):
            raise RuntimeError("configured admission destination metrics are missing")

        stop_at = time.monotonic() + args.duration_seconds
        start_epoch = time.time()
        lock = threading.Lock()
        results = []
        samples = []

        def worker():
            connection = None
            while time.monotonic() < stop_at:
                started = time.monotonic()
                status = 0
                error = ""
                try:
                    if connection is None:
                        target = args.base.removeprefix("http://").removeprefix("https://")
                        host, _, port_text = target.partition(":")
                        connection = http.client.HTTPConnection(host, int(port_text or 80), timeout=15)
                    connection.request("GET", args.path, headers={"Connection": "keep-alive"})
                    response = connection.getresponse()
                    body = response.read()
                    status = response.status
                    if status != 200 or not body.startswith(b"physical-test-origin "):
                        error = f"unexpected_http_{status}"
                except Exception as exc:  # record actual failures; never retry a failed request
                    error = type(exc).__name__
                    if connection is not None:
                        connection.close()
                        connection = None
                ended = time.monotonic()
                with lock:
                    results.append((started, ended, status, error))
            if connection is not None:
                connection.close()

        def metric_sampler():
            while time.monotonic() < stop_at:
                try:
                    values = scrape_metrics(opener, metrics_url)
                    values["timestamp_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
                    with lock:
                        samples.append(values)
                except Exception as exc:
                    with lock:
                        samples.append({"timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                        "scrape_error": type(exc).__name__})
                time.sleep(10)

        sampler = threading.Thread(target=metric_sampler, daemon=True)
        sampler.start()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(worker) for _ in range(args.workers)]
            for future in futures:
                future.result()
        sampler.join(timeout=12)

        elapsed = time.monotonic() - (stop_at - args.duration_seconds)
        successful = [item for item in results if not item[3]]
        latencies = sorted((item[1] - item[0]) * 1000 for item in successful)
        p99 = latencies[max(0, int(0.99 * len(latencies) + 0.999999) - 1)] if latencies else None
        payload = {
            "status": "PASS" if results and len(successful) == len(results) else "NO_GO",
            "environment": "physical EC2 host; loopback gateway and fixture origin",
            "site": args.site,
            "runner_hostname": socket.gethostname(),
            "destination": args.destination,
            "gateway_url": args.base,
            "path": args.path,
            "workers": args.workers,
            "requested_duration_seconds": args.duration_seconds,
            "elapsed_seconds": round(elapsed, 3),
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_epoch)),
            "end_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "requests": len(results),
            "successes": len(successful),
            "errors": len(results) - len(successful),
            "requests_per_second": round(len(results) / max(elapsed, 0.001), 3),
            "p99_latency_ms": round(p99, 3) if p99 is not None else None,
            "admission_metric_samples": samples,
            "http_error_types": sorted({item[3] for item in results if item[3]}),
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({key: payload[key] for key in
                          ("status", "site", "runner_hostname", "elapsed_seconds",
                           "requests", "successes", "errors", "p99_latency_ms")}))
        if payload["status"] != "PASS" or elapsed < args.duration_seconds:
            raise SystemExit(1)
    finally:
        origin.shutdown()
        origin.server_close()
        origin_thread.join(timeout=3)


if __name__ == "__main__":
    main()
