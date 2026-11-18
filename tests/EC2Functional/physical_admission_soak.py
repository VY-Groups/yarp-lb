#!/usr/bin/env python3
"""Run a bounded per-destination HTTP soak from an isolated Linux test host.

The caller must start GatewayCore bound to loopback with an opt-in destination
policy. This script starts only a loopback fixture origin and generates traffic
to the local gateway; it never changes Apache, firewall rules, or public listeners.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from http.cookiejar import CookieJar
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import ipaddress
import json
import os
from pathlib import Path
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener, urlopen


def parse_loopback_base(value: str):
    """Accept only plain HTTP to a literal loopback address; never send credentials remotely."""
    try:
        parsed = urlsplit(value)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port or 80
    except (ValueError, TypeError):
        raise ValueError("--base must use HTTP and a literal loopback IP address") from None
    if (parsed.scheme != "http" or not address.is_loopback or parsed.username is not None or
            parsed.password is not None or parsed.path not in ("", "/") or parsed.query or parsed.fragment or
            not 1 <= port <= 65535):
        raise ValueError("--base must be plain HTTP to a loopback IP, without credentials, path, query, or fragment")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return f"http://{host}:{port}", address.compressed, port


class _RegionCertificateParser(HTMLParser):
    def __init__(self, region: str):
        super().__init__(convert_charrefs=True)
        self.section_id = region + "-cert"
        self.section_depth = 0
        self.certificate_depth = 0
        self.collecting = False
        self.parts = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "awsui-expandable-section" and attributes.get("id") == self.section_id:
            self.section_depth = 1
        elif self.section_depth and tag == "dd" and attributes.get("tab-id") == "rsa-2048":
            self.certificate_depth = 1
            self.collecting = True
        elif self.collecting and tag in ("dd", "pre"):
            self.certificate_depth += 1

    def handle_endtag(self, tag):
        if self.collecting and tag in ("dd", "pre"):
            self.certificate_depth -= 1
            if self.certificate_depth <= 0:
                self.collecting = False
        if self.section_depth and tag == "awsui-expandable-section":
            self.section_depth = 0

    def handle_data(self, data):
        if self.collecting:
            self.parts.append(data)


def verify_instance_identity_document(document: bytes, signature_b64: str, certificate_pem: str) -> dict:
    """Verify the exact IMDS identity-document bytes with the region's AWS RSA-2048 certificate."""
    signature = base64.b64decode(signature_b64, validate=True)
    identity = json.loads(document)
    region = identity.get("region")
    instance_id = identity.get("instanceId")
    if not isinstance(region, str) or not isinstance(instance_id, str) or not instance_id.startswith("i-"):
        raise ValueError("invalid EC2 identity document fields")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-ec2-iid-") as directory:
        cert_path = Path(directory, "region.pem")
        key_path = Path(directory, "region-public.pem")
        doc_path = Path(directory, "identity.json")
        sig_path = Path(directory, "identity.sig")
        cert_path.write_text(certificate_pem, encoding="ascii")
        doc_path.write_bytes(document)
        sig_path.write_bytes(signature)
        subprocess.run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout", "-out", str(key_path)],
                       check=True, capture_output=True, timeout=5)
        subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(key_path), "-signature", str(sig_path), str(doc_path)],
                       check=True, capture_output=True, timeout=5)
    return {"instance_id": instance_id, "region": region}


def verified_ec2_identity():
    """Return an identity only after IMDSv2 and AWS's region-specific RSA signature verify."""
    opener = build_opener(ProxyHandler({}))
    base = "http://169.254.169.254/latest/"
    token_request = Request(base + "api/token", data=b"", method="PUT",
                            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"})
    with opener.open(token_request, timeout=1.5) as response:
        token = response.read(4096).decode("ascii").strip()
    if not token:
        return None
    headers = {"X-aws-ec2-metadata-token": token}
    def metadata(path):
        with opener.open(Request(base + path, headers=headers), timeout=1.5) as response:
            return response.read(16384)
    document = metadata("dynamic/instance-identity/document")
    signature = metadata("dynamic/instance-identity/signature").decode("ascii").strip()
    region = json.loads(document).get("region")
    if not isinstance(region, str) or not region or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in region):
        return None
    docs_url = "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html"
    with urlopen(docs_url, timeout=5) as response:
        page = response.read(2_000_000).decode("utf-8", "replace")
    parser = _RegionCertificateParser(region)
    parser.feed(page)
    cert = "".join(parser.parts).strip()
    if not cert.startswith("-----BEGIN CERTIFICATE-----") or not cert.endswith("-----END CERTIFICATE-----"):
        return None
    return verify_instance_identity_document(document, signature, cert)


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
    base, _, _ = parse_loopback_base(base)
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
    try:
        gateway_url, gateway_host, gateway_port = parse_loopback_base(args.base)
    except ValueError as error:
        parser.error(str(error))

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
        opener = admin_client(gateway_url, "physical_soak_admin", password)
        metrics_url = gateway_url + "/gateway/metrics"
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
                        connection = http.client.HTTPConnection(gateway_host, gateway_port, timeout=15)
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
        ec2_identity = None
        try:
            ec2_identity = verified_ec2_identity()
        except Exception:
            # A missing IMDS, bad signature, unavailable AWS certificate source, or
            # absent OpenSSL must never be reported as a verified EC2 environment.
            pass
        payload = {
            "status": "PASS" if results and len(successful) == len(results) else "NO_GO",
            "environment": "EC2 (verified)" if ec2_identity else "local/unverified",
            "ec2_instance_id": ec2_identity["instance_id"] if ec2_identity else None,
            "ec2_region": ec2_identity["region"] if ec2_identity else None,
            "site": args.site,
            "runner_hostname": socket.gethostname(),
            "destination": args.destination,
            "gateway_url": gateway_url,
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
