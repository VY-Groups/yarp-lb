"""Temporary end-to-end loopback diagnostic; remove after this investigation."""
import concurrent.futures
import http.client
import json
import os
import pathlib
import platform
import statistics
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
GATE = ROOT / "tests/L7/GatewayLab/bin/Release/net10.0/GatewayLab.dll"
BACK = ROOT / "tests/L7/BackendLab/bin/Release/net10.0/BackendLab.dll"
OUT = pathlib.Path(os.environ.get("GATEWAYLAB_OTEL_EVIDENCE_DIR", ROOT / "gatewaylab-otel-evidence"))
OUT.mkdir(exist_ok=True)
WORKERS, REQUESTS, WARMUP, PAIRS = 16, 10000, 500, 3

class Receiver(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_POST(self):
        payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        with COUNTS_LOCK:
            COUNTS[self.path.rsplit("/", 1)[-1]] = COUNTS.get(self.path.rsplit("/", 1)[-1], 0) + 1
            BYTES[self.path.rsplit("/", 1)[-1]] = BYTES.get(self.path.rsplit("/", 1)[-1], 0) + len(payload)
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def log_message(self, *args):
        pass
    def handle_error(self, request, client_address):
        pass

class QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        pass

def requests(count):
    each, rem = divmod(count, WORKERS)
    def worker(n):
        conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=15)
        values = []
        for _ in range(n):
            start = time.perf_counter()
            conn.request("GET", "/api/identity")
            response = conn.getresponse()
            body = response.read()
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status}: {body[:120]!r}")
            values.append((time.perf_counter() - start) * 1000)
        conn.close()
        return values
    start = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        values = [x for result in pool.map(worker, [each + (i < rem) for i in range(WORKERS)]) for x in result]
    return time.perf_counter() - start, sorted(values)

def pct(xs, p): return xs[max(0, min(len(xs)-1, int((len(xs)*p + .999999)-1)))]
def measure(enabled, collector):
    env = os.environ.copy()
    env["YARP_LAB_OTEL_OVERHEAD"] = "1"
    if enabled:
        env["YARP_OTEL_ENDPOINT"] = collector
        env["YARP_OTEL_TRACE_SAMPLE_RATIO"] = "0.05"
    else:
        env.pop("YARP_OTEL_ENDPOINT", None)
        env.pop("YARP_OTEL_TRACE_SAMPLE_RATIO", None)
    logfile = open(OUT / ("telemetry-on.log" if enabled else "telemetry-off.log"), "ab", buffering=0)
    with COUNTS_LOCK:
        before_counts = dict(COUNTS)
        before_bytes = dict(BYTES)
    proc = subprocess.Popen(["dotnet", str(GATE)], cwd=GATE.parent, env=env, stdout=logfile, stderr=subprocess.STDOUT)
    try:
        deadline = time.time() + 20
        while time.time() < deadline:
            if proc.poll() is not None: raise RuntimeError(f"Gateway exited {proc.returncode}")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", 18080, timeout=1)
                conn.request("GET", "/lab/ping")
                res = conn.getresponse(); res.read(); conn.close()
                if res.status == 200: break
            except OSError: time.sleep(.1)
        else: raise RuntimeError("Gateway did not become ready")
        requests(WARMUP)
        elapsed, latency = requests(REQUESTS)
        result = {"requestsPerSecond": round(REQUESTS / elapsed, 2),
                  "p50Milliseconds": round(pct(latency, .50), 3),
                  "p95Milliseconds": round(pct(latency, .95), 3),
                  "p99Milliseconds": round(pct(latency, .99), 3)}
        if enabled:
            flush = http.client.HTTPConnection("127.0.0.1", 18080, timeout=15)
            flush.request("POST", "/lab/otel-flush")
            response = flush.getresponse(); response.read(); flush.close()
            if response.status != 200: raise RuntimeError(f"OTLP flush returned HTTP {response.status}")
    finally:
        proc.terminate()
        try: proc.wait(10)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        logfile.close()
    # Exporter shutdown and collector draining happen after the timed request window.
    end = time.monotonic() + 10
    previous = None
    stable_since = time.monotonic()
    while time.monotonic() < end:
        with COUNTS_LOCK: current = dict(COUNTS)
        if current != previous:
            previous = current
            stable_since = time.monotonic()
        elif time.monotonic() - stable_since >= .5:
            break
        time.sleep(.05)
    with COUNTS_LOCK:
        after_counts = dict(COUNTS)
        after_bytes = dict(BYTES)
    delta = {signal: after_counts.get(signal, 0) - before_counts.get(signal, 0)
             for signal in ("traces", "metrics", "logs")}
    delta_bytes = {signal: after_bytes.get(signal, 0) - before_bytes.get(signal, 0)
                   for signal in ("traces", "metrics", "logs")}
    if enabled and (delta["traces"] < 1 or delta["metrics"] < 1 or delta["logs"] < 1):
        raise RuntimeError(f"OTLP collector did not receive all signals after timed window: {delta}")
    return {**result, "collectorRequestsAfterDrain": delta, "collectorBytesAfterDrain": delta_bytes}

receiver = QuietServer(("127.0.0.1", 0), Receiver)
COUNTS, BYTES, COUNTS_LOCK = {}, {}, threading.Lock()
threading.Thread(target=receiver.serve_forever, daemon=True).start()
collector = f"http://127.0.0.1:{receiver.server_port}"
config = {
    "ReverseProxy": {
        "Routes": {"api": {"ClusterId": "api", "Match": {"Path": "/api/{**catch-all}"}}},
        "Clusters": {"api": {"LoadBalancingPolicy": "RoundRobin", "Destinations": {
            "A": {"Address": "http://127.0.0.1:18081/"},
            "B": {"Address": "http://127.0.0.1:18082/"}}}}
    }
}
cfg = OUT / "lab.json"
cfg.write_text(json.dumps(config), encoding="utf-8")
os.environ["YARP_LAB_CONFIG_FILE"] = str(cfg)
backends = [subprocess.Popen(["dotnet", str(BACK), port, node], cwd=BACK.parent,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for port, node in (("18081", "A"), ("18082", "B"))]
try:
    time.sleep(1)
    pairs = []
    for i in range(PAIRS):
        first_on = i % 2 == 1
        first = measure(first_on, collector)
        second = measure(not first_on, collector)
        pairs.append({"pair": i + 1, "telemetryEnabled": first if first_on else second,
                      "telemetryDisabled": second if first_on else first})
    report = {"workload": "GatewayLab full YARP proxy to two local BackendLab processes",
              "os": platform.platform(), "machine": platform.machine(),
              "processor": platform.processor(), "python": platform.python_version(),
              "requestsPerMode": REQUESTS, "warmup": WARMUP,
              "workers": WORKERS, "samplePairs": PAIRS, "samplingRatio": 0.05,
              "connectionPolicy": "16 HTTP/1.1 keep-alive connections, response bodies drained",
              "collector": "disposable loopback HTTP receiver; all traces/metrics/logs drain after timing",
              "median": {
                  "telemetryDisabledRps": round(statistics.median(p["telemetryDisabled"]["requestsPerSecond"] for p in pairs), 2),
                  "telemetryEnabledRps": round(statistics.median(p["telemetryEnabled"]["requestsPerSecond"] for p in pairs), 2),
                  "telemetryDisabledP95Ms": round(statistics.median(p["telemetryDisabled"]["p95Milliseconds"] for p in pairs), 3),
                  "telemetryEnabledP95Ms": round(statistics.median(p["telemetryEnabled"]["p95Milliseconds"] for p in pairs), 3),
                  "throughputChangePercent": round(statistics.median((p["telemetryEnabled"]["requestsPerSecond"] / p["telemetryDisabled"]["requestsPerSecond"] - 1) * 100 for p in pairs), 3),
                  "p95ChangePercent": round(statistics.median((p["telemetryEnabled"]["p95Milliseconds"] / p["telemetryDisabled"]["p95Milliseconds"] - 1) * 100 for p in pairs), 3)
              },
              "paired": [{**p,
                  "throughputChangePercent": round((p["telemetryEnabled"]["requestsPerSecond"] / p["telemetryDisabled"]["requestsPerSecond"] - 1) * 100, 3),
                  "p95ChangePercent": round((p["telemetryEnabled"]["p95Milliseconds"] / p["telemetryDisabled"]["p95Milliseconds"] - 1) * 100, 3)} for p in pairs]}
    path = OUT / "report.json"
    path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
finally:
    receiver.shutdown(); receiver.server_close()
    for proc in backends:
        proc.terminate()
        try: proc.wait(10)
        except subprocess.TimeoutExpired: proc.kill(); proc.wait()
