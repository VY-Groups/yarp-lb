#!/usr/bin/env python3
"""HTTP checks for two CI Docker ingress containers and real shipping YARP instances.
No production connectivity. JSON artifact includes *every* observed failure.
"""
import argparse
import json
import ssl
import subprocess
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-f", str(ROOT / "compose.yml")]
RESULTS = {"scenario": "CI-only version 0.1 single-host Docker namespaces", "observations": []}


def http(url, method="GET", payload=None, trusted_cert=None, timeout=4):
    context = ssl.create_default_context(cafile=str(trusted_cert)) if trusted_cert else None
    request = Request(url, data=payload, method=method)
    try:
        with urlopen(request, timeout=timeout, context=context) as response:
            return response.status, response.read(), response.headers
    except HTTPError as error:
        return error.code, error.read(), error.headers


def check(condition, message, **details):
    RESULTS["observations"].append({"ok": bool(condition), "check": message, **details})
    if not condition:
        raise AssertionError(message + (" " + repr(details) if details else ""))


def compose_exec(service, *args):
    return subprocess.check_output(COMPOSE + ["exec", "-T", service] + list(args), text=True, timeout=30)


def wait_ready():
    deadline = time.monotonic() + 135
    while time.monotonic() < deadline:
        try:
            for url in ("http://127.0.0.1:18080/api/identity", "http://127.0.0.1:18081/api/identity"):
                code, _, _ = http(url)
                if code != 200:
                    raise RuntimeError("not ready")
            return
        except (URLError, TimeoutError, RuntimeError, ConnectionError):
            time.sleep(1)
    raise AssertionError("Both Docker ingress endpoints never became ready")


def request_samples(url, number, cert=None, allow_initial_failures=False):
    rows = []
    for i in range(number):
        started = time.monotonic()
        try:
            status, raw, _ = http(url, trusted_cert=cert)
            node = json.loads(raw).get("node") if status == 200 else None
            rows.append({"status": status, "node": node, "ms": round((time.monotonic()-started)*1000, 3)})
        except (URLError, TimeoutError, ConnectionError) as error:
            rows.append({"status": 0, "error": type(error).__name__, "ms": round((time.monotonic()-started)*1000, 3)})
    failed = [row for row in rows if row["status"] != 200]
    check(not failed or allow_initial_failures, "request failure bound", url=url, count=number, failed=failed[:30])
    if allow_initial_failures:
        check(all(row["status"] == 200 for row in rows[-30:]), "last 30 requests recover without errors", url=url)
    check(set(row["node"] for row in rows if row["status"] == 200).issubset({"A","B"}), "responses originate from expected backends")
    RESULTS["observations"].append({"check": "requests", "url": url, "count": number,
                                    "failedCount": len(failed), "last30success": all(r["status"] == 200 for r in rows[-30:]),
                                    "backendNames": sorted({r["node"] for r in rows if r["node"]})})
    return rows


def verify_gateway_metrics():
    for gateway in ("gateway-a", "gateway-b"):
        metrics = compose_exec(gateway, "curl", "-fsS", "http://127.0.0.1:8080/gateway/metrics")
        for name in ("yarp_control_http_requests_total", "yarp_control_gc_collections_total",
                     "yarp_logging_dropped_total", "yarp_control_http_duration_seconds_bucket"):
            check(name in metrics, "real loopback shipping metric " + name, gateway=gateway)
        status, _, _ = http("http://127.0.0.1:18080/gateway/metrics")
        check(status == 403, "remote metrics blocked at ingress", status=status)
    status, _, _ = http("http://127.0.0.1:18080/dashboard")
    check(status == 403, "remote administration denied", status=status)


def verify_no_replay():
    ids = []
    for i in range(24):
        identifier = f"ci01unique{i:08d}"
        status, raw, _ = http("http://127.0.0.1:18080/api/transaction/" + identifier,
                              method="POST", payload=b"lab")
        check(status == 200 and json.loads(raw).get("appliedCount") == 1,
              "non-idempotent test request is not replayed", request_id=identifier, http_status=status)
        ids.append(identifier)
    for backend in ("backend-a", "backend-b"):
        py = """import json,sys,urllib.request
base='http://127.0.0.1:8080/lab/count/'
for key in sys.argv[1:]:
    item=json.load(urllib.request.urlopen(base+key))
    if item['count'] > 1:
        raise SystemExit('DUPLICATE '+key+' '+repr(item))
print('ok',len(sys.argv)-1)
"""
        result = compose_exec(backend, "python", "-c", py, *ids)
        check(result.startswith("ok "), "backend no-replay audit", backend=backend)


def verify_prometheus():
    for gateway in ("gateway-a", "gateway-b"):
        url = "http://" + gateway + ":9090/api/v1/query?query=up%7Bjob%3D%22speedsign-gateway%22%7D"
        # Query from the other gateway, which has curl; cannot directly reach private Docker network from host.
        other = "gateway-b" if gateway == "gateway-a" else "gateway-a"
        response = compose_exec(other, "curl", "-fsS", url)
        parsed = json.loads(response)
        values = parsed.get("data", {}).get("result", [])
        check(parsed.get("status") == "success" and values and values[0]["value"][1] == "1",
              "Prometheus real local scrape up=1", gateway=gateway, values=values)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--phase", required=True, choices=("baseline", "gateway-loss", "ingress-loss", "recovered"))
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    RESULTS["phase"] = args.phase
    args.out.parent.mkdir(parents=True, exist_ok=True)
    failure = None
    try:
        if args.phase in ("baseline", "recovered"):
            wait_ready()
            a = request_samples("http://127.0.0.1:18080/api/identity", 80)
            b = request_samples("http://127.0.0.1:18081/api/identity", 80)
            check({x["node"] for x in a+b if x["node"]} == {"A","B"}, "both backend nodes actually used")
            request_samples("https://127.0.0.1:18443/api/identity", 20, ROOT / "certs/server.crt")
            if args.phase == "baseline":
                verify_gateway_metrics()
                verify_no_replay()
                # Prometheus may need several seconds to scrape the gateway.
                deadline = time.monotonic() + 45
                while True:
                    try:
                        verify_prometheus()
                        break
                    except (AssertionError, subprocess.CalledProcessError):
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(2)
        elif args.phase == "gateway-loss":
            request_samples("http://127.0.0.1:18080/api/identity", 80, allow_initial_failures=True)
            request_samples("http://127.0.0.1:18081/api/identity", 80, allow_initial_failures=True)
        elif args.phase == "ingress-loss":
            request_samples("http://127.0.0.1:18081/api/identity", 80)
            request_samples("https://127.0.0.1:18444/api/identity", 20, ROOT / "certs/server.crt")
    except Exception as error:
        failure = str(error)
        RESULTS["error"] = failure
    finally:
        RESULTS["passed"] = failure is None
        args.out.write_text(json.dumps(RESULTS, indent=2))
        print(json.dumps({"phase": args.phase, "passed": RESULTS["passed"], "error": failure,
                          "checks": len(RESULTS["observations"])}, indent=2))
    if failure:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
