#!/usr/bin/env python3
"""Bounded synthetic WAF comparison; runs only in disposable private compose network."""
import concurrent.futures
import http.client
import json
import math
import sys
import time

PHASES = ("direct", "proxy-only", "blocking", "detection", "restored")
REQUESTS = 120
CONCURRENCY = 4
PAYLOAD = b'{"service":"fixture","operation":"inventory","count":42}'
WORKLOAD = "alternating-fixed-get-json-post-http1-close-v1"

def request(index, host, port):
    started = time.perf_counter()
    connection = http.client.HTTPConnection(host, port, timeout=5)
    try:
        if index % 2:
            connection.request("POST", "/acceptance", PAYLOAD,
                {"Content-Type": "application/json", "Connection": "close", "Host": "localhost"})
        else:
            connection.request("GET", "/", headers={"Connection": "close", "Host": "localhost"})
        response = connection.getresponse()
        body = response.read(4096)
        if response.status != 200:
            return None, f"http-{response.status}"
        if index % 2:
            expected = {"accepted": True, "contentType": "application/json", "bytes": len(PAYLOAD)}
            if json.loads(body) != expected:
                return None, "invalid-body"
        elif body != b"YARP-WAF-CI-BENIGN\n":
            return None, "invalid-body"
        return (time.perf_counter() - started) * 1000, None
    except (OSError, http.client.HTTPException, ValueError) as error:
        return None, type(error).__name__
    finally:
        connection.close()

def percentile(values, proportion):
    return round(values[math.ceil(len(values) * proportion) - 1], 3) if values else None

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in PHASES:
        raise SystemExit("Expected disposable lab phase")
    phase = sys.argv[1]
    host, port = ("protected-app", 8000) if phase == "direct" else ("waf", 8080)
    started = time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        results = list(pool.map(lambda i: request(i, host, port), range(REQUESTS)))
    elapsed = time.perf_counter() - started
    latencies = sorted(value for value, error in results if error is None)
    errors = {}
    for _, error in results:
        if error is not None:
            errors[error] = errors.get(error, 0) + 1
    complete = len(latencies) == REQUESTS
    print(json.dumps({"phase": phase, "workload": WORKLOAD, "requests": REQUESTS,
        "concurrency": CONCURRENCY, "successes": len(latencies),
        "errors": REQUESTS - len(latencies), "errorCategories": errors,
        "complete": complete, "elapsedSeconds": round(elapsed, 6),
        "successfulRequestsPerSecond": round(len(latencies) / elapsed, 3),
        "p50Ms": percentile(latencies, .50) if complete else None,
        "p95Ms": percentile(latencies, .95) if complete else None,
        "p99Ms": percentile(latencies, .99) if complete else None}, sort_keys=True))
    return 0 if complete else 1

if __name__ == "__main__":
    sys.exit(main())
