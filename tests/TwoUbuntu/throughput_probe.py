#!/usr/bin/env python3
"""Strict per-minute HTTP body-byte measurement for synthetic CI loads.

Never equivalent to an on-prem wire-speed benchmark or actual traffic mix.
"""
import argparse
import concurrent.futures
import http.client
import json
import math
import os
import socket
import statistics
import threading
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit


def measure(url, duration_seconds, workers, expected_bytes):
    target = urlsplit(url)
    if target.scheme != "http" or not target.hostname or target.query or target.fragment:
        raise ValueError("This isolated smoke supports HTTP only; HTTPS is a distinct workload")
    if expected_bytes < 1 or expected_bytes > 1048576:
        raise ValueError("Expected body size must be 1..1048576 bytes")
    start = time.monotonic()
    stop = start + duration_seconds
    batches = []
    lock = threading.Lock()

    def worker():
        connection = None
        data = []
        while time.monotonic() < stop:
            began = time.monotonic()
            try:
                if connection is None:
                    connection = http.client.HTTPConnection(target.hostname, target.port or 80, timeout=8)
                connection.request("GET", target.path or "/", headers={"Connection": "keep-alive"})
                response = connection.getresponse()
                body = response.read()
                if response.status != 200 or len(body) != expected_bytes:
                    raise ValueError(f"HTTP {response.status}, body={len(body)}")
                data.append((began, time.monotonic(), len(body), None))
            except (OSError, ValueError, TimeoutError, http.client.HTTPException) as e:
                data.append((began, time.monotonic(), 0, type(e).__name__))
                if connection is not None:
                    try:
                        connection.close()
                    except OSError:
                        pass
                connection = None
        if connection:
            connection.close()
        with lock:
            batches.extend(data)

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(worker) for _ in range(workers)]
        for future in futures:
            future.result()
    actual = time.monotonic() - start
    buckets = defaultdict(lambda: {"bytes": 0, "requests": 0, "errors": 0, "latencies_ms": []})
    for began, ended, size, error in batches:
        idx = int((ended - start) // 60)
        if idx >= math.ceil(duration_seconds / 60):
            continue
        b = buckets[idx]
        if error:
            b["errors"] += 1
        else:
            b["bytes"] += size
            b["requests"] += 1
            b["latencies_ms"].append((ended - began) * 1000)
    windows = []
    for idx in range(math.ceil(duration_seconds / 60)):
        b = buckets[idx]
        seconds = min(60, duration_seconds - idx * 60)
        lat = sorted(b["latencies_ms"])
        p99 = lat[max(0, math.ceil(0.99 * len(lat))-1)] if lat else None
        windows.append({"index": idx, "seconds": seconds, "body_bytes": b["bytes"],
                        "body_mbps": round(b["bytes"] * 8 / seconds / 1e6, 4),
                        "requests": b["requests"], "errors": b["errors"],
                        "p99_ms": p99})
    return {"wall_seconds": round(actual, 3), "windows": windows,
            "total_errors": sum(w["errors"] for w in windows),
            "total_requests": sum(w["requests"] for w in windows)}


def accept(result, target_mbps, p99_ms, strict):
    windows = result["windows"]
    if result["total_requests"] == 0 or result["total_errors"] != 0:
        return False, "zero responses or HTTP/transport errors"
    if strict and any(w["seconds"] != 60 for w in windows):
        return False, "strict sustained run must contain complete 60s windows"
    if strict and len(windows) != 60:
        return False, "strict run requires exactly 60 complete minutes"
    if strict and any(w["body_mbps"] < target_mbps for w in windows):
        return False, "at least one full minute below requested HTTP body Mbps floor"
    if strict and any(w["p99_ms"] is None or w["p99_ms"] >= p99_ms for w in windows):
        return False, "p99 exceeds approved ceiling"
    return True, "synthetic runner result accepted (not on-prem qualification)"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--url", required=True)
    p.add_argument("--seconds", type=int, default=15)
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--body-bytes", type=int, default=1048576)
    p.add_argument("--target-mbps", type=float, default=750)
    p.add_argument("--p99-ms", type=float, default=250)
    p.add_argument("--strict", action="store_true")
    p.add_argument("--site", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    if args.seconds not in (15, 3600) or args.workers not in range(1,129):
        p.error("15-second smoke or 60-minute strict run, workers 1..128 only")
    if args.strict and args.seconds != 3600:
        p.error("strict requires 60 minutes")
    result = measure(args.url, args.seconds, args.workers, args.body_bytes)
    passed, detail = accept(result, args.target_mbps, args.p99_ms, args.strict)
    result.update({"site": args.site, "runner_hostname": socket.gethostname(),
                   "head_sha": os.getenv("GITHUB_SHA", ""), "strict": args.strict,
                   "target_body_mbps": args.target_mbps, "p99_limit_ms": args.p99_ms,
                   "status": "PASS" if passed else "NO_GO", "reason": detail,
                   "environment": "GitHub-hosted shared cloud VM, HTTP synthetic fixed 1MiB body"})
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2) + "\n")
    print(json.dumps({key:result[key] for key in
          ("site","runner_hostname","strict","status","reason","total_requests","total_errors")}))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
