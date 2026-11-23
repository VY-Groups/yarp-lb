#!/usr/bin/env python3
"""Bounded Docker WAF CPU/memory snapshots for disposable matched lab phases.

This is neither customer capacity nor YARP managed allocation evidence.
Reads local Docker Engine stats only; no network endpoints or credentials.
"""
import argparse
import http.client
import json
from pathlib import Path
import re
import socket
import sys
import time

MAX_STATS_BYTES = 2 * 1024 * 1024
PHASES = ("direct", "proxy-only", "blocking", "detection", "restored")
CONTAINER_ID = re.compile(r"[a-f0-9]{64}\Z")


class LocalDocker(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=8)

    def connect(self):
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(8)
        connection.connect("/var/run/docker.sock")
        self.sock = connection


def _read_stats(container_id):
    if not isinstance(container_id, str) or not CONTAINER_ID.fullmatch(container_id):
        raise ValueError("invalid immutable Docker container identifier")
    con = LocalDocker()
    try:
        con.request("GET", "/containers/" + container_id + "/stats?stream=false")
        response = con.getresponse()
        if response.status != 200:
            raise ValueError("Docker resource stats unavailable")
        raw = response.read(MAX_STATS_BYTES + 1)
        if len(raw) > MAX_STATS_BYTES or not response.isclosed():
            raise ValueError("Docker resource stats unbounded or incomplete")
    finally:
        con.close()
    data = json.loads(raw)
    cpu = data.get("cpu_stats", {}).get("cpu_usage", {}).get("total_usage")
    memory = data.get("memory_stats", {}).get("usage")
    if (type(cpu) is not int or cpu < 0 or
            type(memory) is not int or memory <= 0):
        raise ValueError("Docker resource counters missing")
    return {"schemaVersion": 1, "container": container_id, "cpuNanoseconds": cpu,
            "memoryBytes": memory, "observedAtMonotonicNs": time.monotonic_ns()}


def _strict_json(path):
    source = Path(path).read_bytes()
    if not source or len(source) > 128 * 1024:
        raise ValueError("invalid bounded local resource evidence")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON keys")
            result[key] = value
        return result
    return json.loads(source.decode("utf-8", "strict"), object_pairs_hook=unique_pairs)


def summarize(before, after, phase, benchmark):
    if phase not in PHASES or not isinstance(benchmark, dict):
        raise ValueError("unapproved phase")
    expected_fields = {"schemaVersion", "container", "cpuNanoseconds",
                       "memoryBytes", "observedAtMonotonicNs"}
    for snapshot in (before, after):
        if (not isinstance(snapshot, dict) or set(snapshot) != expected_fields or
                type(snapshot["schemaVersion"]) is not int or
                snapshot["schemaVersion"] != 1 or
                not CONTAINER_ID.fullmatch(snapshot["container"])):
            raise ValueError("untrusted resource snapshot")
        if any(type(snapshot[field]) is not int or snapshot[field] < 0 for field in
               ("cpuNanoseconds", "memoryBytes", "observedAtMonotonicNs")):
            raise ValueError("invalid resource counter")
        if snapshot["memoryBytes"] == 0:
            raise ValueError("missing observed memory")
    if (before["container"] != after["container"] or
            before["cpuNanoseconds"] > after["cpuNanoseconds"] or
            before["observedAtMonotonicNs"] >= after["observedAtMonotonicNs"]):
        raise ValueError("resource snapshot mismatch or counter reset")
    if (benchmark.get("phase") != phase or benchmark.get("complete") is not True or
            type(benchmark.get("requests")) is not int or
            type(benchmark.get("successes")) is not int or
            benchmark["requests"] < 1 or
            benchmark["successes"] != benchmark["requests"] or
            type(benchmark.get("elapsedSeconds")) not in (float, int) or
            benchmark["elapsedSeconds"] <= 0):
        raise ValueError("benchmark invalid or incomplete")
    # The CPU counter is Docker's cumulative WAF-container CPU time, not
    # allocated managed bytes. The two memory samples are NOT peak memory.
    delta = after["cpuNanoseconds"] - before["cpuNanoseconds"]
    return {
        "schemaVersion": 1, "scope": "synthetic-disposable-waf-container-only",
        "phase": phase, "matchedRequests": benchmark["requests"],
        "benchmarkElapsedSeconds": benchmark["elapsedSeconds"],
        "wafCpuSeconds": round(delta / 1e9, 6),
        "wafCpuMillisecondsPerRequest": round(delta / benchmark["requests"] / 1e6, 5),
        "wafMemoryStartBytes": before["memoryBytes"],
        "wafMemoryEndBytes": after["memoryBytes"],
        "managedAllocationsBytes": None,
        "measurementBoundary": "two Docker WAF stats samples bracket one matched synthetic phase",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--container", required=True)
    capture.add_argument("--out", type=Path, required=True)
    report = sub.add_parser("report")
    report.add_argument("--before", type=Path, required=True)
    report.add_argument("--after", type=Path, required=True)
    report.add_argument("--phase", choices=PHASES, required=True)
    report.add_argument("--benchmark", type=Path, required=True)
    report.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "capture":
            result = _read_stats(args.container)
        else:
            result = summarize(_strict_json(args.before), _strict_json(args.after),
                               args.phase, _strict_json(args.benchmark))
        # These files are fixed synthetic CI output, never private operator
        # corpus or Docker configuration; never emit raw stats response.
        args.out.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        print("PASS: bounded synthetic WAF Docker resource evidence")
    except (OSError, TimeoutError, ValueError, KeyError, TypeError,
            json.JSONDecodeError, http.client.HTTPException):
        print("FAIL: missing or inconsistent WAF resource evidence", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
