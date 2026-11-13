#!/usr/bin/env python3
"""Fail-closed direct-backend vs same-host YARP allocation evidence analyzer.

Gross allocation deltas include other gateway work (health, logging, stats).
The idle direct interval estimates background overhead; this is not a precise
per-request allocation profiler, especially with async continuations.
"""
import json
from pathlib import Path
import sys


def summarize(root: Path) -> dict:
    records = {}
    for mode in ("direct", "proxy"):
        a = json.loads((root / f"{mode}-before.json").read_text())
        b = json.loads((root / f"{mode}-after.json").read_text())
        summary = json.loads((root / f"{mode}-k6.json").read_text())["metrics"]
        elapsed = (int((root / f"{mode}-end-ms.txt").read_text()) -
                   int((root / f"{mode}-start-ms.txt").read_text())) / 1000
        requests = summary["http_reqs"]["count"]
        failed = summary["http_req_failed"]["value"]
        checks = summary["checks"]["value"]
        alloc = b["allocatedBytesTotal"] - a["allocatedBytesTotal"]
        if not 30 <= elapsed <= 115 or requests < 1000 or not 0 <= failed < 0.01 or checks <= 0.995:
            raise ValueError(f"{mode}: workload unsuccessful or duration invalid")
        if alloc < 0 or a["processId"] != b["processId"]:
            raise ValueError(f"{mode}: gateway restarted or allocation counter reset")
        if b["gc2Collections"] < a["gc2Collections"]:
            raise ValueError(f"{mode}: invalid GC collection counter")
        records[mode] = {
            "duration_seconds": elapsed,
            "http_requests": requests,
            "failed_rate": failed,
            "checks_rate": checks,
            "http_p95_ms": summary["http_req_duration"]["p(95)"],
            "http_p99_ms": summary["http_req_duration"]["p(99)"],
            "gateway_allocated_bytes": alloc,
            "gateway_workingset_delta_bytes": b["processWorkingSetBytes"] - a["processWorkingSetBytes"],
            "gateway_gc2_delta": b["gc2Collections"] - a["gc2Collections"],
            "gateway_logging_drops_delta": b.get("loggingDroppedTotal",0)-a.get("loggingDroppedTotal",0),
        }
    direct = records["direct"]
    proxy = records["proxy"]
    estimated = (proxy["gateway_allocated_bytes"]
                 - direct["gateway_allocated_bytes"] *
                   proxy["duration_seconds"] / direct["duration_seconds"])
    return {
        "direct": direct,
        "proxy": proxy,
        "estimated_additional_gateway_allocated_bytes_per_proxied_request":
            round(estimated / proxy["http_requests"], 2),
        "measurement_caveat": (
            "Net gateway allocation minus scaled idle-gateway allocation per proxy "
            "request; includes app log/stats/health overhead, not exact YARP intrinsic allocations. "
            "Compare identical hardware/workload and do not infer production-scale capacity."),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: compare.py <artifact-folder>", file=sys.stderr)
        return 64
    folder = Path(sys.argv[1])
    report = summarize(folder)
    (folder / "allocation-report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
