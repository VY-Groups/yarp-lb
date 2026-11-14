#!/usr/bin/env python3
"""Issue #17: single-shot, loopback-only hung-gateway watchdog for disposable CI.

The watchdog is intentionally independent of the gateway's ASP.NET thread pool.
It records every probe and launches diagnostics once, before the load rig exits.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from urllib import error, parse, request
from datetime import datetime, timezone


def local_http(url: str) -> bool:
    parsed = parse.urlparse(url)
    return parsed.scheme == "http" and parsed.hostname in {"127.0.0.1", "localhost"} and not parsed.username


def probe(url: str, seconds: float) -> dict:
    start = time.monotonic()
    result = {"url": url, "at": datetime.now(timezone.utc).isoformat(), "status": None, "error": None}
    try:
        opener = request.build_opener(request.ProxyHandler({}))
        with opener.open(request.Request(url, method="GET"), timeout=seconds) as reply:
            result["status"] = reply.status
            reply.read(256)
    except (error.HTTPError, error.URLError, TimeoutError, OSError) as ex:
        if isinstance(ex, error.HTTPError):
            result["status"] = ex.code
        result["error"] = type(ex).__name__ + ": " + str(ex)[:200]
    result["elapsed_ms"] = round((time.monotonic() - start) * 1000, 2)
    result["healthy"] = result["status"] == 200 and result["elapsed_ms"] < seconds * 1000
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--backend-url", action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--capture-script", type=Path, required=True)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--timeout", type=float, default=3)
    args = parser.parse_args()
    urls = [args.gateway_url, *args.backend_url]
    if args.pid <= 1 or not all(map(local_http, urls)) or not 0.1 <= args.timeout <= 10 or not 0.1 <= args.interval <= 60:
        parser.error("Watchdog requires a valid PID and loopback HTTP targets with bounded intervals")
    args.output.mkdir(parents=True, exist_ok=True)
    probes_path = args.output / "health-probes.jsonl"
    while True:
        try:
            os.kill(args.pid, 0)
        except ProcessLookupError:
            (args.output / "process-exited.json").write_text(json.dumps({"pid": args.pid}))
            return 2
        p = probe(args.gateway_url, args.timeout)
        with probes_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(p) + "\n")
        if not p["healthy"]:
            marker = args.output / "hang-trigger.json"
            marker.write_text(json.dumps(p, indent=2), encoding="utf-8")
            # Capture first, including thread stacks and dump. Backend probes
            # run afterwards so they do not delay the hang capture.
            try:
                subprocess.run(["bash", str(args.capture_script), str(args.pid),
                                str(args.output)], timeout=175, check=False)
            except (OSError, subprocess.TimeoutExpired) as ex:
                (args.output / "capture-error.txt").write_text(str(ex), encoding="utf-8")
            with (args.output / "backend-probes.jsonl").open("w", encoding="utf-8") as output:
                for target in args.backend_url:
                    output.write(json.dumps(probe(target, args.timeout)) + "\n")
            (args.output / "capture-complete").write_text("done\n", encoding="utf-8")
            return 2
        time.sleep(args.interval)


if __name__ == "__main__":
    sys.exit(main())
