#!/usr/bin/env python3
"""Strict *evidence* gate for matched Windows/Linux direct/YARP/YARP+WAF runs.

This does NOT generate HTTP traffic or assert a real site has been tested.
The controller must supply independent, private, genuine per-minute run
evidence. All thresholds are preapproved policy values, never inferred
or relaxed from measured results; origin success is mandatory.
"""
import argparse
import datetime as dt
import json
import math
from pathlib import Path
import re
import sys

from corpus_evidence_gate import read_bounded_utf8, write_private_report

PLATFORMS = ("windows", "linux")
PATHS = ("direct", "yarp", "yarp_waf")
SHA = re.compile(r"[a-f0-9]{40}\Z", re.ASCII)
HEX = re.compile(r"[A-F0-9]{64}\Z", re.ASCII)
IMAGE = re.compile(r"owasp/modsecurity-crs@sha256:[a-f0-9]{64}\Z", re.ASCII)
MAX_JSON_BYTES = 12 * 1024 * 1024


def parse_strict_json(raw):
    """Fail closed on alternate duplicate-key policy interpretations."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate evidence/policy JSON property")
            result[key] = value
        return result
    value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           ValueError("nonfinite numeric evidence")))
    if type(value) is not dict:
        raise ValueError("evidence/policy must be a JSON object")
    return value


def load_strict(path):
    # No symlink, FIFO, unbounded or mutable evidence files.
    data = read_bounded_utf8(path, MAX_JSON_BYTES).encode("utf-8", "strict")
    if not data:
        raise ValueError("empty measured capacity evidence")
    return parse_strict_json(data)


def positive(value):
    return type(value) in (int, float) and math.isfinite(value) and value > 0


def nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def utc_seconds(value):
    if type(value) is not str or not value.endswith("Z") or len(value) > 32:
        raise ValueError("UTC timestamp with terminal Z required")
    moment = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    if moment.utcoffset() != dt.timedelta():
        raise ValueError("non-UTC timestamp")
    return moment.timestamp()


def check_policy(p):
    if (type(p) is not dict or
            set(p) != {
                "schemaVersion", "sourceSha", "wafImageDigest",
                "trafficProfileSha256", "httpVersion", "keepalive", "concurrency", "windowSeconds",
                "windowCount", "peakBodyGbps", "headroom",
                "maxP95Ms", "maxP99Ms", "maxWafP99Multiplier",
                "maxCpuUtilizationPercent", "maxAllocatedBytesPerRequest",
                "maxGcPauseMsPerWindow", "allowedHttpStatus"
            } or
            type(p["schemaVersion"]) is not int or p["schemaVersion"] != 1 or
            type(p["sourceSha"]) is not str or not SHA.fullmatch(p["sourceSha"]) or
            type(p["wafImageDigest"]) is not str or
            not IMAGE.fullmatch(p["wafImageDigest"]) or
            type(p["trafficProfileSha256"]) is not str or
            not HEX.fullmatch(p["trafficProfileSha256"]) or
            p["httpVersion"] not in ("1.1", "2") or
            type(p["keepalive"]) is not bool or
            (p["httpVersion"] == "2" and not p["keepalive"]) or
            type(p["concurrency"]) is not int or p["concurrency"] < 1 or
            type(p["windowSeconds"]) is not int or
            p["windowSeconds"] not in (60, 120, 300) or
            type(p["windowCount"]) is not int or p["windowCount"] < 1 or
            p["windowCount"] > 240 or
            p["windowCount"] * p["windowSeconds"] < 3600 or
            not positive(p["peakBodyGbps"]) or
            p["peakBodyGbps"] < 0.5 or
            p["headroom"] not in (0.3, 0.5) or
            not positive(p["maxP95Ms"]) or not positive(p["maxP99Ms"]) or
            p["maxP95Ms"] > p["maxP99Ms"] or
            not positive(p["maxWafP99Multiplier"]) or
            p["maxWafP99Multiplier"] < 1 or
            not positive(p["maxCpuUtilizationPercent"]) or
            p["maxCpuUtilizationPercent"] > 100 or
            not positive(p["maxAllocatedBytesPerRequest"]) or
            not nonnegative(p["maxGcPauseMsPerWindow"]) or
            p["allowedHttpStatus"] != [200]):
        raise ValueError("unapproved or incomplete matched WAF capacity policy")
    return p["peakBodyGbps"] * (1 + p["headroom"])


def gate(policy, evidence):
    minimum = check_policy(policy)
    if type(evidence) is not dict or set(evidence) != {"schemaVersion", "runs"} or \
            type(evidence["schemaVersion"]) is not int or evidence["schemaVersion"] != 1 or \
            type(evidence["runs"]) is not dict or set(evidence["runs"]) != set(PLATFORMS):
        raise ValueError("both Windows/Linux measured paths required")
    summary = {"schemaVersion": 1, "decision": "GO",
               "requiredBodyGbps": minimum, "runs": {}, "errors": []}
    issues = summary["errors"]
    seen_raw_window_digests = set()
    for platform in PLATFORMS:
        runs = evidence["runs"][platform]
        if type(runs) is not dict or set(runs) != set(PATHS):
            raise ValueError("direct, YARP, YARP+WAF required on each platform")
        summary["runs"][platform] = {}
        starts = {}
        for path in PATHS:
            run = runs[path]
            if type(run) is not dict or set(run) != {
                "platform", "path", "sourceSha", "trafficProfileSha256",
                "wafImageDigest", "httpVersion", "keepalive",
                "concurrency", "windowSeconds", "hostCpuCores", "windows"
            }:
                raise ValueError("missing or ambiguous measured run metadata")
            if run["platform"] != platform or run["path"] != path or \
                    run["sourceSha"] != policy["sourceSha"] or \
                    run["trafficProfileSha256"] != policy["trafficProfileSha256"] or \
                    (run["wafImageDigest"] != policy["wafImageDigest"]
                     if path == "yarp_waf" else run["wafImageDigest"] is not None) or \
                    run["httpVersion"] != policy["httpVersion"] or \
                    run["keepalive"] != policy["keepalive"] or \
                    run["concurrency"] != policy["concurrency"] or \
                    run["windowSeconds"] != policy["windowSeconds"] or \
                    type(run["hostCpuCores"]) is not int or run["hostCpuCores"] < 1:
                raise ValueError("unmatched run source/CRS/traffic/concurrency metadata")
            samples = run["windows"]
            if type(samples) is not list or len(samples) != policy["windowCount"]:
                raise ValueError("incomplete full-hour measured windows")
            previous_end = None
            min_gbps = float("inf")
            max_p99 = 0.0
            run_duration = 0.0
            for i, sample in enumerate(samples):
                if type(sample) is not dict or set(sample) != {
                    "index", "startUtc", "endUtc", "requests",
                    "errors", "unexpectedStatuses", "responseBodyBytes",
                    "p95Ms", "p99Ms", "cpuSeconds",
                    "allocatedBytes", "gcPauseMs", "rawWindowSha256"
                }:
                    raise ValueError("incomplete native capacity measurement window")
                if type(sample["index"]) is not int or sample["index"] != i or \
                        type(sample["requests"]) is not int or sample["requests"] <= 0 or \
                        type(sample["errors"]) is not int or sample["errors"] < 0 or \
                        type(sample["unexpectedStatuses"]) is not int or \
                        sample["unexpectedStatuses"] < 0 or \
                        type(sample["responseBodyBytes"]) is not int or \
                        sample["responseBodyBytes"] <= 0 or \
                        type(sample["rawWindowSha256"]) is not str or \
                        not HEX.fullmatch(sample["rawWindowSha256"]) or \
                        not nonnegative(sample["p95Ms"]) or \
                        not nonnegative(sample["p99Ms"]) or \
                        sample["p99Ms"] < sample["p95Ms"] or \
                        not nonnegative(sample["cpuSeconds"]):
                    raise ValueError("invalid measured window counters/digest")
                digest = sample["rawWindowSha256"]
                if digest in seen_raw_window_digests:
                    raise ValueError("same raw window evidence reused across paths or minutes")
                seen_raw_window_digests.add(digest)
                if path == "direct":
                    if sample["allocatedBytes"] is not None or sample["gcPauseMs"] is not None:
                        raise ValueError("direct origin cannot fabricate YARP allocation data")
                else:
                    if type(sample["allocatedBytes"]) is not int or \
                            sample["allocatedBytes"] < 0 or \
                            not nonnegative(sample["gcPauseMs"]):
                        raise ValueError("missing managed runtime allocation/GC evidence")
                started, ended = utc_seconds(sample["startUtc"]), utc_seconds(sample["endUtc"])
                duration = ended - started
                if duration < policy["windowSeconds"] - .5 or \
                        duration > policy["windowSeconds"] + 5:
                    raise ValueError("shortened, inflated or missing measured time")
                if previous_end is not None and (started < previous_end - .5 or
                                                 started - previous_end > 5):
                    raise ValueError("overlap, reset or unmeasured capacity window gap")
                if i == 0: starts[path] = started
                previous_end = ended
                run_duration += duration
                gbps = sample["responseBodyBytes"] * 8 / (duration * 1e9)
                min_gbps = min(min_gbps, gbps)
                max_p99 = max(max_p99, sample["p99Ms"])
                if gbps < minimum:
                    issues.append(f"{platform}/{path} window {i}: body throughput below approved headroom")
                if sample["p95Ms"] >= policy["maxP95Ms"] or \
                        sample["p99Ms"] >= policy["maxP99Ms"]:
                    issues.append(f"{platform}/{path} window {i}: p95/p99 exceeds approved cap")
                if sample["errors"] or sample["unexpectedStatuses"]:
                    issues.append(f"{platform}/{path} window {i}: response/transport errors")
                if sample["cpuSeconds"] > duration * run["hostCpuCores"] * \
                        policy["maxCpuUtilizationPercent"] / 100:
                    issues.append(f"{platform}/{path} window {i}: CPU exceeds approved cap")
                if path != "direct":
                    if sample["allocatedBytes"] / sample["requests"] > \
                            policy["maxAllocatedBytesPerRequest"]:
                        issues.append(f"{platform}/{path} window {i}: allocations exceed approved cap")
                    if sample["gcPauseMs"] > policy["maxGcPauseMsPerWindow"]:
                        issues.append(f"{platform}/{path} window {i}: GC pause exceeds approved cap")
            if run_duration < 3600:
                issues.append(f"{platform}/{path}: less than one hour observed")
            summary["runs"][platform][path] = {
                "minBodyGbps": round(min_gbps, 6), "maxP99Ms": max_p99,
                "observedSeconds": round(run_duration, 3), "windows": len(samples)
            }
        # Keep all three paths on the same approved workload. Captured source
        # hashes do not prove real traffic custody; independent raw evidence
        # and audit source signatures still need operator verification.
        if max(starts.values()) - min(starts.values()) > 7200:
            raise ValueError("unmatched Windows/Linux same-site run epoch")
        if summary["runs"][platform]["yarp_waf"]["maxP99Ms"] > \
                max(summary["runs"][platform]["yarp"]["maxP99Ms"], .001) * \
                policy["maxWafP99Multiplier"]:
            issues.append(f"{platform}: WAF p99 overhead exceeds approved limit")
    summary["decision"] = "NO-GO" if issues else "GO"
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args(argv)
    try:
        result = gate(load_strict(options.policy), load_strict(options.evidence))
        # Operator report uses the existing fail-closed owner-only/private
        # WAF evidence writer; never overwrite or print route/raw request data.
        result["measurementPolicyPass"] = result["decision"] == "GO"
        result["productionGo"] = False
        result["sourceCustodyVerified"] = False
        write_private_report(options.out, result)
        print(result["decision"] + ": measured Windows/Linux three-path WAF gate; not production GO")
        return int(result["decision"] != "GO")
    except (ValueError, KeyError, TypeError, OSError, OverflowError):
        print("NO-GO: missing or invalid measured capacity evidence", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
