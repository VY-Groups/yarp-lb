#!/usr/bin/env python3
"""Fail-closed, reproducible WAF corpus confusion-matrix evidence gate (#51).

Input is a CSV of individual observed requests; policy is precommitted JSON.
This does not generate traffic or replace real Windows/Linux WAF acceptance.
"""
import argparse
import csv
import json
import pathlib
import sys
from collections import defaultdict

FIELDS = {"case_id", "route", "expected", "observed", "mode", "severity"}
EXPECTED = {"benign", "malicious"}
OBSERVED = {"allow", "block"}
MODES = {"block", "detect"}
SEVERITIES = {"low", "medium", "high", "critical"}


def evaluate(rows, policy):
    if type(policy) is not dict or set(policy) != {"mode", "routes"} or \
            type(policy["mode"]) is not str or policy["mode"] not in MODES:
        raise ValueError("policy must be an object with valid mode and routes")
    if type(policy["routes"]) is not dict or not policy["routes"]:
        raise ValueError("policy routes must be a nonempty object")
    for route, limits in policy["routes"].items():
        if not isinstance(route, str) or not route or \
                type(limits) is not dict or set(limits) != {"max_fp", "max_fn"}:
            raise ValueError("each route needs an object with max_fp and max_fn")
        if any(type(limits[k]) is not int or limits[k] < 0 for k in ("max_fp", "max_fn")):
            raise ValueError("limits must be nonnegative integers")
    stats = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
    seen = set()
    count = 0
    for row in rows:
        count += 1
        if set(row) != FIELDS or any(not isinstance(v, str) for v in row.values()):
            raise ValueError(f"row {count}: invalid columns")
        case_id, route = row["case_id"], row["route"]
        if not case_id or case_id in seen:
            raise ValueError(f"row {count}: duplicate or empty case_id")
        seen.add(case_id)
        if route not in policy["routes"]:
            raise ValueError(f"row {count}: unapproved route")
        if (row["expected"] not in EXPECTED or row["observed"] not in OBSERVED
                or row["mode"] != policy["mode"] or row["severity"] not in SEVERITIES):
            raise ValueError(f"row {count}: invalid classification or policy mode")
        if row["mode"] == "detect" and row["observed"] == "block":
            raise ValueError(f"row {count}: detection-only policy blocked traffic")
        truth = row["expected"] == "malicious"
        blocked = row["observed"] == "block"
        bucket = "tp" if truth and blocked else "fn" if truth else "fp" if blocked else "tn"
        stats[route][bucket] += 1
    if not count or set(stats) != set(policy["routes"]):
        raise ValueError("empty corpus or untested approved route")
    failures = []
    for route in sorted(stats):
        values = stats[route]
        if values["fp"] > policy["routes"][route]["max_fp"]:
            failures.append(f"{route}: false positives exceed precommitted limit")
        if values["fn"] > policy["routes"][route]["max_fn"]:
            failures.append(f"{route}: false negatives exceed precommitted limit")
        if not (values["tp"] + values["fn"]) or not (values["tn"] + values["fp"]):
            failures.append(f"{route}: missing benign or malicious ground truth")
    return {"status": "FAIL" if failures else "PASS", "cases": count,
            "routes": dict(sorted(stats.items())), "failures": failures}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True, type=pathlib.Path)
    parser.add_argument("--policy", required=True, type=pathlib.Path)
    parser.add_argument("--out", required=True, type=pathlib.Path)
    args = parser.parse_args()
    try:
        # Duplicate keys can silently replace precommitted WAF thresholds
        # under Python's default JSON decoder. Reject duplicates rather than
        # letting the last value redefine the approved route policy.
        def strict_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate WAF policy JSON property")
                result[key] = value
            return result

        policy = json.loads(args.policy.read_text(encoding="utf-8"),
                            object_pairs_hook=strict_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                ValueError("non-JSON policy numeric constant")))
        with args.corpus.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None or set(reader.fieldnames) != FIELDS or len(reader.fieldnames) != len(FIELDS):
                raise ValueError("CSV columns must match exact required schema")
            report = evaluate(reader, policy)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        report = {"status": "FAIL", "failures": [str(exc)]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
