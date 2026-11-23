#!/usr/bin/env python3
"""Fail-closed, reproducible WAF corpus confusion-matrix evidence gate (#51).

Input is a CSV of individual observed requests; policy is precommitted JSON.
This does not generate traffic or replace real Windows/Linux WAF acceptance.
"""
import argparse
import csv
import json
import os
import pathlib
import sys
from collections import defaultdict

# v2 requires a separate rule-evaluation decision: shadow mode should
# allow traffic but may still report that it *would* have blocked it.
FIELDS = {"case_id", "route", "expected", "observed", "would_block", "mode", "severity"}
EXPECTED = {"benign", "malicious"}
OBSERVED = {"allow", "block"}
MODES = {"block", "detect"}
SEVERITIES = {"low", "medium", "high", "critical"}
MAX_CASES = 100_000
MAX_FIELD_CHARS = 4096


def evaluate(rows, policy):
    if type(policy) is not dict or set(policy) != {"schemaVersion", "mode", "routes"} or \
            type(policy["schemaVersion"]) is not int or policy["schemaVersion"] != 2 or \
            type(policy["mode"]) is not str or policy["mode"] not in MODES:
        raise ValueError("policy must be v2 with a valid mode and explicit routes")
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
        if count > MAX_CASES:
            raise ValueError("corpus exceeds bounded case count")
        if any(type(v) is not str or len(v) > MAX_FIELD_CHARS for v in row.values()):
            raise ValueError(f"row {count}: oversized or invalid field")
        if set(row) != FIELDS or any(not isinstance(v, str) for v in row.values()):
            raise ValueError(f"row {count}: invalid columns")
        case_id, route = row["case_id"], row["route"]
        if not case_id or case_id in seen:
            raise ValueError(f"row {count}: duplicate or empty case_id")
        seen.add(case_id)
        if route not in policy["routes"]:
            raise ValueError(f"row {count}: unapproved route")
        if (row["expected"] not in EXPECTED or row["observed"] not in OBSERVED
                or row["would_block"] not in ("true", "false") or
                row["mode"] != policy["mode"] or row["severity"] not in SEVERITIES):
            raise ValueError(f"row {count}: invalid classification or policy mode")
        blocked = row["observed"] == "block"
        would_block = row["would_block"] == "true"
        if row["mode"] == "detect" and blocked:
            raise ValueError(f"row {count}: detection-only policy blocked traffic")
        if row["mode"] == "block" and blocked != would_block:
            raise ValueError(f"row {count}: enforcement disagrees with rule-evaluation evidence")
        # In shadow/detect mode a malicious allowed request can still be a
        # true positive if its policy decision says it *would* be blocked.
        # Conflating the HTTP result with the rule outcome makes detect-only
        # tests incorrectly report every malicious request as false-negative.
        truth = row["expected"] == "malicious"
        decision = would_block
        bucket = "tp" if truth and decision else "fn" if truth else "fp" if decision else "tn"
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
    return {"schemaVersion": 2, "mode": policy["mode"],
            "status": "FAIL" if failures else "PASS", "cases": count,
            "routes": dict(sorted(stats.items())), "failures": failures}


def write_private_report(path, report):
    """Write local, operator-owned evidence via a fresh 0600 temporary inode.

    Never follow a predictable temporary symlink or publish route identifiers
    to stdout. Parent-directory permissions remain the operator's duty.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    if path.is_symlink():
        raise ValueError("private WAF evidence report destination is a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    created = True
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if path.is_symlink():
            raise ValueError("private WAF evidence destination became a symlink")
        os.replace(temporary, path)
        created = False
    finally:
        if created:
            temporary.unlink(missing_ok=True)


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
        csv.field_size_limit(MAX_FIELD_CHARS)
        with args.corpus.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            if reader.fieldnames is None or set(reader.fieldnames) != FIELDS or len(reader.fieldnames) != len(FIELDS):
                raise ValueError("CSV columns must match exact required schema")
            report = evaluate(reader, policy)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError, csv.Error) as exc:
        report = {"status": "FAIL", "failures": [str(exc)]}
    try:
        write_private_report(args.out, report)
    except (OSError, ValueError):
        print("FAIL: unable to write private WAF evidence report", file=sys.stderr)
        return 2
    # Public CI stdout contains only status/count, never operator route names,
    # case identifiers, policy values or detailed exceptions.
    print(json.dumps({"status": report["status"], "cases": report.get("cases", 0)},
                     sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
