#!/usr/bin/env python3
"""Fail-closed WAF corpus confusion-matrix evidence gate (stdlib only).

Input CSV columns: route,case_id,expected,observed,mode.
expected: benign|malicious; observed: allowed|blocked; mode: block.
This evaluates actual enforcement only: shadow/detect-only must be assessed
separately and cannot be counted as successful blocking.
"""
import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

FIELDS = ("route", "case_id", "expected", "observed", "mode")
MAX_BYTES = 16 * 1024 * 1024
MAX_ROWS = 100000


def assess(path, max_fp, max_fn, min_benign, min_malicious):
    if not (math.isfinite(max_fp) and math.isfinite(max_fn) and 0 <= max_fp <= 1 and 0 <= max_fn <= 1):
        raise ValueError("rates must be within [0,1]")
    if min_benign < 1 or min_malicious < 1:
        raise ValueError("minimum corpus counts must be positive")
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("missing or oversized evidence CSV")
    counts = defaultdict(lambda: dict(tp=0, tn=0, fp=0, fn=0))
    seen = set()
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream, strict=True)
        if reader.fieldnames is None or tuple(reader.fieldnames) != FIELDS:
            raise ValueError("unexpected CSV header; required: " + ",".join(FIELDS))
        for number, row in enumerate(reader, 1):
            if number > MAX_ROWS:
                raise ValueError("too many corpus rows")
            if None in row or any(v is None for v in row.values()):
                raise ValueError(f"row {number}: malformed columns")
            route, case_id, expected, observed, mode = (row[k].strip() for k in FIELDS)
            if not route.startswith("/") or any(c in route for c in "\r\n\x00") or len(route) > 256:
                raise ValueError(f"row {number}: invalid route")
            if not case_id or len(case_id) > 128 or any(c in case_id for c in "\r\n\x00"):
                raise ValueError(f"row {number}: invalid case ID")
            if expected not in ("benign", "malicious") or observed not in ("allowed", "blocked"):
                raise ValueError(f"row {number}: invalid verdict")
            if mode != "block":
                raise ValueError(f"row {number}: only enforcement-mode evidence is accepted")
            key = (route, case_id)
            if key in seen:
                raise ValueError(f"row {number}: duplicate route/case ID")
            seen.add(key)
            bucket = ("tp" if observed == "blocked" else "fn") if expected == "malicious" else ("fp" if observed == "blocked" else "tn")
            counts[route][bucket] += 1
    if not counts:
        raise ValueError("empty corpus")
    report = {}
    passed = True
    for route, c in sorted(counts.items()):
        benign = c["tn"] + c["fp"]
        malicious = c["tp"] + c["fn"]
        fp_rate = c["fp"] / benign if benign else None
        fn_rate = c["fn"] / malicious if malicious else None
        ok = (benign >= min_benign and malicious >= min_malicious
              and fp_rate is not None and fp_rate <= max_fp
              and fn_rate is not None and fn_rate <= max_fn)
        passed &= ok
        report[route] = {**c, "benign": benign, "malicious": malicious,
                         "fp_rate": fp_rate, "fn_rate": fn_rate, "pass": ok}
    return {"pass": bool(passed), "limits": {"max_fp_rate": max_fp,
            "max_fn_rate": max_fn, "min_benign_per_route": min_benign,
            "min_malicious_per_route": min_malicious}, "routes": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--max-fp-rate", type=float, required=True)
    parser.add_argument("--max-fn-rate", type=float, required=True)
    parser.add_argument("--min-benign", type=int, required=True)
    parser.add_argument("--min-malicious", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        if not all(math.isfinite(x) for x in (args.max_fp_rate, args.max_fn_rate)):
            raise ValueError("non-finite rate")
        result = assess(args.csv, args.max_fp_rate, args.max_fn_rate,
                        args.min_benign, args.min_malicious)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["pass"] else 1
    except (ValueError, OSError, UnicodeError, csv.Error) as exc:
        print(json.dumps({"pass": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
