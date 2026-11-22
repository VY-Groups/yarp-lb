#!/usr/bin/env python3
"""Fail-closed, redacted per-route WAF corpus confusion-matrix acceptance gate.

Input contains only ground-truth labels and outcomes, never request bodies or secrets.
No thresholds are invented: the reviewer must provide explicit route/severity limits.
"""
import argparse
import json
import math
import sys
from collections import defaultdict
from pathlib import Path


def _fraction(value, name):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
        raise ValueError(f"{name} must be a finite fraction in [0,1]")
    return float(value)


MAX_CORPUS_CASES = 100_000
MAX_POLICY_CLASSES = 1_024
MAX_INPUT_BYTES = 16 * 1024 * 1024


def _read_bounded_json(path):
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("WAF evidence input exceeds 16 MiB")
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("WAF evidence input exceeds 16 MiB")
    return json.loads(raw.decode("utf-8"))


def evaluate(corpus, policy):
    if not isinstance(corpus, list) or not corpus or len(corpus) > MAX_CORPUS_CASES:
        raise ValueError("nonempty corpus array required")
    if not isinstance(policy, dict) or not policy:
        raise ValueError("explicit route/severity policy required")
    limits = {}
    for route, severities in policy.items():
        if not isinstance(route, str) or not route or not isinstance(severities, dict) or not severities:
            raise ValueError("invalid policy route")
        for severity, values in severities.items():
            if len(limits) >= MAX_POLICY_CLASSES:
                raise ValueError("WAF policy exceeds class budget")
            if severity not in ("low", "medium", "high", "critical") or not isinstance(values, dict):
                raise ValueError("invalid severity policy")
            if set(values) != {"max_fp_rate", "max_fn_rate", "min_benign", "min_attack"}:
                raise ValueError("explicit FP/FN and coverage thresholds required")
            benign, attack = values["min_benign"], values["min_attack"]
            if type(benign) is not int or type(attack) is not int or benign < 1 or attack < 1:
                raise ValueError("positive integer class coverage required")
            limits[(route, severity)] = (
                _fraction(values["max_fp_rate"], "max_fp_rate"),
                _fraction(values["max_fn_rate"], "max_fn_rate"), benign, attack
            )
    counts = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
    seen = set()
    for item in corpus:
        if not isinstance(item, dict) or set(item) != {"case_id", "route", "severity", "expected_attack", "blocked", "mode"}:
            raise ValueError("corpus entries require exact redacted fields")
        case_id, route, severity = item["case_id"], item["route"], item["severity"]
        if not isinstance(case_id, str) or not case_id or len(case_id) > 128 or case_id in seen:
            raise ValueError("missing, duplicate or oversized case_id")
        seen.add(case_id)
        if (route, severity) not in limits:
            raise ValueError("unapproved route/severity in corpus")
        if type(item["expected_attack"]) is not bool or type(item["blocked"]) is not bool:
            raise ValueError("labels and outcomes must be boolean")
        if item["mode"] not in ("detect", "block"):
            raise ValueError("invalid WAF mode")
        if item["mode"] == "detect" and item["blocked"]:
            raise ValueError("detect-only traffic was blocked")
        # Detect-only observations cannot establish a blocking confusion matrix.
        if item["mode"] != "block":
            continue
        key = "tp" if item["expected_attack"] and item["blocked"] else (
            "fn" if item["expected_attack"] else ("fp" if item["blocked"] else "tn")
        )
        counts[(route, severity)][key] += 1
    results = []
    passed = True
    for route, severity in sorted(limits):
        c = counts[(route, severity)]
        fp_limit, fn_limit, min_benign, min_attack = limits[(route, severity)]
        benign, attack = c["fp"] + c["tn"], c["tp"] + c["fn"]
        fp_rate = c["fp"] / benign if benign else None
        fn_rate = c["fn"] / attack if attack else None
        ok = (benign >= min_benign and attack >= min_attack and
              fp_rate is not None and fn_rate is not None and
              fp_rate <= fp_limit and fn_rate <= fn_limit)
        passed &= ok
        results.append({"route": route, "severity": severity, **c,
                        "fp_rate": fp_rate, "fn_rate": fn_rate, "pass": ok})
    return {"pass": bool(passed), "matrix": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(_read_bounded_json(args.corpus),
                          _read_bounded_json(args.policy))
        args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0 if result["pass"] else 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"WAF corpus evidence invalid: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
