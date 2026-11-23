#!/usr/bin/env python3
"""Fail-closed, redacted per-route WAF corpus confusion-matrix acceptance gate.

Input contains only ground-truth labels and outcomes, never request bodies or secrets.
No thresholds are invented: the reviewer must provide explicit route/severity limits.
"""
import argparse
import json
import math
import os
import stat
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


def _reject_duplicate_json_keys(pairs):
    # A second field can silently override a route threshold or a ground-truth
    # case label. Reject it at every JSON object nesting level.
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property in WAF evidence")
        result[key] = value
    return result


def _read_bounded_json(path):
    """Read only one stable, regular evidence inode (never a linked alias).

    An opened-descriptor size/read check protects against input growth and a
    race where a path is swapped after its initial lstat. On POSIX O_NOFOLLOW
    rejects a symlink substituted at open; the inode check also detects a
    replacement between lstat and open. Windows additionally uses a best-
    effort path preflight, not an OS-wide concurrent-attacker guarantee.
    """
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("WAF input must be a single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    # FIFOs must never block the validator while opening; fstat will reject
    # all nonregular objects before attempting any read.
    flags |= getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    try:
        current = os.fstat(fd)
        if (not stat.S_ISREG(current.st_mode) or current.st_nlink != 1 or
                (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("WAF input changed or is not a single-link regular file")
        if current.st_size > MAX_INPUT_BYTES:
            raise ValueError("WAF evidence input exceeds 16 MiB")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_INPUT_BYTES + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("WAF evidence input exceeds 16 MiB")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)


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



def write_private_report(path, result):
    """Atomically publish bounded WAF summary under an operator-owned output directory.

    On POSIX, the replacement inode is 0600 regardless of umask or prior
    report permissions. Reject symlink destinations and existing predictable
    temporary paths. Operators must provision a trusted private parent
    directory; Windows ACL qualification remains separate.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("unsafe WAF report destination")
    temporary = path.with_name(path.name + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    published = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if path.is_symlink():
            raise ValueError("unsafe WAF report destination")
        os.replace(temporary, path)
        published = True
    finally:
        if not published:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(_read_bounded_json(args.corpus),
                          _read_bounded_json(args.policy))
        write_private_report(args.out, result)
        return 0 if result["pass"] else 1
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        # Paths and operator-specific fields must never leak into CI/stdout.
        print("FAIL: WAF matrix validation or private report write failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
