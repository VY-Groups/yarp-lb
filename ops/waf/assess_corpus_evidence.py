#!/usr/bin/env python3
"""Fail-closed per-route WAF *enforcement* confusion-matrix evidence gate.

This validates shape, completeness and internal consistency of redacted
operator-produced evidence. It cannot authenticate ground truth or audit
provenance on its own; those require an independently held collection trail.
"""
import argparse
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
from collections import defaultdict

FIELDS = ("route", "case_id", "expected", "observed", "mode",
          "waf_action", "audit_sha256")
MAX_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ROWS = 100000
ROUTE = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z")
CASE = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
DIGEST = re.compile(r"[A-F0-9]{64}\Z")
SHA = re.compile(r"[a-fA-F0-9]{40}\Z")
REQUIRED_MANIFEST = frozenset(("schemaVersion", "approvedRulesetSha256",
                                "corpusManifestSha256", "gatewaySha",
                                "platform", "routes", "evidenceBinding"))


def _read_regular(path, maximum):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("evidence and approved route manifest need absolute paths")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("evidence must be a regular, single-linked file")
    if before.st_size < 1 or before.st_size > maximum:
        raise ValueError("missing or oversized evidence file")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        after = os.fstat(fd)
        if (not stat.S_ISREG(after.st_mode) or after.st_nlink != 1 or
                (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or
                after.st_size < 1 or after.st_size > maximum):
            raise ValueError("evidence changed between inspection and open")
        with os.fdopen(os.dup(fd), "rb") as handle:
            raw = handle.read(maximum + 1)
        if len(raw) > maximum or len(raw) != after.st_size:
            raise ValueError("evidence changed or exceeds byte limit")
        return raw
    finally:
        os.close(fd)


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate route manifest JSON key")
        result[key] = value
    return result


def _valid_route(route):
    return (isinstance(route, str) and len(route) <= 256 and
            ROUTE.fullmatch(route) is not None and
            not any(segment in (".", "..") for segment in route.split("/")))


def _load_manifest(raw):
    obj = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_json)
    if (not isinstance(obj, dict) or frozenset(obj) != REQUIRED_MANIFEST or
            type(obj["schemaVersion"]) is not int or obj["schemaVersion"] != 1 or
            not isinstance(obj["approvedRulesetSha256"], str) or
            not DIGEST.fullmatch(obj["approvedRulesetSha256"]) or
            not isinstance(obj["corpusManifestSha256"], str) or
            not DIGEST.fullmatch(obj["corpusManifestSha256"]) or
            not isinstance(obj["gatewaySha"], str) or
            not SHA.fullmatch(obj["gatewaySha"]) or
            obj["platform"] not in ("windows", "linux") or
            obj["evidenceBinding"] != "native-waf-audit-per-request" or
            not isinstance(obj["routes"], list) or not obj["routes"] or
            len(obj["routes"]) > 256):
        raise ValueError("incomplete or invalid approved route manifest")
    routes = obj["routes"]
    if any(not _valid_route(route) for route in routes) or len(set(routes)) != len(routes):
        raise ValueError("ambiguous or duplicated expected route")
    return obj


def assess(path, max_fp, max_fn, min_benign, min_malicious, route_manifest):
    if (type(max_fp) not in (int, float) or type(max_fn) not in (int, float) or
            not math.isfinite(max_fp) or not math.isfinite(max_fn) or
            not 0 <= max_fp <= 1 or not 0 <= max_fn <= 1):
        raise ValueError("rates must be within [0,1]")
    if (type(min_benign) is not int or type(min_malicious) is not int or
            min_benign < 1 or min_malicious < 1 or
            min_benign > MAX_ROWS or min_malicious > MAX_ROWS):
        raise ValueError("minimum corpus counts must be positive and bounded")

    manifest_raw = _read_regular(route_manifest, MAX_MANIFEST_BYTES)
    manifest = _load_manifest(manifest_raw)
    raw = _read_regular(path, MAX_BYTES)
    counts = defaultdict(lambda: dict(tp=0, tn=0, fp=0, fn=0))
    seen_cases = set()
    seen_audits = set()
    # Bound a single CSV field; no request bodies or sensitive native audit
    # logs are permitted in this metadata-only evidence format.
    previous_limit = csv.field_size_limit()
    try:
        csv.field_size_limit(4096)
        stream = io.StringIO(raw.decode("utf-8-sig", "strict"), newline="")
        reader = csv.DictReader(stream, strict=True)
        if reader.fieldnames is None or tuple(reader.fieldnames) != FIELDS:
            raise ValueError("unexpected CSV header; required: " + ",".join(FIELDS))
        for number, row in enumerate(reader, 1):
            if number > MAX_ROWS:
                raise ValueError("too many corpus rows")
            if None in row or any(v is None for v in row.values()):
                raise ValueError("malformed corpus columns")
            route, case_id, expected, observed, mode, action, audit_hash = (
                row[k] for k in FIELDS)
            if not _valid_route(route):
                raise ValueError("noncanonical route in evidence")
            if not CASE.fullmatch(case_id):
                raise ValueError("invalid case identifier")
            if expected not in ("benign", "malicious") or observed not in ("allowed", "blocked"):
                raise ValueError("invalid ground-truth label or HTTP observation")
            if mode != "block":
                raise ValueError("only verified enforcement-mode evidence is accepted")
            if action not in ("pass", "block") or (
                    (observed == "blocked") != (action == "block")):
                raise ValueError("HTTP status cannot substitute for a matched WAF audit action")
            if not DIGEST.fullmatch(audit_hash):
                raise ValueError("missing fixed SHA256 digest of case-specific native WAF audit")
            if (route, case_id) in seen_cases or audit_hash in seen_audits:
                raise ValueError("duplicate case identity or reused native audit event")
            seen_cases.add((route, case_id))
            seen_audits.add(audit_hash)
            bucket = (("tp" if action == "block" else "fn") if expected == "malicious"
                      else ("fp" if action == "block" else "tn"))
            counts[route][bucket] += 1
    finally:
        csv.field_size_limit(previous_limit)

    if not counts:
        raise ValueError("empty corpus")
    expected_routes = set(manifest["routes"])
    if set(counts) != expected_routes:
        raise ValueError("evidence routes omit or exceed the independently approved route set")
    report = {}
    passed = True
    for route in sorted(expected_routes):
        c = counts[route]
        benign = c["tn"] + c["fp"]
        malicious = c["tp"] + c["fn"]
        fp_rate = c["fp"] / benign if benign else None
        fn_rate = c["fn"] / malicious if malicious else None
        ok = (benign >= min_benign and malicious >= min_malicious and
              fp_rate is not None and fp_rate <= max_fp and
              fn_rate is not None and fn_rate <= max_fn)
        passed &= ok
        report[route] = {**c, "benign": benign, "malicious": malicious,
                         "fp_rate": fp_rate, "fn_rate": fn_rate, "pass": ok}
    # These hashes allow an external auditor to match the submitted inputs;
    # they do NOT authenticate the operator or rule/corpus ground truth.
    return {"pass": bool(passed),
            "evidenceSha256": hashlib.sha256(raw).hexdigest().upper(),
            "approvedRouteManifestSha256": hashlib.sha256(manifest_raw).hexdigest().upper(),
            "approvedRulesetSha256": manifest["approvedRulesetSha256"],
            "corpusManifestSha256": manifest["corpusManifestSha256"],
            "gatewaySha": manifest["gatewaySha"], "platform": manifest["platform"],
            "evidenceBinding": "operator-supplied-native-audit-digest-per-case",
            "limits": {"max_fp_rate": max_fp, "max_fn_rate": max_fn,
                       "min_benign_per_route": min_benign,
                       "min_malicious_per_route": min_malicious},
            "routes": report}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", type=Path)
    parser.add_argument("--route-manifest", type=Path, required=True,
                        help="independently approved exact route manifest, never generated from the CSV")
    parser.add_argument("--max-fp-rate", type=float, required=True)
    parser.add_argument("--max-fn-rate", type=float, required=True)
    parser.add_argument("--min-benign", type=int, required=True)
    parser.add_argument("--min-malicious", type=int, required=True)
    args = parser.parse_args(argv)
    try:
        result = assess(args.csv, args.max_fp_rate, args.max_fn_rate,
                        args.min_benign, args.min_malicious, args.route_manifest)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if result["pass"] else 1
    except (ValueError, OSError, UnicodeError, csv.Error, json.JSONDecodeError) as error:
        print(json.dumps({"pass": False, "error": type(error).__name__}),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
