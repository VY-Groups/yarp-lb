#!/usr/bin/env python3
"""Fail-closed, reproducible WAF corpus confusion-matrix evidence gate (#51).

Input is a CSV of individual observed requests; policy is precommitted JSON.
This does not generate traffic or replace real Windows/Linux WAF acceptance.
"""
import argparse
import csv
import io
import json
import os
import pathlib
import math
import re
import stat
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
MAX_POLICY_BYTES = 1024 * 1024
MAX_CORPUS_BYTES = 128 * 1024 * 1024
V3_FIELDS = FIELDS | {"audit_sha256"}
V3_LIMITS = {"max_fp", "max_fn", "max_fp_rate", "max_fn_rate",
             "min_benign", "min_malicious"}
V3_POLICY_KEYS = {"schemaVersion", "mode", "routes", "approvedRulesetSha256",
                  "corpusManifestSha256", "gatewaySha", "platform"}
HEX64 = re.compile(r"[A-F0-9]{64}\Z")
HEX40 = re.compile(r"[A-Fa-f0-9]{40}\Z")
CANONICAL_ROUTE = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z")
CASE_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")


def read_bounded_utf8(path, limit):
    """Read one regular, unlinked-by-symlink evidence file under a byte cap.

    An input can be untrusted even when an operator selects its path. Reject
    FIFOs/devices and changing or oversized files before CSV/JSON parsing.
    This bounds parser memory; signed evidence custody is a separate gate.
    """
    path = pathlib.Path(os.path.abspath(path))
    # Reject aliases in every ancestor, not just the leaf. Resolving the
    # parent first would silently follow an attacker-controlled directory.
    def check_parent():
        if path.parent.resolve(strict=True) != path.parent:
            raise ValueError("WAF evidence input ancestor cannot be a symlink")
    check_parent()
    if path.is_symlink():
        raise ValueError("WAF evidence input cannot be a symlink")
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    # On POSIX, pin each ancestor as a directory descriptor. Checking
    # resolve() alone is racy: a directory can be replaced with a symlink
    # between the check and the final open. Never follow such a replacement.
    if os.name == "posix":
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for component in path.parent.parts[1:]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY |
                                  os.O_NOFOLLOW, dir_fd=directory_fd)
                os.close(directory_fd)
                directory_fd = next_fd
            fd = os.open(path.name, flags, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)
    else:
        fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as handle:
        before = os.fstat(handle.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("WAF evidence input is not a bounded regular file")
        data = handle.read(limit + 1)
        after = os.fstat(handle.fileno())
        if (len(data) > limit or len(data) != before.st_size or
                before.st_size != after.st_size or
                before.st_mtime_ns != after.st_mtime_ns):
            raise ValueError("WAF evidence input exceeds cap or changed during read")
        # Recheck the entire ancestor chain after the descriptor read too.
        check_parent()
        # Ensure the pathname was not swapped while the descriptor was open.
        if path.is_symlink():
            raise ValueError("WAF evidence input changed to a symlink")
        current = path.stat()
        if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("WAF evidence input changed identity during read")
    return data.decode("utf-8", "strict")


def evaluate(rows, policy):
    if type(policy) is not dict or type(policy.get("schemaVersion")) is not int:
        raise ValueError("expected preapproved WAF policy v2 or v3")
    version = policy["schemaVersion"]
    keys = {"schemaVersion", "mode", "routes"} if version == 2 else V3_POLICY_KEYS
    if (version not in (2, 3) or set(policy) != keys or
            type(policy["mode"]) is not str or policy["mode"] not in MODES):
        raise ValueError("policy must match the explicit approved version and mode")
    if version == 3:
        if (type(policy["approvedRulesetSha256"]) is not str or
                not HEX64.fullmatch(policy["approvedRulesetSha256"]) or
                type(policy["corpusManifestSha256"]) is not str or
                not HEX64.fullmatch(policy["corpusManifestSha256"]) or
                type(policy["gatewaySha"]) is not str or
                not HEX40.fullmatch(policy["gatewaySha"]) or
                policy["platform"] not in ("windows", "linux")):
            raise ValueError("v3 policy requires pinned ruleset, corpus, gateway and platform")
    if type(policy["routes"]) is not dict or not policy["routes"]:
        raise ValueError("policy routes must be a nonempty object")
    for route, limits in policy["routes"].items():
        required_limits = {"max_fp", "max_fn"} if version == 2 else V3_LIMITS
        if (not isinstance(route, str) or not route or
                type(limits) is not dict or set(limits) != required_limits):
            raise ValueError("each route needs complete preapproved count/rate limits")
        if version == 3 and (not CANONICAL_ROUTE.fullmatch(route) or
                any(segment in (".", "..") for segment in route.split("/")) or
                len(route) > 256):
            raise ValueError("v3 route is ambiguous or noncanonical")
        if any(type(limits[k]) is not int or limits[k] < 0 for k in ("max_fp", "max_fn")):
            raise ValueError("count limits must be nonnegative integers")
        if version == 3:
            if (any(type(limits[k]) not in (int, float) or
                    not math.isfinite(limits[k]) or not 0 <= limits[k] <= 1
                    for k in ("max_fp_rate", "max_fn_rate")) or
                    any(type(limits[k]) is not int or limits[k] < 1 or
                        limits[k] > MAX_CASES
                        for k in ("min_benign", "min_malicious"))):
                raise ValueError("v3 preapproved route rates or minimum sizes invalid")
    stats = defaultdict(lambda: {"tp": 0, "tn": 0, "fp": 0, "fn": 0})
    seen = set()
    seen_native_audits = set()
    count = 0
    for row in rows:
        count += 1
        if count > MAX_CASES:
            raise ValueError("corpus exceeds bounded case count")
        if any(type(v) is not str or len(v) > MAX_FIELD_CHARS for v in row.values()):
            raise ValueError(f"row {count}: oversized or invalid field")
        expected_fields = FIELDS if version == 2 else V3_FIELDS
        if set(row) != expected_fields or any(not isinstance(v, str) for v in row.values()):
            raise ValueError(f"row {count}: invalid columns")
        case_id, route = row["case_id"], row["route"]
        if not case_id or case_id in seen:
            raise ValueError(f"row {count}: duplicate or empty case_id")
        seen.add(case_id)
        if version == 3:
            if not CASE_ID.fullmatch(case_id):
                raise ValueError(f"row {count}: noncanonical case identity")
            audit_hash = row["audit_sha256"]
            if not HEX64.fullmatch(audit_hash) or audit_hash in seen_native_audits:
                raise ValueError(f"row {count}: missing or reused native WAF audit digest")
            seen_native_audits.add(audit_hash)
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
    measured_rates = {}
    for route in sorted(stats):
        values = stats[route]
        if values["fp"] > policy["routes"][route]["max_fp"]:
            failures.append(f"{route}: false positives exceed precommitted limit")
        if values["fn"] > policy["routes"][route]["max_fn"]:
            failures.append(f"{route}: false negatives exceed precommitted limit")
        benign = values["tn"] + values["fp"]
        malicious = values["tp"] + values["fn"]
        if not malicious or not benign:
            failures.append(f"{route}: missing benign or malicious ground truth")
        if version == 3:
            limits = policy["routes"][route]
            fp_rate = values["fp"] / benign if benign else None
            fn_rate = values["fn"] / malicious if malicious else None
            measured_rates[route] = {"fp_rate": fp_rate, "fn_rate": fn_rate,
                                     "benign": benign, "malicious": malicious}
            if benign < limits["min_benign"] or malicious < limits["min_malicious"]:
                failures.append(f"{route}: insufficient preapproved corpus size")
            if (fp_rate is None or fp_rate > limits["max_fp_rate"] or
                    fn_rate is None or fn_rate > limits["max_fn_rate"]):
                failures.append(f"{route}: preapproved FP/FN rate exceeded")
    report = {"schemaVersion": version, "mode": policy["mode"],
              "status": "FAIL" if failures else "PASS", "cases": count,
              "routes": dict(sorted(stats.items())), "failures": failures}
    if version == 3:
        report["rates"] = measured_rates
        report["pinnedEvidence"] = {
            key: policy[key] for key in
            ("approvedRulesetSha256", "corpusManifestSha256", "gatewaySha", "platform")}
    return report


def write_private_report(path, report):
    """Create a non-overwriting 0600 operator report beneath a private directory.

    The report contains per-route labels. A permissive output directory or
    replace-overwrite could leak evidence or erase a previous acceptance run.
    """
    path = pathlib.Path(path)
    if not path.is_absolute() or path.name in ("", ".", ".."):
        raise ValueError("private WAF report needs an absolute output filename")
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.is_symlink() or parent.resolve(strict=True) != parent:
        raise ValueError("private WAF report path cannot traverse a symlink")
    directory = parent.stat()
    if (not stat.S_ISDIR(directory.st_mode) or
            (os.name == "posix" and
             (directory.st_uid != os.geteuid() or
              stat.S_IMODE(directory.st_mode) & 0o077))):
        raise ValueError("private WAF report directory must be owner-only")
    temporary = path.with_name(path.name + ".tmp")
    if path.is_symlink() or path.exists():
        raise ValueError("private WAF evidence report must use a new destination")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        # Exclusive hard-link promotion fails if another writer created the
        # destination; unlike os.replace, it never overwrites prior evidence.
        os.link(temporary, path, follow_symlinks=False)
        if os.name == "posix":
            directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
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

        policy = json.loads(read_bounded_utf8(args.policy, MAX_POLICY_BYTES),
                            object_pairs_hook=strict_object,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                ValueError("non-JSON policy numeric constant")))
        csv.field_size_limit(MAX_FIELD_CHARS)
        with io.StringIO(read_bounded_utf8(args.corpus, MAX_CORPUS_BYTES), newline="") as stream:
            reader = csv.DictReader(stream)
            version = policy.get("schemaVersion") if type(policy) is dict else None
            if type(version) is not int or version not in (2, 3):
                raise ValueError("invalid or missing WAF evidence policy version")
            expected = FIELDS if version == 2 else V3_FIELDS
            if (reader.fieldnames is None or set(reader.fieldnames) != expected or
                    len(reader.fieldnames) != len(expected)):
                raise ValueError("CSV columns must match exact versioned schema")
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
