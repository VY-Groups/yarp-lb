#!/usr/bin/env python3
"""Correlate synthetic detect/block requests to native CRS audit transactions.

Do not upload native logs: they may contain headers, tokens, and raw payloads.
Emit only fixed synthetic case names, rule families and checked statuses.
"""
import json
from pathlib import Path
import re
import sys

MAX_AUDIT_BYTES = 8 * 1024 * 1024
CASE_FAMILIES = {"xss": "941", "sqli": "942", "traversal": "930"}
BLOCKING_CASE_FAMILIES = {**CASE_FAMILIES, **{
    "spoofed-" + name: family for name, family in CASE_FAMILIES.items()}}
BOUNDARY = re.compile(r"--([A-Za-z0-9_-]{6,64})-([A-Z])--")
CASE_HEADER = re.compile(
    r"(?im)^X-GatewayCore-CI-Case:\s*((?:detection|blocking)-(?:spoofed-)?(?:xss|sqli|traversal))\s*$")
RULE_ID = re.compile(r'\[id "([0-9]{6})"\]')


def audit_transactions(text):
    """Keep each B/H audit section paired under the same native transaction."""
    current_id = None
    current_part = None
    current = None
    for original in text.splitlines():
        # docker compose logs prefixes every native ModSecurity line.
        line = original.split(" | ", 1)[1] if " | " in original else original
        marker = BOUNDARY.search(line)
        if marker:
            txn, part = marker.groups()
            if part == "A":
                current_id, current_part = txn, part
                current = {"B": [], "H": []}
            elif current is not None and txn == current_id:
                if part == "Z":
                    yield current
                    current_id, current_part, current = None, None, None
                else:
                    current_part = part
            else:
                # A broken/mixed transaction cannot be accepted as evidence.
                current_id, current_part, current = None, None, None
            continue
        if current is not None and current_part in ("B", "H"):
            current[current_part].append(line)


def correlate(text, phase="detection"):
    """Return fixed case->family evidence; fail on missing/duplicate/misbound."""
    if phase not in ("detection", "blocking"):
        raise ValueError("unsupported WAF evidence phase")
    expected = CASE_FAMILIES if phase == "detection" else BLOCKING_CASE_FAMILIES
    found = {name: [] for name in expected}
    for transaction in audit_transactions(text):
        headers = "\n".join(transaction["B"])
        markers = CASE_HEADER.findall(headers)
        if not markers:
            continue
        if len(markers) != 1:
            raise ValueError("ambiguous case tags in native transaction")
        if not markers[0].startswith(phase + "-"):
            continue
        case = markers[0].removeprefix(phase + "-")
        if case not in found:
            raise ValueError("unexpected case-specific CRS verdict")
        families = {match[:3] for match in
                    RULE_ID.findall("\n".join(transaction["H"]))}
        found[case].append(families)
    result = {}
    for case, family in expected.items():
        hits = found[case]
        if len(hits) != 1 or family not in hits[0]:
            raise ValueError("missing, duplicated or mismatched case-specific CRS verdict")
        result[case] = family
    return result


def build_report(audit_file, output_root, phase="detection"):
    audit_file = Path(audit_file)
    if audit_file.stat().st_size > MAX_AUDIT_BYTES:
        raise ValueError("synthetic native audit exceeds evidence cap")
    with audit_file.open("rb") as stream:
        raw = stream.read(MAX_AUDIT_BYTES + 1)
    if len(raw) > MAX_AUDIT_BYTES:
        raise ValueError("synthetic native audit exceeds evidence cap")
    matched = correlate(raw.decode("utf-8", errors="replace"), phase)
    root = Path(output_root)
    results = {}
    for case, family in matched.items():
        filename = root / (("detection-" + case + "-status.txt") if phase == "detection"
                           else (case + "-http-status.txt"))
        code = filename.read_text(encoding="ascii").strip()
        if code != ("200" if phase == "detection" else "403"):
            raise ValueError("case HTTP result disagrees with correlated native CRS verdict")
        results[case] = {"httpStatus": code, "crsFamily": family,
                         "observed": True, "forwarded": phase == "detection"}
    return {"schemaVersion": 2,
            "scope": "synthetic-native-audit-correlated-" + phase + "-lab-only",
            "attackClasses": results, "auditBinding": "native-B-header-to-H-rule-same-transaction"}


def main(argv):
    if len(argv) not in (3, 4) or (len(argv) == 4 and argv[3] != "--blocking"):
        raise ValueError("expected isolated lab artifact root, native audit filename and optional --blocking")
    phase = "blocking" if len(argv) == 4 else "detection"
    report = build_report(argv[2], argv[1], phase)
    output = "blocking-native-audit-report.json" if phase == "blocking" else "detection-corpus-report.json"
    (Path(argv[1]) / output).write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS: synthetic " + phase + " attack cases independently bound to native CRS audit decisions")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError):
        print("FAIL: synthetic WAF audit-to-case correlation incomplete or ambiguous",
              file=sys.stderr)
        raise SystemExit(1)
