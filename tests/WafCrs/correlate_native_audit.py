#!/usr/bin/env python3
"""Correlate synthetic detect-only requests to native CRS audit transactions.

Do not upload native logs: they may contain headers, tokens, and raw payloads.
Emit only fixed synthetic case names, rule families and checked statuses.
"""
import json
from pathlib import Path
import re
import sys

MAX_AUDIT_BYTES = 8 * 1024 * 1024
CASE_FAMILIES = {"xss": "941", "sqli": "942", "traversal": "930"}
BOUNDARY = re.compile(r"--([A-Za-z0-9_-]{6,64})-([A-Z])--")
CASE_HEADER = re.compile(r"(?im)^X-GatewayCore-CI-Case:\s*(detection-(?:xss|sqli|traversal))\s*$")
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


def correlate(text):
    """Return fixed case->family evidence; fail on missing/duplicate/misbound."""
    found = {name: [] for name in CASE_FAMILIES}
    for transaction in audit_transactions(text):
        headers = "\n".join(transaction["B"])
        markers = CASE_HEADER.findall(headers)
        if not markers:
            continue
        if len(markers) != 1:
            raise ValueError("ambiguous case tags in native transaction")
        case = markers[0].removeprefix("detection-")
        families = {match[:3] for match in
                    RULE_ID.findall("\n".join(transaction["H"]))}
        found[case].append(families)
    result = {}
    for case, family in CASE_FAMILIES.items():
        hits = found[case]
        if len(hits) != 1 or family not in hits[0]:
            raise ValueError("missing, duplicated or mismatched case-specific CRS verdict")
        result[case] = family
    return result


def build_report(audit_file, output_root):
    audit_file = Path(audit_file)
    if audit_file.stat().st_size > MAX_AUDIT_BYTES:
        raise ValueError("synthetic native audit exceeds evidence cap")
    with audit_file.open("rb") as stream:
        raw = stream.read(MAX_AUDIT_BYTES + 1)
    if len(raw) > MAX_AUDIT_BYTES:
        raise ValueError("synthetic native audit exceeds evidence cap")
    matched = correlate(raw.decode("utf-8", errors="replace"))
    root = Path(output_root)
    results = {}
    for case, family in matched.items():
        filename = root / ("detection-" + case + "-status.txt")
        code = filename.read_text(encoding="ascii").strip()
        if code != "200":
            raise ValueError("detection case did not reach expected origin")
        results[case] = {"httpStatus": code, "crsFamily": family,
                         "observed": True, "forwarded": True}
    return {"schemaVersion": 2, "scope": "synthetic-native-audit-correlated-lab-only",
            "attackClasses": results, "auditBinding": "native-B-header-to-H-rule-same-transaction"}


def main(argv):
    if len(argv) != 3:
        raise ValueError("expected isolated lab artifact root and native audit filename")
    report = build_report(argv[2], argv[1])
    (Path(argv[1]) / "detection-corpus-report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("PASS: three synthetic attack cases independently bound to native CRS audit decisions")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError):
        print("FAIL: synthetic WAF audit-to-case correlation incomplete or ambiguous",
              file=sys.stderr)
        raise SystemExit(1)
