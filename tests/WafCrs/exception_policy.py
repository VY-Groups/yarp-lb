#!/usr/bin/env python3
"""Fail-closed governance check for the single disposable WAF lab exception.

This validates a checked-in fixture and its exact ModSecurity rule. It is not
a production exception API, approval or dynamic rules engine.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "integrations" / "WafCrs" / "exception-policy.lab.json"
RULE = ROOT / "integrations" / "WafCrs" / "REQUEST-900-LAB-PKIX.conf"
COMPOSE = ROOT / "integrations" / "WafCrs" / "compose.lab.yml"
EXPECTED = {
    "schemaVersion": 1,
    "exceptionId": "lab-pkix-920420",
    "environment": "disposable-lab-only",
    "owner": "gatewaycore-ci-waf-fixture",
    "reason": "Allow valid X.509 public DER uploads in a private acceptance lab",
    "httpMethod": "POST",
    "path": "/acceptance",
    "contentType": "application/pkix-cert",
    "removedRuleId": 920420,
}
EXPECTED_RULE = (
    'SecRule REQUEST_METHOD "@streq POST" \\\n'
    '    "id:1000420,phase:1,pass,nolog,t:none,chain"\n'
    '    SecRule REQUEST_URI "@streq /acceptance" "t:none,chain"\n'
    '        SecRule REQUEST_HEADERS:Content-Type "@streq application/pkix-cert" \\\n'
    '            "t:lowercase,ctl:ruleRemoveById=920420"\n'
)
REQUIRED = set(EXPECTED) | {"approvedForProduction", "issuedAtUtc", "expiresAtUtc"}


def _no_duplicate_properties(pairs):
    output = {}
    normalized = set()
    for name, value in pairs:
        lowered = name.casefold()
        if lowered in normalized:
            raise ValueError("Ambiguous duplicate JSON policy property")
        normalized.add(lowered)
        output[name] = value
    return output


def _date(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise ValueError("Policy timestamps must be UTC seconds with Z suffix")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ValueError("Invalid policy timestamp") from error


def validate(policy=POLICY, rule=RULE, compose=COMPOSE, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Current time must be timezone-aware")
    policy_bytes = Path(policy).read_bytes()
    if not 1 <= len(policy_bytes) <= 4096:
        raise ValueError("Lab policy exceeds its input bound")
    try:
        data = json.loads(policy_bytes.decode("utf-8", errors="strict"),
                          object_pairs_hook=_no_duplicate_properties,
                          parse_constant=lambda value: (_ for _ in ()).throw(
                              ValueError("Non-JSON numeric constant")))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("Invalid lab policy JSON") from error
    if type(data) is not dict or set(data) != REQUIRED:
        raise ValueError("Lab policy has missing or unsupported fields")
    if any(type(data[name]) is not type(expected) or data[name] != expected
           for name, expected in EXPECTED.items()):
        raise ValueError("Unexpected policy scope or test-only owner")
    if data["approvedForProduction"] is not False:
        raise ValueError("Lab exception must never claim production approval")
    issued = _date(data["issuedAtUtc"])
    expiry = _date(data["expiresAtUtc"])
    if issued > now or expiry <= now or expiry <= issued or (
            expiry - issued > dt.timedelta(days=45)):
        raise ValueError("Lab exception missing, expired or too long-lived")
    actual_rule = "\n".join(line for line in Path(rule).read_text(
        encoding="utf-8").splitlines() if line.strip() and
        not line.lstrip().startswith("#")) + "\n"
    if actual_rule != EXPECTED_RULE:
        raise ValueError("Lab ModSecurity exception changed scope or commands")
    compose_text = Path(compose).read_text(encoding="utf-8")
    if compose_text.count("./REQUEST-900-LAB-PKIX.conf:") != 1 or (
            "./REQUEST-900-LAB-PKIX.conf:"
            "/etc/modsecurity.d/owasp-crs/rules/"
            "REQUEST-900-GATEWAYCORE-LAB-PKIX.conf:ro") not in compose_text:
        raise ValueError("Lab rule not mounted once, read-only, at the expected path")
    return {"exceptionId": data["exceptionId"],
            "scope": data["environment"],
            "expiresAtUtc": data["expiresAtUtc"],
            "productionApproved": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--validate", action="store_true",
                        help="check current repository fixture")
    args = parser.parse_args()
    if not args.validate:
        parser.error("pass --validate")
    try:
        result = validate()
    except (OSError, ValueError) as error:
        parser.exit(1, "FAIL: WAF lab exception policy: " + str(error) + "\n")
    print(json.dumps(result, sort_keys=True))
