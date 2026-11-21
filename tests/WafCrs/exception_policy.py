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
EXPECTED_RULE = r"""SecRule REQUEST_METHOD "@streq POST" \
    "id:1000420,phase:1,pass,nolog,t:none,chain"
    SecRule REQUEST_URI "@streq /acceptance" "t:none,chain"
        SecRule REQUEST_HEADERS:Content-Type "@streq application/pkix-cert" \
            "t:lowercase,ctl:ruleRemoveById=920420"
"""
REQUIRED = set(EXPECTED) | {"approvedForProduction", "issuedAtUtc", "expiresAtUtc"}

# Lock the disposable lab's effective WAF and backend Compose stanzas. The
# policy manifest alone does not protect an exception when another mount,
# runtime override or published origin silently bypasses the intended engine.
# Treat any Compose change as a separately reviewed fixture revision.
_EXPECTED_BACKEND = (
    'image: python:3.12-alpine',
    'command: ["python", "/app/backend.py"]',
    'volumes:',
    '- ../../tests/WafCrs/backend.py:/app/backend.py:ro',
    'expose: ["8000"]',
    'networks: ["waf-private"]',
)
_EXPECTED_WAF = (
    'image: ${WAF_IMAGE:-owasp/modsecurity-crs@sha256:f7b4ec036553aa65e65fe792394099f597d6130465e63ff58d84f087617f5412}',
    'volumes:',
    '- ./REQUEST-900-LAB-PKIX.conf:/etc/modsecurity.d/owasp-crs/rules/REQUEST-900-GATEWAYCORE-LAB-PKIX.conf:ro',
    'environment:',
    'BACKEND: http://protected-app:8000',
    'SERVER_NAME: localhost',
    'PORT: "8080"',
    'MODSEC_RULE_ENGINE: "${WAF_MODE:-On}"',
    'MODSEC_REQ_BODY_ACCESS: "On"',
    'MODSEC_REQ_BODY_LIMIT: "131072"',
    'MODSEC_REQ_BODY_NOFILES_LIMIT: "65536"',
    'MODSEC_REQ_BODY_LIMIT_ACTION: "Reject"',
    'BLOCKING_PARANOIA: "1"',
    'DETECTION_PARANOIA: "1"',
    'ANOMALY_INBOUND: "5"',
    'MODSEC_AUDIT_ENGINE: "On"',
    'MODSEC_AUDIT_LOG_FORMAT: "Native"',
    'ports:',
    '- "127.0.0.1:18888:8080"',
    'depends_on:',
    '- protected-app',
    'networks: ["waf-private"]',
)


def _compose_service_active_lines(compose_text, service):
    """Read only the exact two-space-indented lab Compose service block.

    No YAML aliases, Compose extensions, additional mounts or environment
    fields are permitted by this fixture contract. This is NOT a general YAML
    parser; docker compose config --quiet still validates the actual document.
    """
    lines = compose_text.splitlines()
    starts = [index for index, line in enumerate(lines)
              if line == f"  {service}:"]
    if len(starts) != 1:
        raise ValueError(f"Expected exactly one {service} service block")
    selected = []
    for line in lines[starts[0] + 1:]:
        if line.strip() and not line.startswith("    "):
            break
        value = line.strip()
        if value and not value.startswith("#"):
            selected.append(value)
    return tuple(selected)


def _validate_compose_lab_boundary(compose_text):
    if _compose_service_active_lines(compose_text, "protected-app") != _EXPECTED_BACKEND:
        raise ValueError("WAF lab backend isolation or config changed")
    if _compose_service_active_lines(compose_text, "waf") != _EXPECTED_WAF:
        raise ValueError("WAF lab engine, rule mounts, threshold or binding changed")


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
    _validate_compose_lab_boundary(compose_text)
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
