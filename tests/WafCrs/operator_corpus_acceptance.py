#!/usr/bin/env python3
"""Opt-in, redacted operator-corpus acceptance against the isolated WAF lab.

The only network destination is hard-coded loopback:18888. Never send a
customer-provided fixture to a public endpoint, automatically redirect,
retry a POST, or copy raw requests/responses into GitHub artifacts.
"""
import argparse
import collections
import http.client
import json
import os
from pathlib import Path
import re
import sys

MAX_INPUT = 512 * 1024
MAX_CASES = 256
MAX_BODY = 128 * 1024
ALLOWED_CONTENT_TYPES = frozenset((
    "application/json", "application/xml", "text/plain",
    "application/pkix-cert", "application/octet-stream",
))
CASE_FIELDS = frozenset((
    "id", "route", "method", "path", "expected", "severity",
    "contentType", "body",
))
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}\Z", re.ASCII)


def strict_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON property")
        result[key] = value
    return result


def require_object(value, allowed):
    if not isinstance(value, dict) or set(value) != allowed:
        raise ValueError("unrecognized or missing corpus fields")


def load_corpus(filename):
    path = Path(filename)
    if path.stat().st_size > MAX_INPUT or path.stat().st_size < 2:
        raise ValueError("operator WAF corpus exceeds input limit or is empty")
    with path.open("rb") as handle:
        source = handle.read(MAX_INPUT + 1)
    try:
        doc = json.loads(source.decode("utf-8", "strict"), object_pairs_hook=strict_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("malformed private operator corpus") from exc
    require_object(doc, frozenset(("schemaVersion", "cases", "maxFalsePositives", "maxFalseNegatives")))
    if type(doc["schemaVersion"]) is not int or doc["schemaVersion"] != 1:
        raise ValueError("unsupported corpus schema")
    # This tool deliberately will not accept relaxed FP/FN thresholds from
    # an unreviewed operator corpus. Production exception governance is
    # separate; the opt-in acceptance remains fail-closed.
    if type(doc["maxFalsePositives"]) is not int or doc["maxFalsePositives"] != 0 or \
            type(doc["maxFalseNegatives"]) is not int or doc["maxFalseNegatives"] != 0:
        raise ValueError("operator acceptance requires zero FP/FN")
    cases = doc["cases"]
    if not isinstance(cases, list) or len(cases) not in range(4, MAX_CASES + 1):
        raise ValueError("operator corpus requires 4..256 distinct cases")
    seen = set()
    labels = collections.Counter()
    for case in cases:
        require_object(case, CASE_FIELDS)
        if any(not isinstance(case[key], str) for key in CASE_FIELDS):
            raise ValueError("corpus case fields must be bounded text")
        case_id = case["id"]
        canonical_case_id = case_id.casefold()
        if not SAFE_ID.fullmatch(case_id) or canonical_case_id in seen or \
                not SAFE_ID.fullmatch(case["route"]):
            raise ValueError("duplicate or unsafe case/route identifier")
        seen.add(canonical_case_id)
        if case["expected"] not in ("benign", "malicious") or \
                case["severity"] not in ("none", "low", "medium", "high", "critical") or \
                (case["expected"] == "benign") != (case["severity"] == "none"):
            raise ValueError("invalid fixed ground-truth class or severity")
        labels[case["expected"]] += 1
        if case["method"] not in ("GET", "POST"):
            raise ValueError("only non-retried GET and POST are supported")
        uri = case["path"]
        if not uri.startswith("/") or uri.startswith("//") or \
                len(uri) > 512 or "#" in uri or "\\" in uri or \
                any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in uri):
            raise ValueError("unsafe local lab request target")
        if case["contentType"] not in ALLOWED_CONTENT_TYPES:
            raise ValueError("unapproved lab Content-Type")
        body = case["body"].encode("utf-8")
        if len(body) > MAX_BODY or (case["method"] == "GET" and body):
            raise ValueError("unbounded or invalid lab request body")
    if labels["benign"] < 2 or labels["malicious"] < 2:
        raise ValueError("corpus needs at least two benign and two malicious fixtures")
    return cases


def verified_origin_response(method, content_type, body_size, response_type, payload):
    """Accept only the real private origin's bounded GET or POST response.

    A substring marker or arbitrary JSON cannot establish that a response
    reached the expected backend. Never return body bytes to the report.
    """
    if method == "GET":
        return (response_type == "text/plain; charset=utf-8"
                and payload == b"YARP-WAF-CI-BENIGN\\n")
    if method != "POST" or response_type != "application/json" or len(payload) > 4096:
        return False
    try:
        record = json.loads(payload.decode("ascii", "strict"),
                            object_pairs_hook=strict_pairs)
    except (ValueError, UnicodeError):
        return False
    return (type(record) is dict and set(record) == {"accepted", "contentType", "bytes"}
            and record["accepted"] is True
            and type(record["bytes"]) is int and record["bytes"] == body_size
            and record["contentType"] == content_type)


def run_cases(cases, connection_factory=None):
    if connection_factory is None:
        connection_factory = lambda: http.client.HTTPConnection(
            "127.0.0.1", 18888, timeout=5)
    rows = []
    matrices = collections.defaultdict(lambda: collections.Counter(
        {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "ERROR": 0}))
    for case in cases:
        connection = connection_factory()
        status = None
        marker = False
        try:
            body = case["body"].encode("utf-8")
            # No redirects, dynamic hostname, auth or arbitrary headers.
            connection.request(case["method"], case["path"], body=body,
                               headers={"Content-Type": case["contentType"],
                                        "Connection": "close"})
            response = connection.getresponse()
            status = response.status
            payload = response.read(4097)
            marker = verified_origin_response(
                case["method"], case["contentType"], len(body),
                response.getheader("Content-Type", ""), payload)
        except (OSError, TimeoutError, http.client.HTTPException):
            pass  # mark ERROR; never log a raw request or exception
        finally:
            connection.close()
        if status == 200 and marker:
            result = "TN" if case["expected"] == "benign" else "FN"
        elif status == 403:
            result = "FP" if case["expected"] == "benign" else "TP"
        else:
            result = "ERROR"
        matrices[(case["route"], case["severity"])][result] += 1
        rows.append({"id": case["id"], "route": case["route"],
                     "severity": case["severity"], "expected": case["expected"],
                     "status": status, "result": result})
    aggregate = collections.Counter(row["result"] for row in rows)
    by_route = [
        {"route": route, "severity": severity, "counts": dict(counts)}
        for (route, severity), counts in sorted(matrices.items())
    ]
    # No path, body, query, headers, response payload, upstream addresses
    # or customer secrets appear in this emitted evidence.
    report = {
        "schemaVersion": 1, "scope": "operator-supplied-private-lab-corpus",
        "total": len(rows), "counts": {name: aggregate[name]
                                      for name in ("TP", "TN", "FP", "FN", "ERROR")},
        "byRouteAndSeverity": by_route, "cases": rows,
        "passesZeroFalsePositiveNegativeGate":
            aggregate["FP"] == 0 and aggregate["FN"] == 0 and aggregate["ERROR"] == 0,
    }
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    try:
        cases = load_corpus(args.corpus)
        report = run_cases(cases)
        target = Path(args.report)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_name(target.name + ".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
        os.replace(temporary, target)
        if not report["passesZeroFalsePositiveNegativeGate"]:
            print("FAIL: private corpus contains blocked benign, allowed malicious or failed requests",
                  file=sys.stderr)
            return 1
        print("PASS: private corpus matched all ground-truth WAF decisions; no raw payloads exported")
        return 0
    except (ValueError, OSError) as exc:
        print("FAIL: invalid or inaccessible private operator WAF corpus", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
