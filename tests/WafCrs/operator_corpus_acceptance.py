#!/usr/bin/env python3
"""Opt-in, redacted operator-corpus acceptance against the isolated WAF lab.

The only network destination is hard-coded loopback:18888. Never send a
customer-provided fixture to a public endpoint, automatically redirect,
retry a POST, or copy raw requests/responses into GitHub artifacts.
"""
import argparse
import collections
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

import correlate_native_audit as native_audit

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
RUN_HEADER = re.compile(r"(?im)^X-GatewayCore-Corpus-Run:\s*([0-9a-f]{32})\s*$")
CASE_HEADER = re.compile(r"(?im)^X-GatewayCore-Corpus-Case:\s*([A-Za-z0-9_-]{1,48})\s*$")
CRS_RULE = re.compile(r'\[id "9[0-9]{5}"\]')
DENIED_403 = re.compile(r"Access denied with code 403", re.IGNORECASE)


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
    # An operator corpus may contain private request bodies. Do not follow
    # symlink/hardlink aliases or silently switch to a different inode after
    # checking the path; never open a FIFO that could hang the CI process.
    path = Path(filename)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("private WAF corpus must be a single-link regular file")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or
                (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError("private WAF corpus input changed or is aliased")
        if not 2 <= opened.st_size <= MAX_INPUT:
            raise ValueError("operator WAF corpus exceeds input limit or is empty")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            source = handle.read(MAX_INPUT + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if not 2 <= len(source) <= MAX_INPUT:
        raise ValueError("operator WAF corpus exceeds input limit or is empty")
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
        # http.client builds an ASCII HTTP/1 request line. Raw Unicode
        # (or unpaired JSON-surrogate escapes) in the target can throw an
        # uncaught UnicodeEncodeError with portions of the private payload
        # in its diagnostic. Require a fully ASCII request target, and let
        # the operator supply UTF-8 via percent-encoded URL bytes instead.
        if not uri.startswith("/") or uri.startswith("//") or \
                len(uri) > 512 or not uri.isascii() or \
                "#" in uri or "\\" in uri or \
                any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in uri):
            raise ValueError("unsafe local lab request target")
        if case["contentType"] not in ALLOWED_CONTENT_TYPES:
            raise ValueError("unapproved lab Content-Type")
        try:
            body = case["body"].encode("utf-8", "strict")
        except UnicodeError as exc:
            # An unpaired surrogate is legal JSON input but cannot be
            # encoded as a real UTF-8 request body. Do not surface the
            # offending case, body or Python's byte/character diagnostic.
            raise ValueError("invalid UTF-8 private corpus body") from None
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
                and payload == b"YARP-WAF-CI-BENIGN\n")
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


def verified_response_framing(headers, payload):
    """Reject ambiguous or incomplete declared HTTP response framing.

    Real WAF and origin responses may be chunked without Content-Length.
    When a length is present, it must be unique and match all received bytes.
    """
    lengths = headers.get_all("Content-Length", [])
    transfers = headers.get_all("Transfer-Encoding", [])
    # http.client decodes a *single* standard chunked response; it does not
    # validate or decode arbitrary Transfer-Encoding extensions. Without
    # explicit framing checks a forged identity body could count as origin
    # evidence under an unsupported or ambiguous transfer coding.
    if len(lengths) > 1 or len(transfers) > 1 or (lengths and transfers):
        return False
    if transfers:
        return transfers[0].strip().lower() == "chunked"
    if not lengths:
        # Close-delimited legacy HTTP responses remain supported, but their
        # actual origin body still must match the exact bounded marker.
        return True
    length = lengths[0]
    if not length.isascii() or not length.isdecimal() or len(length) > 10:
        return False
    return int(length) == len(payload)


def read_native_audit(started_at):
    """Read bounded private native audit output from the fixed local lab."""
    lab = Path(__file__).resolve().parents[2]
    compose = lab / "integrations" / "WafCrs" / "compose.lab.yml"
    command = ["docker", "compose", "-f", str(compose), "logs",
               "--since", started_at, "--no-color", "waf"]
    try:
        # TemporaryFile is private and unlinked. Never put raw customer
        # request headers or bodies in a workflow artifact or stdout.
        with tempfile.TemporaryFile(mode="w+b") as output:
            completed = subprocess.run(command, cwd=lab, stdout=output,
                                       stderr=subprocess.STDOUT, timeout=20,
                                       check=False)
            if completed.returncode != 0 or output.tell() > native_audit.MAX_AUDIT_BYTES:
                raise ValueError("private native WAF audit unavailable or oversized")
            output.seek(0)
            return output.read(native_audit.MAX_AUDIT_BYTES + 1).decode(
                "utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("private native WAF audit unavailable") from None


def native_crs_blocks(text, run_id, allowed_cases):
    """Bind each complete native B/H transaction to one tagged 403 decision."""
    matched = set()
    seen = set()
    for transaction in native_audit.audit_transactions(text):
        headers = "\n".join(transaction["B"])
        runs = RUN_HEADER.findall(headers)
        if run_id not in runs:
            continue
        cases = CASE_HEADER.findall(headers)
        if len(runs) != 1 or len(cases) != 1 or cases[0] not in allowed_cases:
            raise ValueError("ambiguous private WAF audit request identity")
        case_id = cases[0]
        if case_id in seen:
            raise ValueError("duplicate private WAF audit transaction")
        seen.add(case_id)
        messages = "\n".join(transaction["H"])
        if CRS_RULE.search(messages) and DENIED_403.search(messages):
            matched.add(case_id)
    return matched


def run_cases(cases, connection_factory=None, audit_reader=None):
    if connection_factory is None:
        connection_factory = lambda: http.client.HTTPConnection(
            "127.0.0.1", 18888, timeout=5)
    if audit_reader is None:
        audit_reader = read_native_audit
    started_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = secrets.token_hex(16)
    rows = []
    for case in cases:
        connection = connection_factory()
        status = None
        marker = False
        framing_ok = False
        try:
            body = case["body"].encode("utf-8")
            # No redirects, dynamic hostname, auth or arbitrary headers.
            connection.request(case["method"], case["path"], body=body,
                               headers={"Content-Type": case["contentType"],
                                        "Connection": "close",
                                        "X-GatewayCore-Corpus-Run": run_id,
                                        "X-GatewayCore-Corpus-Case": case["id"]})
            response = connection.getresponse()
            status = response.status
            # A received HTTP status is not proof of a completed response.
            # Partial bodies and unsupported framing must never count as
            # a successful WAF block, even when the status line says 403.
            payload = response.read(4097)
            # Bounded reads can stop before EOF for large or chunked 403
            # bodies. Never accept a status line while unread response
            # bytes remain, even if its headers claim valid framing.
            framing_ok = (response.isclosed() and len(payload) <= 4096 and
                          verified_response_framing(response.headers, payload))
            marker = framing_ok and verified_origin_response(
                case["method"], case["contentType"], len(body),
                response.getheader("Content-Type", ""), payload)
        except (OSError, TimeoutError, http.client.HTTPException):
            pass  # mark ERROR; never log a raw request or exception
        finally:
            connection.close()
        if framing_ok and status == 200 and marker:
            result = "TN" if case["expected"] == "benign" else "FN"
        elif framing_ok and status == 403:
            result = "FP" if case["expected"] == "benign" else "TP"
        else:
            result = "ERROR"
        rows.append({"id": case["id"], "route": case["route"],
                     "severity": case["severity"], "expected": case["expected"],
                     "status": status, "result": result})
    # An origin or intermediary can emit HTTP 403. Count it as a WAF
    # verdict only when the same tagged request has one complete native
    # ModSecurity transaction containing a CRS rule and denial decision.
    matched = native_crs_blocks(audit_reader(started_at), run_id,
                                {case["id"] for case in cases})
    for row in rows:
        row["nativeBlockVerified"] = row["id"] in matched
        if row["result"] in ("TP", "FP") and row["id"] not in matched:
            row["result"] = "ERROR"
        elif row["status"] == 200 and row["id"] in matched:
            row["result"] = "ERROR"
    matrices = collections.defaultdict(lambda: collections.Counter(
        {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "ERROR": 0}))
    for row in rows:
        matrices[(row["route"], row["severity"])][row["result"]] += 1
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


def write_private_report(report, target):
    """Atomically publish only a 0600 local report without following a link.

    The operator chooses the destination directory; this never uploads data
    or emits case identifiers to standard output. Reject a stale or
    attacker-created .tmp pathname rather than overwriting/following it.
    """
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    if target.is_symlink():
        raise ValueError("private WAF report destination must not be a symlink")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(temporary, flags, 0o600)
    created = True
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if target.is_symlink():
            raise ValueError("private WAF report destination changed into a symlink")
        os.replace(temporary, target)
        created = False
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args(argv)
    try:
        cases = load_corpus(args.corpus)
        report = run_cases(cases)
        write_private_report(report, args.report)
        if not report["passesZeroFalsePositiveNegativeGate"]:
            print("FAIL: private corpus contains blocked benign, allowed malicious or failed requests",
                  file=sys.stderr)
            return 1
        print("PASS: private corpus matched ground truth with native CRS audit binding; no raw payloads exported")
        return 0
    except (ValueError, OSError) as exc:
        print("FAIL: invalid or inaccessible private operator WAF corpus", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
