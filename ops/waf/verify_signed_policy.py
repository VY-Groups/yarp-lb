#!/usr/bin/env python3
"""Fail-closed offline two-reviewer WAF deployment-input policy gate.

Never applies WAF rules or claims to verify deployed policy or site traffic.
Only detached signatures and externally trusted P-256 public keys are read.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

MAX_BYTES = 65536
DOMAIN = "GatewayCore.WAF.Review.v1\n"
REVIEWER = re.compile(r"[A-Za-z0-9_.-]{3,64}\Z", re.ASCII)
HEX = re.compile(r"[A-F0-9]{64}\Z", re.ASCII)
POLICY_FIELDS = {"schemaVersion", "revision", "mode", "rulesetSha256",
                 "shadowEvidenceSha256", "issuedAtUtc", "expiresAtUtc", "exceptions"}
EXCEPTION_FIELDS = {"exceptionId", "owner", "reason", "routeId", "httpMethod",
                    "path", "contentType", "ruleId", "issuedAtUtc", "expiresAtUtc"}
APPROVAL_FIELDS = {"schemaVersion", "reviewer", "policySha256",
                   "signedAtUtc", "signatureBase64"}


def _read_file(path, limit=MAX_BYTES):
    """Read one stable regular inode; reject final symlink/hardlink aliases."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("absolute trusted input paths required")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ValueError("unsafe or oversized policy input")
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) |
             getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        actual = os.fstat(fd)
        if (not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1 or
                (actual.st_dev, actual.st_ino) != (before.st_dev, before.st_ino)):
            raise ValueError("input inode changed or was aliased")
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(limit + 1)
    finally:
        if fd >= 0:
            os.close(fd)
    if not raw or len(raw) > limit:
        raise ValueError("invalid or oversized policy input")
    return raw


def _unique_props(pairs):
    obj = {}
    seen = set()
    for key, value in pairs:
        canonical = key.casefold()
        if canonical in seen:
            raise ValueError("duplicate or case-aliased JSON property")
        seen.add(canonical)
        obj[key] = value
    return obj


def _json(raw):
    return json.loads(raw.decode("utf-8", "strict"),
                      object_pairs_hook=_unique_props,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError("nonfinite JSON")))


def _utc(raw):
    if not isinstance(raw, str) or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", raw):
        raise ValueError("UTC seconds required")
    return dt.datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=dt.timezone.utc)


def _safe_id(value):
    return isinstance(value, str) and REVIEWER.fullmatch(value) is not None


def _digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def validate_policy(doc, minimum_revision, observed_ruleset, observed_mode, now):
    if type(doc) is not dict or set(doc) != POLICY_FIELDS:
        raise ValueError("wrong signed policy schema")
    revision = doc["revision"]
    if (type(doc["schemaVersion"]) is not int or doc["schemaVersion"] != 1 or
            type(revision) is not int or revision <= minimum_revision or
            revision > 2**53):
        raise ValueError("invalid or rollback policy revision")
    if doc["mode"] not in ("detect", "block") or doc["mode"] != observed_mode:
        raise ValueError("unapproved actual WAF mode")
    if not _digest(doc["rulesetSha256"]) or doc["rulesetSha256"] != observed_ruleset:
        raise ValueError("unapproved observed WAF ruleset")
    evidence = doc["shadowEvidenceSha256"]
    if doc["mode"] == "block" and not _digest(evidence):
        raise ValueError("blocking requires approved shadow evidence digest")
    if doc["mode"] == "detect" and evidence is not None:
        raise ValueError("detect policy cannot claim blocking evidence")
    issued, expires = _utc(doc["issuedAtUtc"]), _utc(doc["expiresAtUtc"])
    if (issued > now or expires <= now or expires <= issued or
            expires - issued > dt.timedelta(days=45)):
        raise ValueError("missing, future or expired policy window")
    exceptions = doc["exceptions"]
    if type(exceptions) is not list or len(exceptions) > 64:
        raise ValueError("invalid exception budget")
    seen = set()
    for item in exceptions:
        if type(item) is not dict or set(item) != EXCEPTION_FIELDS:
            raise ValueError("invalid scoped exception schema")
        name, owner, route = item["exceptionId"], item["owner"], item["routeId"]
        if not all(_safe_id(x) for x in (name, owner, route)) or name.casefold() in seen:
            raise ValueError("missing or repeated exception identity")
        seen.add(name.casefold())
        if (type(item["ruleId"]) is not int or not 1 <= item["ruleId"] <= 9999999 or
                item["httpMethod"] not in ("GET", "POST") or
                item["contentType"] not in ("application/json", "application/xml",
                    "application/pkix-cert", "text/plain", "application/octet-stream") or
                not isinstance(item["reason"], str) or not 10 <= len(item["reason"]) <= 256):
            raise ValueError("unbounded WAF exception dimensions")
        path = item["path"]
        if (not isinstance(path, str) or not 1 <= len(path) <= 256 or
                not path.startswith("/") or path.startswith("//") or
                not path.isascii() or
                "//" in path or
                any(c in path for c in "*?#{\\}%;:") or
                any(ord(c) < 33 or ord(c) > 126 for c in path) or
                any(piece in (".", "..") for piece in path.split("/"))):
            raise ValueError("exception must use literal exact route")
        begin, end = _utc(item["issuedAtUtc"]), _utc(item["expiresAtUtc"])
        if (begin > now or end <= now or end <= begin or
                end - begin > dt.timedelta(days=30) or
                begin < issued or end > expires):
            raise ValueError("unsafe exception expiry")
    return revision


def _approval_payload(digest, reviewer, signed_at):
    return (DOMAIN + digest + "\n" + reviewer + "\n" + signed_at + "\n").encode("ascii")


def _verify_signature(public_key, signature, signed_bytes):
    # Public-key material only: no production signer private key is loaded.
    with tempfile.TemporaryDirectory(prefix="gateway-waf-review-") as directory:
        pub = Path(directory) / "verifier.pem"
        sig = Path(directory) / "review.sig"
        pub.write_bytes(public_key)
        sig.write_bytes(signature)
        if os.name == "posix":
            pub.chmod(0o600)
            sig.chmod(0o600)
        info = subprocess.run(
            ["openssl", "pkey", "-pubin", "-in", str(pub), "-text", "-noout"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=5, check=False)
        if (info.returncode != 0 or b"ASN1 OID: prime256v1" not in info.stdout or
                b"Public-Key: (256 bit)" not in info.stdout):
            raise ValueError("trusted reviewer key must be P-256 SPKI")
        result = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig)],
            input=signed_bytes, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=5, check=False)
        return result.returncode == 0


def _canonical_reviewer_key_digest(public_key):
    """Compare actual SPKI public key bytes, not mutable PEM whitespace."""
    result = subprocess.run(
        ["openssl", "pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
        input=public_key, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=5, check=False)
    if result.returncode != 0 or not 80 <= len(result.stdout) <= 512:
        raise ValueError("invalid trusted reviewer SPKI")
    return hashlib.sha256(result.stdout).digest()


def verify(policy_path, approvals, reviewers, minimum_revision_path,
           observed_ruleset, observed_mode, now=None, shadow_evidence_path=None,
           *, return_digest=False):
    now = now or dt.datetime.now(dt.timezone.utc)
    if (now.tzinfo is None or not _digest(observed_ruleset) or
            observed_mode not in ("detect", "block")):
        raise ValueError("observed WAF state required")
    if len(approvals) != 2 or len(reviewers) != 2:
        raise ValueError("two independent approvals and trust roots required")
    policy_bytes = _read_file(policy_path)
    minimum_bytes = _read_file(minimum_revision_path, limit=24)
    if not re.fullmatch(rb"(0|[1-9][0-9]{0,18})\n?", minimum_bytes):
        raise ValueError("invalid external monotonic revision source")
    minimum = int(minimum_bytes)
    policy_root = Path(policy_path).parent.resolve(strict=True)
    for external in [minimum_revision_path, *reviewers.values()]:
        # Protect the *independent* trust root against a restored policy tree
        # supplying both the policy and its own revocation/verification floor.
        if Path(external).resolve(strict=True).is_relative_to(policy_root):
            raise ValueError("trust input cannot reside in policy tree")
    policy_data = _json(policy_bytes)
    revision = validate_policy(policy_data, minimum,
                               observed_ruleset, observed_mode, now)
    # Blocking approval must bind the actual evidence bytes to the reviewed
    # policy digest. A SHA-256-looking string alone is not site evidence.
    if observed_mode == "block":
        if shadow_evidence_path is None:
            raise ValueError("blocking requires a supplied shadow evidence file")
        observed_shadow = hashlib.sha256(
            _read_file(shadow_evidence_path, limit=4 * 1024 * 1024)).hexdigest().upper()
        if observed_shadow != policy_data["shadowEvidenceSha256"]:
            raise ValueError("shadow evidence does not match reviewed digest")
    elif shadow_evidence_path is not None:
        raise ValueError("detect-only policy must not assert blocking evidence")
    policy_digest = hashlib.sha256(policy_bytes).hexdigest().upper()
    seen = set()
    seen_keys = set()
    for path in approvals:
        obj = _json(_read_file(path, limit=16384))
        if (type(obj) is not dict or set(obj) != APPROVAL_FIELDS or
                type(obj["schemaVersion"]) is not int or obj["schemaVersion"] != 1):
            raise ValueError("invalid detached approval")
        who = obj["reviewer"]
        if (not _safe_id(who) or who in seen or who not in reviewers or
                obj["policySha256"] != policy_digest):
            raise ValueError("unknown/reused reviewer or changed policy")
        signed = _utc(obj["signedAtUtc"])
        if signed < now - dt.timedelta(days=7) or signed > now + dt.timedelta(seconds=30):
            raise ValueError("approval time outside signed review window")
        key = _read_file(reviewers[who], limit=8192)
        key_digest = _canonical_reviewer_key_digest(key)
        if key_digest in seen_keys:
            raise ValueError("reviewers share a signing key")
        seen_keys.add(key_digest)
        signature_b64 = obj["signatureBase64"]
        if not isinstance(signature_b64, str) or len(signature_b64) > 256:
            raise ValueError("invalid detached signature encoding")
        try:
            signature = base64.b64decode(signature_b64, validate=True)
        except ValueError:
            raise ValueError("invalid detached signature encoding") from None
        if (not 64 <= len(signature) <= 128 or
                not _verify_signature(key, signature,
                    _approval_payload(policy_digest, who, obj["signedAtUtc"]))):
            raise ValueError("detached reviewer signature rejected")
        seen.add(who)
    if seen != set(reviewers):
        raise ValueError("one or more independent approvals missing")
    return (revision, policy_digest) if return_digest else revision


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--approval", type=Path, action="append", required=True)
    parser.add_argument("--reviewer-key", action="append", required=True,
                        help="reviewer-name=absolute SPKI public PEM path")
    parser.add_argument("--minimum-revision-file", type=Path, required=True)
    parser.add_argument("--observed-ruleset-sha256", required=True)
    parser.add_argument("--observed-mode", choices=("detect", "block"), required=True)
    parser.add_argument("--shadow-evidence-file", type=Path,
                        help="required for block: privately reviewed evidence bytes")
    args = parser.parse_args()
    try:
        keys = {}
        for pair in args.reviewer_key:
            who, sep, path = pair.partition("=")
            if (not sep or not _safe_id(who) or who in keys or
                    not Path(path).is_absolute()):
                raise ValueError("invalid trusted reviewer mapping")
            keys[who] = Path(path)
        rev = verify(args.policy, args.approval, keys, args.minimum_revision_file,
                     args.observed_ruleset_sha256, args.observed_mode,
                     shadow_evidence_path=args.shadow_evidence_file)
    except (ValueError, OSError, TypeError, UnicodeError, json.JSONDecodeError,
            subprocess.SubprocessError, RecursionError):
        # Never echo raw operator-supplied paths, signatures or policy content.
        parser.exit(1, "FAIL: signed WAF policy input acceptance\n")
    print("PASS: signed WAF policy input accepted at revision " + str(rev) +
          " with two distinct approved P-256 reviewer keys")


if __name__ == "__main__":
    main()
