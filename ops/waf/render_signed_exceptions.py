#!/usr/bin/env python3
"""Render an owner-approved, short-lived narrow WAF exception as private config.

This DOES NOT activate a WAF or replace end-to-end deployment/recovery gates.
Only a known protocol false-positive exclusion is supported; other CRS
bypass requests fail closed until independently reviewed and tested.
"""
import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

import verify_signed_policy as signed

SAFE_PATH = re.compile(r"/(?:[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*)?\Z", re.ASCII)
SUPPORTED = (920420, "POST", "application/pkix-cert")
RULE_START = 11050000
MAX_CONFIG = 32768


def render(doc, now):
    """Return a static, bounded ModSecurity configuration with request-time expiry.

    The caller MUST have validated the complete signed policy and two
    independent approvals before passing these bytes to any deployment.
    """
    if type(doc) is not dict or type(doc.get("exceptions")) is not list:
        raise ValueError("signed WAF exceptions missing")
    if now.tzinfo is None:
        raise ValueError("UTC clock required")
    now = now.astimezone(dt.timezone.utc)
    rows, scopes = [], set()
    for index, item in enumerate(doc["exceptions"]):
        if type(item) is not dict:
            raise ValueError("invalid exception")
        path, method, mime, rule = (item["path"], item["httpMethod"],
                                    item["contentType"], item["ruleId"])
        if (not SAFE_PATH.fullmatch(path) or path == "/" or
                any(bit in (".", "..") for bit in path.split("/")) or
                (rule, method, mime) != SUPPORTED):
            raise ValueError("unsupported WAF exception scope")
        issued, expiry = signed._utc(item["issuedAtUtc"]), signed._utc(item["expiresAtUtc"])
        if not issued <= now < expiry:
            raise ValueError("expired or future WAF exception")
        key = (path, method, mime, rule)
        if key in scopes:
            raise ValueError("duplicate effective WAF exception scope")
        scopes.add(key)
        # Raw URI comparison forbids query, encoding and alternate path forms.
        # TIME_EPOCH must be checked on EVERY request: restart-only expiry
        # would leave a previously authorized exception indefinitely active.
        rows.append(
            f"# exceptionId={item['exceptionId']} owner={item['owner']} "
            f"routeId={item['routeId']} until={item['expiresAtUtc']}\n"
            f'SecRule TIME_EPOCH "@ge {int(issued.timestamp())}" \\\n'
            f'    "id:{RULE_START + index},phase:1,pass,nolog,t:none,chain"\n'
            f'    SecRule TIME_EPOCH "@lt {int(expiry.timestamp())}" "t:none,chain"\n'
            f'        SecRule REQUEST_METHOD "@streq POST" "t:none,chain"\n'
            f'            SecRule REQUEST_URI_RAW "@streq {path}" "t:none,chain"\n'
            '                SecRule REQUEST_HEADERS:Content-Type '
            '"@streq application/pkix-cert" '
            '"t:none,ctl:ruleRemoveById=920420"\n'
        )
    if not rows:
        raise ValueError("no scoped WAF exceptions to render")
    output = (
        "# GatewayCore approved WAF exception candidate, NEVER automatic deployment\n"
        f"# signed-policy-revision={doc['revision']}\n"
        "# Load only BEFORE the referenced CRS rule; verify full effective include graph.\n"
        + "\n".join(rows)
    ).encode("ascii", "strict")
    if len(output) > MAX_CONFIG:
        raise ValueError("rendered WAF exception configuration oversized")
    return output


def write_private_new(path, data):
    """Create a fsynced, immutable-by-name private output without overwrite."""
    path = Path(path)
    if not path.is_absolute() or path.name in ("", ".", "..") or path.is_symlink():
        raise ValueError("absolute private WAF output required")
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink() or parent.resolve(strict=True) != parent:
        raise ValueError("private WAF output ancestor is unsafe")
    s = parent.stat()
    if s.st_uid != os.geteuid() or stat.S_IMODE(s.st_mode) & 0o077:
        raise ValueError("WAF output directory must be owner-only")
    if not isinstance(data, bytes) or not data or len(data) > MAX_CONFIG:
        raise ValueError("rendered configuration is invalid")
    name = "." + path.name + "." + os.urandom(12).hex() + ".tmp"
    temp = parent / name
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temp, path, follow_symlinks=False)
        folder = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(folder)
        finally:
            os.close(folder)
    finally:
        temp.unlink(missing_ok=True)


def verify_and_render(policy_path, approvals, reviewer_keys, floor_path,
                      ruleset, mode, output, *, now=None, shadow=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    # Capture the complete policy bytes and compare after the signature gate.
    # A policy switched after verification must never control the renderer.
    raw = signed._read_file(policy_path)
    approved_digest = hashlib.sha256(raw).hexdigest().upper()
    revision = signed.verify(policy_path, approvals, reviewer_keys, floor_path,
                             ruleset, mode, now, shadow_evidence_path=shadow)
    if raw != signed._read_file(policy_path):
        raise ValueError("signed WAF policy changed during rendering")
    for approval in approvals:
        if signed._json(signed._read_file(approval, 16384))["policySha256"] != approved_digest:
            raise ValueError("rendered policy differs from approved digest")
    doc = signed._json(raw)
    if doc["revision"] != revision:
        raise ValueError("approved WAF revision changed")
    data = render(doc, now)
    write_private_new(output, data)
    return (revision, hashlib.sha256(data).hexdigest().upper())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--approval", type=Path, action="append", required=True)
    parser.add_argument("--reviewer-key", action="append", required=True)
    parser.add_argument("--minimum-revision-file", type=Path, required=True)
    parser.add_argument("--observed-ruleset-sha256", required=True)
    parser.add_argument("--observed-mode", choices=("detect", "block"), required=True)
    parser.add_argument("--shadow-evidence-file", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        keys = {}
        for item in args.reviewer_key:
            who, sep, path = item.partition("=")
            if not sep or who in keys or not signed._safe_id(who) or not Path(path).is_absolute():
                raise ValueError("invalid independent reviewer trust input")
            keys[who] = Path(path)
        revision, digest = verify_and_render(
            args.policy, args.approval, keys, args.minimum_revision_file,
            args.observed_ruleset_sha256, args.observed_mode, args.out,
            shadow=args.shadow_evidence_file)
    except (ValueError, KeyError, OSError, TypeError, UnicodeError):
        print("FAIL: signed WAF scoped exception candidate refused", file=sys.stderr)
        return 1
    print(f"PASS: private signed exception candidate revision={revision} sha256={digest}; NOT deployed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
