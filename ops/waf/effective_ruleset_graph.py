#!/usr/bin/env python3
"""Attest observed Docker WAF Nginx/ModSecurity include reachability (#51).

This does NOT claim runtime policy approval, source-image signature trust,
physical host security, tenant request enforcement, or enterprise WAF GO.
Read all config only in bounded memory; never export raw Nginx/CRS content.
"""
import argparse
import fnmatch
import hashlib
import os
from pathlib import PurePosixPath
import re
import selectors
import subprocess
import sys
import time

import runtime_ruleset_inventory as rules

ROOT = "/etc/modsecurity.d"
RULE_PREFIX = ROOT + "/owasp-crs/rules/"
MAX_FILE = 1024 * 1024
MAX_FILES = 512
MAX_TOTAL = 20 * 1024 * 1024
MAX_LISTING = 128 * 1024
MODSEC_ON = re.compile(r"(?m)^\s*modsecurity\s+on\s*;")
MODSEC_OFF = re.compile(r"(?m)^\s*modsecurity\s+off\s*;")
MODSEC_FILE = re.compile(
    r'(?m)^\s*modsecurity_rules_file\s+["\x27]?(/etc/modsecurity\.d/[a-zA-Z0-9_.\-/]+)["\x27]?\s*;')
INCLUDE = re.compile(r"(?i)^\s*Include\s+([^\s;#]+)\s*;?\s*$")
FAMILY = re.compile(r"(?:REQUEST|RESPONSE)-([0-9]{3})-", re.ASCII)


def run_bounded(argv, *, max_bytes, timeout=35):
    if max_bytes > MAX_TOTAL or max_bytes <= 0:
        raise ValueError("unbounded runtime WAF inspection")
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               shell=False, bufsize=0)
    deadline = time.monotonic() + timeout
    data = bytearray()
    try:
        with selectors.DefaultSelector() as select:
            select.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select(remaining):
                    raise ValueError("running WAF inspection timed out")
                block = os.read(process.stdout.fileno(),
                                min(65536, max_bytes + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > max_bytes:
                    raise ValueError("running WAF inspection exceeded size cap")
        if process.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
            raise ValueError("running WAF configuration unavailable")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()


def valid_config_path(path):
    if type(path) is not str or not path.startswith(ROOT + "/") or \
            len(path) > 256 or not path.isascii() or "\\" in path or \
            "//" in path or "\x00" in path or \
            not re.fullmatch(r"/etc/modsecurity\.d/[a-zA-Z0-9_./*-]+", path):
        raise ValueError("untrusted ModSecurity include path")
    parts = PurePosixPath(path).parts
    if ".." in parts or "." in parts or path != "/" + "/".join(parts[1:]):
        # The join above handles canonical absolute POSIX spelling.
        raise ValueError("ModSecurity include path not canonical")
    return path


def root_from_nginx(config):
    if not isinstance(config, bytes) or not config or len(config) > MAX_TOTAL:
        raise ValueError("missing effective Nginx configuration")
    text = config.decode("utf-8", "strict")
    # This is an opt-in lab / external nginx integration. A wildcard,
    # conditional or disabled ModSecurity directive is NOT a complete
    # effective-runtime attestation and must fail closed.
    if not MODSEC_ON.search(text) or MODSEC_OFF.search(text):
        raise ValueError("Nginx ModSecurity is not consistently enabled")
    matched = MODSEC_FILE.findall(text)
    if len(matched) != 1:
        raise ValueError("ambiguous Nginx ModSecurity rule-file roots")
    return valid_config_path(matched[0])


def includes_from_conf(blob):
    if not isinstance(blob, bytes) or len(blob) > MAX_FILE:
        raise ValueError("ModSecurity configuration too large")
    text = blob.decode("utf-8", "strict")
    result = []
    for line in text.splitlines():
        line = line.split("#", 1)[0]
        if not line.strip():
            continue
        if re.match(r"(?i)^\s*Include(?:Optional)?\b", line):
            match = INCLUDE.fullmatch(line)
            if match is None:
                raise ValueError("unsupported dynamic or optional ModSecurity include")
            result.append(valid_config_path(match.group(1)))
    return result


def walk_graph(files, root):
    if not isinstance(files, dict) or not (1 <= len(files) <= MAX_FILES) or \
            not all(type(p) is str and type(v) is bytes and
                    0 < len(v) <= MAX_FILE for p, v in files.items()) or \
            sum(len(v) for v in files.values()) > MAX_TOTAL:
        raise ValueError("unbounded ModSecurity config file inventory")
    if len({p.casefold() for p in files}) != len(files):
        raise ValueError("case-aliased WAF configuration path")
    for path in files:
        valid_config_path(path)
        if "*" in path:
            raise ValueError("literal config file path contains wildcard")
    valid_config_path(root)
    if root not in files:
        raise ValueError("effective Nginx ModSecurity entrypoint missing")
    visiting = set()
    reached = set()
    sequence = []

    def visit(path):
        if path in visiting:
            raise ValueError("cyclic ModSecurity configuration include")
        if path in reached:
            raise ValueError("duplicate effective WAF include")
        if path not in files:
            raise ValueError("missing ModSecurity include file")
        visiting.add(path)
        reached.add(path)
        sequence.append(path)
        for match in includes_from_conf(files[path]):
            if "*" in match:
                parent = str(PurePosixPath(match).parent)
                # A wildcard in any ancestor path could escape an intended
                # ruleset namespace or produce ambiguous nested resolution.
                if "*" in parent or "?" in parent:
                    raise ValueError("unsafe nested ModSecurity include wildcard")
                basename = PurePosixPath(match).name
                targets = sorted(p for p in files if
                                 str(PurePosixPath(p).parent) == parent and
                                 fnmatch.fnmatchcase(PurePosixPath(p).name, basename))
            else:
                targets = [match] if match in files else []
            if not targets:
                raise ValueError("missing ModSecurity include target")
            for target in targets:
                visit(target)
        visiting.remove(path)
    visit(root)

    actual_rules = set(p for p in files if p.startswith(RULE_PREFIX) and
                       p.endswith(".conf"))
    included_rules = [p for p in sequence if p in actual_rules]
    if not actual_rules or set(included_rules) != actual_rules:
        raise ValueError("observed CRS files are not all included")
    families = {match.group(1) for p in included_rules
                if (match := FAMILY.match(PurePosixPath(p).name))}
    if not {"930","941","942"}.issubset(families):
        raise ValueError("critical WAF attack families not reachable")
    # A CRS anomaly pass at 949 must execute AFTER the SQLi/XSS attack
    # families, and protocol setup at 900 precedes the evaluated attacks.
    ids = [PurePosixPath(p).name for p in included_rules]
    first = lambda number: min((i for i, name in enumerate(ids)
                                if name.startswith("REQUEST-" + number + "-")),
                               default=-1)
    if not (first("900") >= 0 and first("949") > first("942") >
            first("900") and first("941") > first("900")):
        raise ValueError("unsafe effective CRS setup/attack/anomaly order")
    digest = hashlib.sha256(rules.DOMAIN)
    for path in sorted(actual_rules):
        blob = files[path]
        logical = "rules/" + PurePosixPath(path).name
        name = logical.encode("ascii")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(blob).to_bytes(8, "big"))
        digest.update(blob)
    return digest.hexdigest().upper(), len(included_rules)


def observe(container_id):
    if type(container_id) is not str or not rules.HEX_ID.fullmatch(container_id):
        raise ValueError("invalid pinned WAF Docker identity")
    stage = "nginx-command"
    try:
        nginx = run_bounded(["docker", "exec", container_id, "nginx", "-T"],
                            max_bytes=2*1024*1024)
        stage = "nginx-mode"
        nginx_text = nginx.decode("utf-8", "strict")
        if not MODSEC_ON.search(nginx_text) or MODSEC_OFF.search(nginx_text):
            raise ValueError("Nginx ModSecurity not enabled")
        stage = "nginx-root-count"
        if len(MODSEC_FILE.findall(nginx_text)) != 1:
            raise ValueError("Nginx rule root count mismatch")
        stage = "nginx-root-path"
        root = root_from_nginx(nginx)
        stage = "config-path-listing"
        names = run_bounded(
            ["docker", "exec", container_id, "find", ROOT, "-type", "f",
             "-name", "*.conf"], max_bytes=MAX_LISTING).decode("utf-8", "strict")
        # Unfollowed symlinks can hide additional effective rules. Refuse
        # the whole tree instead of assuming Docker's pinned image has none.
        stage = "config-symlink-check"
        links = run_bounded(["docker", "exec", container_id, "find", ROOT,
                             "-type", "l"], max_bytes=MAX_LISTING)
        if links.strip():
            raise ValueError("symlinked ModSecurity rule path")
        filenames = names.splitlines()
        if len(filenames) > MAX_FILES or len(filenames) != len(set(filenames)):
            raise ValueError("oversized/duplicate WAF path inventory")
        files = {}
        stage = "read-actual-config-bytes"
        for name in filenames:
            valid_config_path(name)
            files[name] = run_bounded(["docker", "exec", container_id,
                                       "cat", name], max_bytes=MAX_FILE)
        stage = "graph-and-inventory"
        digest, count = walk_graph(files, root)
        if digest != rules.observe(container_id):
            raise ValueError("included CRS bytes differ from observed Docker inventory")
        return digest, count
    except (OSError, UnicodeError, subprocess.SubprocessError, ValueError):
        # Safe stage diagnostics only; never dump raw Nginx / rule config.
        raise ValueError("Effective WAF graph rejected at " + stage) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    args = parser.parse_args(argv)
    try:
        digest, count = observe(args.container)
        print(f"PASS: observed effective CRS include graph files={count} sha256={digest}")
        return 0
    except ValueError as exc:
        # Never publish raw Nginx/ModSecurity exception strings or private
        # config paths. A fixed safe phase narrows CI failures reproducibly.
        stages = {
            "nginx-command", "nginx-mode", "nginx-root-count",
            "nginx-root-path", "config-path-listing", "config-symlink-check",
            "read-actual-config-bytes", "graph-and-inventory"
        }
        stage = str(exc).removeprefix("Effective WAF graph rejected at ")
        if stage not in stages:
            stage = "preflight"
        print("FAIL: effective live WAF include graph at stage=" + stage,
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
