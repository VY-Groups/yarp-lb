#!/usr/bin/env python3
"""Canonical digest of CRS .conf bytes observed inside one running WAF container.

This attests the observed rule-file subtree, NOT nginx/modsecurity include
reachability, rule execution, approved source custody or tenant decisions.
No request payload, credential, private policy or raw rule data is printed.
"""
import argparse
import hashlib
import io
import os
from pathlib import PurePosixPath
import re
import selectors
import subprocess
import sys
import tarfile
import time

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_CONF_BYTES = 20 * 1024 * 1024
MAX_ENTRIES = 512
DOMAIN = b"GatewayCore.WAF.ObservedCRSRuleFiles.v1\0"
HEX_ID = re.compile(r"[0-9a-f]{12,64}\Z", re.ASCII)
FAMILY = re.compile(r"(?:REQUEST|RESPONSE)-([0-9]{3})-", re.ASCII)
REQUIRED_FAMILIES = frozenset(("930", "941", "942"))


def limited_docker_copy(container_id, *, limit=MAX_ARCHIVE, timeout=35.0):
    """Read a fixed Docker archive with bounded memory/time; never use shell."""
    if not isinstance(container_id, str) or not HEX_ID.fullmatch(container_id):
        raise ValueError("untrusted Docker container ID")
    if type(limit) is not int or limit <= 0 or limit > MAX_ARCHIVE:
        raise ValueError("unsupported rule-inventory cap")
    command = ["docker", "cp",
               container_id + ":/etc/modsecurity.d/owasp-crs/rules", "-"]
    process = subprocess.Popen(command, shell=False, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, bufsize=0)
    data = bytearray()
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("Docker rule inventory timed out")
                if not selector.select(remaining):
                    raise ValueError("Docker rule inventory timed out")
                block = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
                if len(data) > limit:
                    raise ValueError("Docker rule inventory exceeds size cap")
        if process.wait(timeout=max(0.01, deadline - time.monotonic())) != 0:
            raise ValueError("Docker rule inventory unavailable")
        if not data:
            raise ValueError("Docker returned no CRS inventory")
        return bytes(data)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        if process.stdout:
            process.stdout.close()


def canonical_rule_digest(archive):
    if not isinstance(archive, bytes) or not archive or len(archive) > MAX_ARCHIVE:
        raise ValueError("invalid bounded Docker rule inventory")
    seen = set()
    conf = {}
    count = 0
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
            for entry in tar:
                count += 1
                if count > MAX_ENTRIES:
                    raise ValueError("too many rule archive entries")
                if not entry.name or "\\" in entry.name or entry.name.startswith("/"):
                    raise ValueError("unsafe archive member path")
                # Docker cp often prefixes its selected directory with './'.
                name = entry.name.removeprefix("./").rstrip("/")
                parts = PurePosixPath(name).parts
                if (".." in parts or "." in parts or not parts or
                        parts[0] != "rules"):
                    raise ValueError("unexpected rule archive member")
                if entry.isdir():
                    continue
                if not entry.isfile() or entry.islnk() or entry.issym():
                    raise ValueError("linked or special rule archive entry")
                if name.casefold().endswith(".conf") and not name.endswith(".conf"):
                    raise ValueError("case-aliased CRS config extension")
                if not name.endswith(".conf"):
                    # README/docs in the directory are not live CRS .conf.
                    continue
                if len(parts) != 2 or entry.size < 1 or entry.size > 1024 * 1024:
                    raise ValueError("unbounded or nested CRS rule")
                key = name.casefold()
                if key in seen:
                    raise ValueError("duplicate or case-aliased rule path")
                seen.add(key)
                total += entry.size
                if total > MAX_CONF_BYTES:
                    raise ValueError("CRS rule bytes exceed inventory cap")
                item = tar.extractfile(entry)
                if item is None:
                    raise ValueError("CRS rule content is unreadable")
                content = item.read(entry.size + 1)
                if len(content) != entry.size:
                    raise ValueError("truncated CRS rule")
                conf[name] = content
    except (tarfile.TarError, EOFError, OSError) as exc:
        raise ValueError("invalid CRS rule archive") from None
    families = {m.group(1) for name in conf
                if (m := FAMILY.match(PurePosixPath(name).name))}
    if not REQUIRED_FAMILIES.issubset(families):
        raise ValueError("required XSS, SQLi or traversal rule family missing")
    digest = hashlib.sha256(DOMAIN)
    for path, content in sorted(conf.items()):
        encoded = path.encode("utf-8", "strict")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest().upper()


def observe(container_id):
    return canonical_rule_digest(limited_docker_copy(container_id))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True,
                        help="literal running Docker container hex ID, never a name")
    args = parser.parse_args()
    try:
        digest = observe(args.container)
    except (OSError, ValueError, TimeoutError, subprocess.SubprocessError):
        print("FAIL: bounded running CRS rule inventory unavailable", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
