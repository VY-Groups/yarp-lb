#!/usr/bin/env python3
"""Single-node, fail-closed signed external WAF detect/block rollout.

Requires a separately authorized operator and two cryptographic approvals.
Does NOT implement a distributed two-host transaction, exception rendering,
authenticated external audit collector or production fleet key custody.
"""
import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import verify_signed_policy as signatures

OCI_IMAGE = re.compile(r"owasp/modsecurity-crs@sha256:[a-f0-9]{64}\Z")
DOCKER_ID = re.compile(r"[a-f0-9]{12,64}\Z")
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
MODES = {"detect": "DetectionOnly", "block": "On"}
MAX_DOCKER_OUTPUT = 2 * 1024 * 1024


def strict_json(raw):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique_pairs)


def private_directory(path):
    path = Path(path)
    if not path.is_absolute() or not path.is_dir() or path.is_symlink():
        raise ValueError("private operator directory required")
    st = path.stat()
    if st.st_uid != os.geteuid() or stat.S_IMODE(st.st_mode) & 0o077:
        raise ValueError("operator directory must be owned and owner-only")
    return path


def receipt(path, item):
    path = Path(path)
    parent = private_directory(path.parent)
    if path.name in ("", ".", "..") or not path.is_absolute():
        raise ValueError("private absolute receipt path required")
    result = json.dumps(item, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(result) > 8192:
        raise ValueError("operator receipt is oversized")
    temp = parent / ("." + path.name + "." + os.urandom(12).hex() + ".tmp")
    fd = None
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.write(fd, result)
        os.fsync(fd)
        os.close(fd)
        fd = None
        # Exclusive hardlink promotion rejects existing receipts without
        # ever overwriting the history. The temp inode is private and local.
        os.link(temp, path, follow_symlinks=False)
        dirfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            temp.unlink()
        except FileNotFoundError:
            pass


@contextlib.contextmanager
def operator_lock(parent):
    parent = private_directory(parent)
    lock = parent / ".signed-waf-rollout.lock"
    fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1 or \
                fst.st_uid != os.geteuid() or stat.S_IMODE(fst.st_mode) & 0o077:
            raise ValueError("unsafe operator lock")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def run_checked(argv, env=None):
    result = subprocess.run(argv, shell=False, env=env, text=False,
                            capture_output=True, timeout=50, check=False)
    if result.returncode or len(result.stdout) > MAX_DOCKER_OUTPUT:
        raise ValueError("Docker provider action or observation failed")
    return result.stdout.decode("utf-8", "strict").strip()


class DockerComposeProvider:
    """Fixed WAF service, pinned image and loopback HTTP acceptance only."""

    def __init__(self, compose, image, health_url, runner=run_checked):
        self.compose = Path(compose)
        self.image = image
        self.runner = runner
        if (not self.compose.is_absolute() or self.compose.is_symlink() or
                not self.compose.is_file() or self.compose.stat().st_size > 262144 or
                not OCI_IMAGE.fullmatch(image)):
            raise ValueError("private pinned WAF Compose contract required")
        u = urllib.parse.urlsplit(health_url)
        if (u.scheme != "http" or u.hostname != "127.0.0.1" or
                u.username is not None or u.password is not None or
                u.query or u.fragment or not u.port or u.path not in ("", "/")):
            raise ValueError("WAF local health endpoint must be literal HTTP loopback")
        self.health = "http://127.0.0.1:" + str(u.port) + "/"

    def command(self, *args, mode=None):
        env = os.environ.copy()
        if mode is not None:
            if mode not in MODES:
                raise ValueError("invalid WAF mode")
            env["WAF_MODE"] = MODES[mode]
        return self.runner(["docker", "compose", "-f", str(self.compose), *args],
                           env=env)

    def image_and_config(self, mode):
        config = strict_json(self.command("config", "--format", "json", mode=mode))
        services = config.get("services")
        if not isinstance(services, dict) or "waf" not in services:
            raise ValueError("WAF service is missing")
        for name, service in services.items():
            if not isinstance(service, dict):
                raise ValueError("invalid Compose service configuration")
            if name != "waf" and (service.get("ports") or
                                  service.get("network_mode") == "host"):
                raise ValueError("origin or secondary service may bypass protected WAF")
        waf = services["waf"]
        if (waf.get("image") != self.image or waf.get("privileged") or
                waf.get("network_mode") == "host" or
                waf.get("environment", {}).get("MODSEC_RULE_ENGINE") != MODES[mode]):
            raise ValueError("mutable or unapproved WAF service configuration")
        raw_image_id = self.runner(["docker", "image", "inspect", self.image,
                                    "--format", "{{.Id}}"], env=os.environ.copy())
        if not IMAGE_ID.fullmatch(raw_image_id):
            raise ValueError("immutable image identifier cannot be verified")
        return raw_image_id

    def inspect(self):
        # Calling ps without mode avoids changing the currently running WAF.
        container_id = self.command("ps", "-q", "waf")
        if not DOCKER_ID.fullmatch(container_id):
            raise ValueError("exactly one existing WAF container required")
        raw = self.runner(["docker", "inspect", container_id, "--format",
                           "{{json .}}"], env=os.environ.copy())
        info = strict_json(raw)
        if not isinstance(info, dict) or not IMAGE_ID.fullmatch(info.get("Image", "")):
            raise ValueError("untrusted WAF container identity")
        env = info.get("Config", {}).get("Env")
        if not isinstance(env, list):
            raise ValueError("WAF runtime environment unavailable")
        matches = [entry.split("=", 1)[1] for entry in env
                   if isinstance(entry, str) and entry.startswith("MODSEC_RULE_ENGINE=")]
        if len(matches) != 1 or matches[0] not in MODES.values():
            raise ValueError("running WAF engine mode unverified")
        mode = next(key for key, val in MODES.items() if val == matches[0])
        if not info.get("State", {}).get("Running"):
            raise ValueError("WAF container is not running")
        return {"mode": mode, "imageId": info["Image"]}

    def apply(self, mode):
        self.image_and_config(mode)
        self.command("up", "--no-deps", "-d", "--force-recreate", "waf", mode=mode)

    def smoke(self, mode):
        # Sends fixed synthetic GET requests only; no customer data or tokens.
        # There are no retries of POST or nonidempotent requests.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        cases = [(self.health, 200),
                 (self.health + "?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
                  403 if mode == "block" else 200)]
        for url, expected in cases:
            status = 0
            try:
                with opener.open(urllib.request.Request(url, method="GET"),
                                 timeout=5) as response:
                    status = response.status
                    response.read(4096)
            except urllib.error.HTTPError as error:
                status = error.code
            if status != expected:
                raise ValueError("WAF local observed HTTP mode acceptance failed")


def transaction(provider, target, revision, receipt_file, policy_sha256):
    """Single-host signed mode switch with verified rollback and audit receipt."""
    if target not in MODES or type(revision) is not int or revision <= 0:
        raise ValueError("invalid approved WAF target")
    if not re.fullmatch(r"[0-9A-F]{64}", policy_sha256):
        raise ValueError("invalid policy digest")
    before = provider.inspect()
    if before["mode"] == target:
        raise ValueError("already active: refuse replaying approved WAF policy")
    prior_image = before["imageId"]
    provider.image_and_config(target)
    provider.smoke(before["mode"])
    recorded_at = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    evidence = {
        "schemaVersion": 1, "scope": "single-node-external-waf-mode-transaction",
        "revision": revision, "policySha256": policy_sha256,
        "previousMode": before["mode"], "requestedMode": target,
        "completedAtUtc": recorded_at,
        "trustedRevisionFloorAdvanced": False, "fleetAtomic": False
    }
    try:
        provider.apply(target)
        after = provider.inspect()
        if after["imageId"] != prior_image or after["mode"] != target:
            raise ValueError("WAF switched image or rejected approved engine mode")
        provider.smoke(target)
        # A successful mode change without a durable audit receipt is NOT
        # accepted: the receipt write belongs inside the rollback boundary.
        receipt(receipt_file, {
            **evidence, "result": "applied", "rollbackVerified": None,
            "sameImageVerified": True
        })
        return "applied"
    except Exception:
        rolled_back = False
        try:
            provider.apply(before["mode"])
            restored = provider.inspect()
            if restored != before:
                raise ValueError("prior WAF image/mode not restored")
            provider.smoke(before["mode"])
            rolled_back = True
        except Exception:
            # This is a critical local operator incident, not a success.
            pass
        try:
            receipt(receipt_file, {
                **evidence,
                "result": "rolled_back" if rolled_back else "rollback_failed",
                "rollbackVerified": rolled_back, "sameImageVerified": False
            })
        except (OSError, ValueError):
            raise ValueError("rollout not accepted; audit receipt unavailable") from None
        raise ValueError("WAF rollout unsuccessful; inspect private receipt") from None

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--approval", type=Path, action="append", required=True)
    parser.add_argument("--reviewer-key", action="append", required=True)
    parser.add_argument("--minimum-revision-file", type=Path, required=True)
    parser.add_argument("--observed-ruleset-sha256", required=True)
    parser.add_argument("--shadow-evidence-file", type=Path)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--confirm-revision", type=int, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not sys.platform.startswith("linux"):
            raise ValueError("only Linux Docker operator adapter supported")
        keys = {}
        for record in args.reviewer_key:
            name, sep, path = record.partition("=")
            if (not sep or not signatures._safe_id(name) or name in keys or
                    not Path(path).is_absolute()):
                raise ValueError("invalid reviewer trust mapping")
            keys[name] = Path(path)
        policy_bytes = signatures._read_file(args.policy)
        policy = signatures._json(policy_bytes)
        if policy.get("exceptions"):
            raise ValueError("exception rendering unsupported: cannot silently bypass rules")
        target = policy.get("mode")
        if target not in MODES:
            raise ValueError("unsupported WAF mode")
        rev = signatures.verify(
            args.policy, args.approval, keys, args.minimum_revision_file,
            args.observed_ruleset_sha256, target,
            shadow_evidence_path=args.shadow_evidence_file)
        if rev != args.confirm_revision:
            raise ValueError("operator revision confirmation mismatch")
        provider = DockerComposeProvider(args.compose, args.image, args.health_url)
        with operator_lock(args.receipt.parent):
            live = provider.inspect()
            if live["imageId"] != provider.image_and_config(live["mode"]):
                raise ValueError("running WAF image differs from reviewed pin")
            if args.execute:
                transaction(provider, target, rev, args.receipt,
                            hashlib.sha256(policy_bytes).hexdigest().upper())
            else:
                # READ ONLY: signed intent does not equal live activation.
                print("PASS: signed WAF mode intent and live image preflight only")
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            subprocess.SubprocessError, urllib.error.URLError, TimeoutError):
        print("FAIL: WAF rollout preflight, activation or rollback", file=sys.stderr)
        return 1
    if args.execute:
        print("PASS: locally applied approved WAF mode with redacted private receipt")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
