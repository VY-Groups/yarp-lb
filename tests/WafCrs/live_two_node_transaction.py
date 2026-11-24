#!/usr/bin/env python3
"""Actual two Docker WAF instances testing fenced coordinator compensation.

Uses disposable P-256 signatures and a SYNTHETIC fencing callback only.
No two physical hosts, authenticated network leases or customer traffic.
All private logs/keys remain in a 0700 temporary directory, never uploaded.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "waf"))
import two_node_transaction as dual
import rollout_controller as rollout
import verify_signed_policy as signed
import live_signed_rollout as fixture

LABELS = ("node-a", "node-b")
PORTS = (18890, 18891)


class DisposableFence:
    """In-process test-only fence; explicitly NOT distributed authority."""
    def __init__(self, revision, policy_digest):
        self.revision = revision
        self.digest = policy_digest
        self.seen = []

    def assert_current(self, names, revision, digest, phase):
        self.seen.append(phase)
        return (names == LABELS and revision == self.revision and
                digest == self.digest and phase in (
                "preflight", "check-node-a", "check-node-b", "before-journal",
                "before-apply-node-a", "after-apply-node-a",
                "before-apply-node-b", "after-apply-node-b", "before-receipt",
                "rollback-node-a", "rollback-node-b"))


def checked(cmd, *, env=None, timeout=60):
    run = subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         timeout=timeout, check=False)
    if run.returncode != 0:
        raise ValueError("synthetic WAF Docker environment command failed")


def prepare_node(parent, name, port, source):
    layout = parent / name
    compose_dir = layout / "integrations" / "WafCrs"
    fixture_dir = layout / "tests" / "WafCrs"
    compose_dir.mkdir(parents=True, mode=0o700)
    fixture_dir.mkdir(parents=True, mode=0o700)
    original = source.read_text(encoding="utf-8")
    old_port = '"127.0.0.1:18888:8080"'
    if original.count(old_port) != 1:
        raise ValueError("unexpected WAF port schema in synthetic fixture")
    manifest = compose_dir / "compose.lab.yml"
    manifest.write_text(original.replace(
        old_port, f'"127.0.0.1:{port}:8080"'), encoding="utf-8")
    for src, dest in (
        (source.parent / "REQUEST-900-LAB-PKIX.conf",
         compose_dir / "REQUEST-900-LAB-PKIX.conf"),
        (ROOT / "tests" / "WafCrs" / "backend.py",
         fixture_dir / "backend.py"),
        (ROOT / "tests" / "WafCrs" / "benchmark.py",
         fixture_dir / "benchmark.py"),
    ):
        shutil.copyfile(src, dest)
        dest.chmod(0o644)  # Disposable non-secret Docker bind mounts only.
    return manifest


def verify_two_signatures(root, rev, shadow, digest):
    policy, approvals, identities, floor = fixture.approve(
        root, "block", rev, shadow, digest)
    keys = dict(item.split("=", 1) for item in identities)
    result = signed.verify(policy, approvals, {k: Path(v) for k, v in keys.items()},
                           floor, digest, "block", shadow_evidence_path=shadow)
    if result != rev:
        raise ValueError("synthetic real P-256 approvals do not authorize revision")
    return hashlib.sha256(policy.read_bytes()).hexdigest().upper()


def run(source):
    if os.getenv("GITHUB_ACTIONS") != "true" or os.getenv("RUNNER_OS") != "Linux":
        raise ValueError("two-node Docker WAF test is disposable GitHub Linux CI only")
    source = Path(source).resolve(strict=True)
    if source != ROOT / "integrations" / "WafCrs" / "compose.lab.yml":
        raise ValueError("unexpected WAF Docker fixture")
    image = os.getenv("WAF_IMAGE", "")
    if not rollout.OCI_IMAGE.fullmatch(image):
        raise ValueError("immutable WAF image is required")
    old_umask = os.umask(0o077)
    nodes = {}
    try:
        with tempfile.TemporaryDirectory(prefix="gatewaycore-two-node-waf-ci-") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            receipts = root / "private-receipts"
            receipts.mkdir(mode=0o700)
            for name, port in zip(LABELS, PORTS):
                compose = prepare_node(root, name, port, source)
                provider = rollout.DockerComposeProvider(
                    compose, image, f"http://127.0.0.1:{port}/",
                    project_name="gatewaycore-two-node-" + name)
                nodes[name] = provider
            try:
                for provider in nodes.values():
                    # Compose starts its private backend alongside the WAF.
                    provider.command("up", "--detach", mode="detect")
                    provider.smoke("detect")
                rules = {provider.observed_rule_digest() for provider in nodes.values()}
                if len(rules) != 1:
                    raise ValueError("separate live WAF instances have different CRS inventories")
                digest = next(iter(rules))
                if not signed._digest(digest):
                    raise ValueError("observed CRS digest not canonical")
                shadow = root / "private-synthetic-shadow.json"
                shadow.write_text('{"scope":"two-disposable-WAF-containers"}',
                                  encoding="utf-8")
                # First: deliberate second-node failure AFTER a real Docker
                # mutation. Both actual nodes must recover to DetectionOnly.
                revision = 7
                hash7 = verify_two_signatures(root, revision, shadow, digest)
                fail_receipt = receipts / "revision-7.json"
                real_apply = nodes["node-b"].apply

                def fault_after_real_apply(mode):
                    real_apply(mode)
                    if mode == "block":
                        raise ValueError("synthetic failure after second remote apply")

                nodes["node-b"].apply = fault_after_real_apply
                try:
                    try:
                        dual.coordinate(nodes, "block", revision, hash7, digest,
                                        fail_receipt,
                                        fence=DisposableFence(revision, hash7))
                    except ValueError:
                        pass
                    else:
                        raise ValueError("partially applied live WAF fleet accepted")
                finally:
                    nodes["node-b"].apply = real_apply
                if fail_receipt.exists():
                    raise ValueError("failed two-node transaction wrote success receipt")
                failed = json.loads((receipts / ".revision-7.json.failure").read_text())
                if (failed["result"] != "rolled-back" or
                        failed["rollbackVerified"] !=
                        {"node-a": True, "node-b": True}):
                    raise ValueError("real two-node compensating rollback not verified")
                for provider in nodes.values():
                    if provider.inspect()["mode"] != "detect":
                        raise ValueError("partial WAF rollout left an active block mode")
                    provider.smoke("detect")
                print("PASS: two real isolated WAF instances compensate after "
                      "second-node post-apply failure")

                # Second: approved new signed revision applies successfully
                # to both real Docker instances. Never advance trusted floor.
                revision = 8
                hash8 = verify_two_signatures(root, revision, shadow, digest)
                good = receipts / "revision-8.json"
                if dual.coordinate(nodes, "block", revision, hash8, digest, good,
                                   fence=DisposableFence(revision, hash8)) != \
                        "applied-uncommitted":
                    raise ValueError("two-node WAF signed candidate incomplete")
                applied = json.loads(good.read_text(encoding="utf-8"))
                if (applied["nodesVerified"] != list(LABELS) or
                        applied["trustedRevisionFloorAdvanced"] is not False or
                        applied["fleetAtomic"] is not False):
                    raise ValueError("false distributed guarantee in audit receipt")
                for provider in nodes.values():
                    if provider.inspect()["mode"] != "block":
                        raise ValueError("signed second WAF instance not activated")
                    provider.smoke("block")
                print("PASS: signed two-node WAF real image/mode/CRS/HTTP "
                      "software transaction with private durable receipts")
            finally:
                for provider in nodes.values():
                    try:
                        provider.command("down", "--remove-orphans", "--volumes")
                    except (OSError, ValueError, subprocess.SubprocessError):
                        # Cleanup failures must not leak raw Docker logs.
                        raise ValueError("WAF container cleanup was unsuccessful") from None
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected fixed isolated WAF fixture path")
        run(sys.argv[1])
    except (OSError, ValueError, KeyError, TypeError, RuntimeError,
            subprocess.SubprocessError, UnicodeError):
        print("FAIL: two-node signed WAF Docker software acceptance", file=sys.stderr)
        raise SystemExit(1)
