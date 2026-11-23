#!/usr/bin/env python3
"""Real disposable CRS Docker acceptance of the signed single-node controller.

All signer identities and shadow evidence are freshly generated synthetic
fixtures under a mode-0700 temporary directory; NOTHING is published.
Only invoke after tests/WafCrs/verify.sh restored genuine CRS blocking.
"""
import base64
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "waf"))
import rollout_controller as rollout
import verify_signed_policy as signed

FAKE_RULESET_OBSERVATION = "A" * 64


def command(*args, input=None):
    return subprocess.run(args, input=input, capture_output=True,
                          check=True).stdout


def approve(root, mode, revision, shadow):
    now = dt.datetime.now(dt.timezone.utc)
    utc = lambda t: t.strftime("%Y-%m-%dT%H:%M:%SZ")
    policy_dir = root / ("policy-" + str(revision))
    policy_dir.mkdir(mode=0o700)
    independent = root / "independent-signers"
    independent.mkdir(mode=0o700, exist_ok=True)
    floor = independent / "revision-floor"
    floor.write_text("6\n", encoding="ascii")
    if mode == "block":
        if shadow is None:
            raise ValueError("blocking fixture must supply real temporary shadow bytes")
        evidence_hash = hashlib.sha256(shadow.read_bytes()).hexdigest().upper()
    else:
        evidence_hash = None
    data = {
        "schemaVersion": 1, "revision": revision, "mode": mode,
        "rulesetSha256": FAKE_RULESET_OBSERVATION,
        "shadowEvidenceSha256": evidence_hash,
        "issuedAtUtc": utc(now - dt.timedelta(minutes=2)),
        "expiresAtUtc": utc(now + dt.timedelta(days=1)), "exceptions": []
    }
    policy_file = policy_dir / "policy.json"
    policy_raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    policy_file.write_bytes(policy_raw)
    policy_hash = hashlib.sha256(policy_raw).hexdigest().upper()
    signed_at = utc(now)
    approvals = []
    reviewers = []
    for name in ("reviewerA", "reviewerB"):
        sk = independent / (name + ".key")
        pub = independent / (name + ".pem")
        if not sk.exists():
            command("openssl", "ecparam", "-name", "prime256v1",
                    "-genkey", "-noout", "-out", str(sk))
            command("openssl", "pkey", "-in", str(sk), "-pubout", "-out", str(pub))
        signature = command("openssl", "dgst", "-sha256", "-sign", str(sk),
                            input=signed._approval_payload(policy_hash, name, signed_at))
        record = {
            "schemaVersion": 1, "reviewer": name,
            "policySha256": policy_hash, "signedAtUtc": signed_at,
            "signatureBase64": base64.b64encode(signature).decode("ascii")
        }
        path = policy_dir / (name + ".json")
        path.write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
        approvals.append(path)
        reviewers.append(name + "=" + str(pub))
    return (policy_file, approvals, reviewers, floor)


def verify_mode(provider, mode):
    observed = provider.inspect()
    if observed["mode"] != mode:
        raise AssertionError("real ModSecurity runtime mode differs from tested transaction")


def main(compose_path):
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise ValueError("signed WAF live acceptance is disposable Linux CI-only")
    compose = Path(compose_path).resolve(strict=True)
    image = json.loads(command("docker", "compose", "-f", str(compose),
                               "config", "--format", "json"))["services"]["waf"]["image"]
    provider = rollout.DockerComposeProvider(compose, image,
                                             "http://127.0.0.1:18888/")
    verify_mode(provider, "block")
    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="gatewaycore-waf-signed-ci-") as temp:
            root = Path(temp)
            root.chmod(0o700)
            receipts = root / "receipts"
            receipts.mkdir(mode=0o700)
            shadow = root / "approved-synthetic-shadow.json"
            shadow.write_text('{"scope":"synthetic-lab-only","result":"manual-approval-fixture"}',
                              encoding="utf-8")
            for mode, revision in (("detect", 7), ("block", 8)):
                policy, approvals, reviewers, floor = approve(
                    root, mode, revision, shadow if mode == "block" else None)
                report = receipts / ("revision-" + str(revision) + ".json")
                args = [
                    "--policy", str(policy),
                    "--approval", str(approvals[0]),
                    "--approval", str(approvals[1]),
                    "--reviewer-key", reviewers[0],
                    "--reviewer-key", reviewers[1],
                    "--minimum-revision-file", str(floor),
                    "--observed-ruleset-sha256", FAKE_RULESET_OBSERVATION,
                    "--compose", str(compose), "--image", image,
                    "--health-url", "http://127.0.0.1:18888/",
                    "--receipt", str(report),
                    "--confirm-revision", str(revision)
                ]
                if mode == "block":
                    args += ["--shadow-evidence-file", str(shadow)]
                if rollout.main(args) != 0:
                    raise AssertionError("signed WAF preflight failed")
                verify_mode(provider, "block" if mode == "detect" else "detect")
                if rollout.main(args + ["--execute"]) != 0:
                    raise AssertionError("actual signed WAF mode activation failed")
                verify_mode(provider, mode)
                observed = json.loads(report.read_text(encoding="utf-8"))
                if (observed.get("result") != "applied" or
                        observed.get("revision") != revision or
                        observed.get("trustedRevisionFloorAdvanced") is not False):
                    raise AssertionError("WAF signed local receipt mismatch")
                if report.stat().st_mode & 0o077:
                    raise AssertionError("WAF signed receipt is not owner-only")
            # A signed blocking approval cannot be replayed after its
            # evidence bytes are modified; live mode must remain blocking.
            shadow.write_text('{"scope":"tampered"}', encoding="utf-8")
            if rollout.main(args + ["--execute"]) == 0:
                raise AssertionError("tampered signed shadow evidence accepted")
            verify_mode(provider, "block")
            print("PASS: real Docker WAF signed detect/block, image and private receipt"
                  " acceptance; tampered evidence rejected", flush=True)
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("required absolute disposable Compose file")
        main(sys.argv[1])
    except (OSError, ValueError, subprocess.SubprocessError, AssertionError):
        print("FAIL: signed disposable real WAF rollout acceptance", file=sys.stderr)
        raise SystemExit(1)
