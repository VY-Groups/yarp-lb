#!/usr/bin/env python3
"""Exercise a newly rendered P-256-approved exception against REAL Docker CRS.

Disposable GitHub Linux CI only. No customer signatures/payloads and no
production WAF config changes. Raw native audit stays memory/private.
"""
import base64
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "waf"))
import render_signed_exceptions as renderer
import runtime_ruleset_inventory as inventory
import verify_signed_policy as signed
import live_signed_rollout as live
import correlate_native_audit as native

PORT = 18889
STAGE = "initial"
CASE = re.compile(r"(?im)^X-GatewayCore-CI-Case:\s*(signed-[a-z-]+)\s*$")
CRS_920420 = re.compile(r'\[id "920420"\]')


def compose_run(command, *, env, timeout=60):
    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    if result.returncode:
        raise ValueError("private signed WAF Docker acceptance command failed")
    if len(result.stdout) > native.MAX_AUDIT_BYTES:
        raise ValueError("private signed WAF Docker observation oversized")
    return result.stdout.decode("utf-8", "replace")


def probe(path, case, mime="application/pkix-cert"):
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    try:
        # The JSON control must contain valid JSON; a fake non-JSON body
        # would trigger CRS body-processing failure instead of testing the
        # signed exception and produce a false startup-failure signal.
        payload = (b'{"fixture":"ordinary"}' if mime == "application/json"
                   else b"synthetic-bounded-public-upload")
        connection.request("POST", path, body=payload,
                           headers={"Content-Type": mime, "Connection": "close",
                                    "X-GatewayCore-CI-Case": case})
        response = connection.getresponse()
        status = response.status
        body = response.read(1024)
        if response.read(1):
            raise ValueError("unbounded WAF lab response")
        return status, body
    finally:
        connection.close()


def main(compose):
    global STAGE
    STAGE = "verify_existing_ruleset"
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise ValueError("real signed exception test restricted to disposable Linux CI")
    source = Path(compose).resolve(strict=True)
    if source != ROOT / "integrations" / "WafCrs" / "compose.lab.yml":
        raise ValueError("real WAF acceptance requires fixed disposable Compose file")
    original = source.read_text(encoding="utf-8")
    publish = '"127.0.0.1:18888:8080"'
    if original.count(publish) != 1:
        raise ValueError("unexpected disposable WAF port layout")
    existing = subprocess.check_output(
        ["docker", "compose", "-f", str(source), "ps", "--quiet", "waf"],
        timeout=15, text=True).strip()
    observed_digest = inventory.observe(existing)
    if not signed._digest(observed_digest):
        raise ValueError("actual running CRS inventory missing")

    old_umask = os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="gatewaycore-waf-scoped-ci-") as tmp:
            root = Path(tmp)
            root.chmod(0o700)
            shadow = root / "approved-shadow.json"
            shadow.write_text('{"fixture":"synthetic signed exception"}', encoding="utf-8")
            policy, approvals, reviewer_args, floor = live.approve(
                root, "block", 7, shadow, observed_digest)
            now = dt.datetime.now(dt.timezone.utc)
            utc = lambda value: value.strftime("%Y-%m-%dT%H:%M:%SZ")
            raw = json.loads(policy.read_text(encoding="utf-8"))
            raw["exceptions"] = [{
                "exceptionId": "synthetic-pkix", "owner": "fixture-security-owner",
                "reason": "Fixed disposable legitimate DER upload",
                "routeId": "synthetic-cert",
                "httpMethod": "POST", "path": "/signed-pkix",
                "contentType": "application/pkix-cert", "ruleId": 920420,
                "issuedAtUtc": utc(now - dt.timedelta(seconds=50)),
                "expiresAtUtc": utc(now + dt.timedelta(minutes=20))
            }]
            encoded = json.dumps(raw, sort_keys=True, separators=(",", ":")).encode("utf-8")
            policy.write_bytes(encoded)
            digest = hashlib.sha256(encoded).hexdigest().upper()
            for name, approval in zip(("reviewerA", "reviewerB"), approvals):
                doc = json.loads(approval.read_text(encoding="utf-8"))
                doc["policySha256"] = digest
                signed_at = utc(now)
                doc["signedAtUtc"] = signed_at
                signature = live.command(
                    "openssl", "dgst", "-sha256", "-sign",
                    str(root / "independent-signers" / (name + ".key")),
                    input=signed._approval_payload(digest, name, signed_at))
                doc["signatureBase64"] = base64.b64encode(signature).decode("ascii")
                approval.write_text(json.dumps(doc), encoding="utf-8")
            reviewers = dict(item.split("=", 1) for item in reviewer_args)
            rendered = root / "signed-scoped-exception.conf"
            revision, config_hash = renderer.verify_and_render(
                policy, approvals, {k: Path(v) for k, v in reviewers.items()},
                floor, observed_digest, "block", rendered, now=now, shadow=shadow)
            if revision != 7 or not re.fullmatch(r"[A-F0-9]{64}", config_hash):
                raise ValueError("cryptographically approved WAF configuration missing")

            private_base = root / "compose.signed.yml"
            private_base.write_text(
                original.replace(publish, '"127.0.0.1:18889:8080"'),
                encoding="utf-8")
            private_override = root / "compose.extra.yml"
            private_override.write_text(
                "services:\n  waf:\n    volumes:\n"
                "      - type: bind\n"
                "        source: " + json.dumps(str(rendered)) + "\n"
                "        target: /etc/modsecurity.d/owasp-crs/rules/"
                "REQUEST-901-GATEWAYCORE-SIGNED-PKIX.conf\n"
                "        read_only: true\n", encoding="utf-8")
            STAGE = "compose_fixture_generation"
            prefix = ["docker", "compose", "--project-directory", str(source.parent),
                      "--project-name", "gatewaycore-signed-exception-ci",
                      "-f", str(private_base), "-f", str(private_override)]
            env = os.environ.copy()
            env["WAF_MODE"] = "On"
            env["WAF_IMAGE"] = os.environ["WAF_IMAGE"]
            STAGE = "compose_config_validation"
            compose_run([*prefix, "config", "--quiet"], env=env)
            try:
                STAGE = "compose_start"
                compose_run([*prefix, "up", "--detach"], env=env, timeout=90)
                STAGE = "compose_readiness"
                for _ in range(80):
                    try:
                        if probe("/", "signed-readiness", mime="application/json")[0] == 200:
                            break
                    except (ConnectionError, OSError, TimeoutError, http.client.HTTPException):
                        pass
                    time.sleep(0.6)
                else:
                    raise ValueError("newly rendered WAF configuration failed to start")

                STAGE = "scoped_requests"
                expected = [
                    ("/signed-pkix", "signed-approved", 200),
                    ("/other-route", "signed-outside", 403),
                    ("/signed-pkix?field=1", "signed-query", 403),
                    ("/signed-pkix", "signed-other-mime", 200)
                ]
                for path, name, code in expected:
                    STAGE = "scoped_" + name
                    media = "application/json" if name == "signed-other-mime" else "application/pkix-cert"
                    status, body = probe(path, name, media)
                    if status != code:
                        # Only fixed synthetic case ID, status and numeric
                        # target are safe for public CI; never request bytes.
                        print(f"SYNTHETIC_SIGNED_SCOPE verdict={name} http={status} expected={code}",
                              file=sys.stderr)
                        raise ValueError("signed ModSecurity scoped request was not enforced")
                    if code == 200 and b'"accepted":true' not in body:
                        raise ValueError("signed exception request did not reach private origin")

                STAGE = "origin_isolation"
                container = compose_run([*prefix, "ps", "--quiet", "protected-app"],
                                        env=env).strip()
                ports = json.loads(compose_run(
                    ["docker", "inspect", container, "--format",
                     "{{json .NetworkSettings.Ports}}"], env=env))
                if any(rows for rows in ports.values()):
                    raise ValueError("signed exception lab unexpectedly published origin")
                STAGE = "native_denial_correlation"
                log = compose_run([*prefix, "logs", "--no-color", "waf"],
                                  env=env, timeout=25)
                matches = {"signed-outside": [], "signed-query": []}
                for transaction in native.audit_transactions(log):
                    tags = CASE.findall("\n".join(transaction["B"]))
                    if len(tags) == 1 and tags[0] in matches:
                        matches[tags[0]].append(bool(CRS_920420.search(
                            "\n".join(transaction["H"]))))
                if any(matches[name] != [True] for name in matches):
                    raise ValueError("native ModSecurity audit did not bind scoped 920420 denial")
                print("PASS: signed P-256 exception loads in real CRS; exact URI only, "
                      "native 920420 denials retained outside approved scope")
            finally:
                compose_run([*prefix, "down", "--remove-orphans", "--volumes"],
                            env=env, timeout=60)
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        if len(sys.argv) != 2:
            raise ValueError("expected fixed disposable compose path")
        main(sys.argv[1])
    except (KeyError, ValueError, OSError, UnicodeError, subprocess.SubprocessError,
            TimeoutError, http.client.HTTPException):
        print("FAIL: private real signed WAF exception acceptance at " + STAGE,
              file=sys.stderr)
        raise SystemExit(1)
