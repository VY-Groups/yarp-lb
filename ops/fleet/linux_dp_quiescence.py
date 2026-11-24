#!/usr/bin/env python3
"""Node-specific signed systemd quiescence witness for offline Linux DP (#48).

This module cannot start a production gateway or promote restored state.
Operators first approve the exact independently pinned DP etcd recovery
epoch. Each *different* node independently masks its audited writer units
under its own local systemd authority, verifies 0 running main PIDs, and
signs a bounded epoch-specific receipt using an independently held P-256
identity. The receiving node requires two different verified identities.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

import linux_dp_mtls_transport as wire
import linux_dp_quorum_authority as authority

UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@-]{0,75}\.service\Z", re.ASCII)
MAX_RECEIPT = 8192
MAX_UNITS = 8
MAX_AGE = 90
CLOCK_SKEW = 15
OPENSSL = "/usr/bin/openssl"
SYSTEMCTL = "/usr/bin/systemctl"
STAGE = "init"


def require_units(units):
    if (type(units) not in (tuple, list) or not 1 <= len(units) <= MAX_UNITS or
            any(type(unit) is not str or not UNIT.fullmatch(unit)
                for unit in units) or
            list(units) != sorted(set(units))):
        raise ValueError("approved exact service unit inventory required")
    return list(units)


def owner_private(path):
    wire.canonical_absolute(str(path))
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or
            info.st_uid != os.geteuid() or info.st_nlink != 1 or
            stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("independently provisioned signing key not private")
    return str(path)


def epoch(fence):
    identity = getattr(fence, "_identity", None)
    if (type(identity) is not tuple or len(identity) != 4 or
            type(identity[3]) is not str or not
            authority.etcd.NONCE.fullmatch(identity[3])):
        raise ValueError("quiescence epoch not pinned")
    return {"clusterId":str(identity[0]),
            "raftModRevision":str(identity[1]),
            "leaseId":str(identity[2]), "holder":identity[3]}


def canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True, allow_nan=False).encode("ascii")
    if not 0 < len(raw) <= MAX_RECEIPT:
        raise ValueError("unbounded signed quiescence payload")
    return raw


def invoke_systemctl(runner, *parts):
    result = runner([SYSTEMCTL, "--system", "--no-pager",
                     "--no-ask-password", *parts],
                    shell=False, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    check=False, timeout=20)
    if result.returncode:
        raise ValueError("systemd service management or inspection refused")
    if type(result.stdout) is not bytes or len(result.stdout) > 4096:
        raise ValueError("unbounded systemd service-state response")
    return result.stdout.decode("ascii", "strict")


def stopped_and_masked(runner, unit):
    report = invoke_systemctl(
        runner, "show", unit, "--property=LoadState,ActiveState,SubState,"
        "MainPID,UnitFileState")
    entries = {}
    for line in report.splitlines():
        key, sep, value = line.partition("=")
        if not sep or key in entries:
            raise ValueError("ambiguous systemd service-state response")
        entries[key] = value
    return (entries.get("LoadState") in ("loaded", "masked") and
            entries.get("ActiveState") == "inactive" and
            entries.get("SubState") == "dead" and
            entries.get("MainPID") == "0" and
            entries.get("UnitFileState") in ("masked-runtime", "masked"))


def require_private_p256_signer(private_key, *, runner=subprocess.run):
    # Reject a wrong-algorithm, malformed or unavailable signing identity
    # BEFORE stopping any service. An RSA key can produce an OpenSSL dgst
    # signature but cannot satisfy a subsequently approved P-256 receipt.
    owner_private(private_key)
    result = runner([OPENSSL, "pkey", "-in", str(private_key),
                     "-pubout", "-outform", "DER"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, check=False, timeout=15)
    _validated_p256_spki(result)


# Strict DER SubjectPublicKeyInfo for an uncompressed secp256r1 point.
# 30 59 SEQUENCE(89):
#   30 13 AlgorithmIdentifier(ecPublicKey, prime256v1)
#   03 42 00 04 || X(32) || Y(32)
# OpenSSL parses the key first. Do NOT search for OID byte sequences:
# a different curve can contain the P-256 OID inside attacker-controlled
# point bytes and must never be accepted as a second signing authority.
P256_SPKI_PREFIX = bytes.fromhex(
    "3059301306072A8648CE3D020106082A8648CE3D03010703420004"
)


def _validated_p256_spki(result):
    data = getattr(result, "stdout", None)
    if (getattr(result, "returncode", None) != 0 or
            type(data) is not bytes or
            len(data) != len(P256_SPKI_PREFIX) + 64 or
            not data.startswith(P256_SPKI_PREFIX)):
        raise ValueError("strict uncompressed P-256 SPKI signing identity required")
    # Identity digest is canonical uncompressed DER (not PEM formatting).
    # Reject compressed and explicit-curve parameters rather than silently
    # treating non-identical encodings as separate node identities.
    return hashlib.sha256(data).digest()


def sign(private_key, payload, *, runner=subprocess.run):
    require_private_p256_signer(private_key, runner=runner)
    signature = runner([OPENSSL, "dgst", "-sha256",
                        "-sign", str(private_key)],
                       input=payload, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL, check=False, timeout=15)
    if signature.returncode or not 0 < len(signature.stdout) <= 256:
        raise ValueError("P-256 quiescence signing refused")
    return signature.stdout


def canonical_p256_spki(public_key, *, runner=subprocess.run):
    # Independent node identity must be compared by canonical DER SPKI,
    # NOT by mutable PEM formatting. Two copies of the same private key
    # with different comments/line wrapping must never count as two hosts.
    owner_private(public_key)
    result = runner([OPENSSL, "pkey", "-pubin", "-in", str(public_key),
                     "-pubout", "-outform", "DER"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, check=False, timeout=15)
    return _validated_p256_spki(result)


def verify(public_key, payload, signature, *, runner=subprocess.run):
    canonical_p256_spki(public_key, runner=runner)
    if type(signature) is not bytes or not 0 < len(signature) <= 256:
        return False
    with tempfile.TemporaryDirectory(prefix="dp-quiescence-signature-") as folder:
        # Temporary root is private 0700 and the signature contains no keys.
        path = os.path.join(folder, "signature.der")
        wire.safe_write(path, signature)
        response = runner([OPENSSL, "dgst", "-sha256", "-verify",
                           str(public_key), "-signature", path],
                          input=payload, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False, timeout=15)
        return response.returncode == 0


def issue(fence, node_id, units, signing_key, *,
          runner=subprocess.run, clock=time.time):
    global STAGE
    STAGE = "preflight"
    if (not sys.platform.startswith("linux") or
            type(node_id) is not str or node_id not in
            (fence.sender, fence.receiver) or
            fence.current("preflight") is not True):
        raise ValueError("offline service quiescence requires signed quorum approval")
    approved_units = require_units(units)
    require_private_p256_signer(signing_key, runner=runner)

    for unit in approved_units:
        # Stop first, mask against service-manager autorestart, then prove
        # stopped and masked. Never unmask/resume on later failure.
        STAGE = "stop-registered-writer"
        invoke_systemctl(runner, "stop", unit)
        STAGE = "mask-registered-writer"
        invoke_systemctl(runner, "mask", "--runtime", unit)
        # A unit file may remain cached as "disabled" even when a runtime
        # /dev/null mask symlink was created. The service manager itself
        # must reload and confirm its EFFECTIVE masked state; successful
        # systemctl exit alone must never count as writer fencing.
        invoke_systemctl(runner, "daemon-reload")
        STAGE = "verify-masked-inactive"
        if not stopped_and_masked(runner, unit):
            raise ValueError("writer remains active or can restart")
    STAGE = "verify-live-quorum-after-stop"
    if fence.current("before-transfer") is not True:
        raise ValueError("recovery lease expired while stopping key-ring writers")
    remaining = fence.remaining_seconds()
    if not remaining >= 20:
        raise ValueError("insufficient independent lease runway for receipt")
    now = int(clock())
    lifetime = min(MAX_AGE, int(remaining) - 10)
    if lifetime < 10:
        raise ValueError("insufficient signed stop receipt lifetime")

    payload = {
        "schemaVersion":1, "kind":"linux-dp-quiescence",
        "fleet":fence.client.fleet,
        "nodeId":node_id, "senderNodeId":fence.sender,
        "receiverNodeId":fence.receiver,
        "revision":fence.revision,
        "checkpointSha256":fence.checkpoint_sha,
        "epoch":epoch(fence),
        "serviceUnits":approved_units,
        "serviceState":"masked-inactive",
        "issuedUtc":now, "expiresUtc":now+lifetime
    }
    STAGE = "sign-node-quiescence"
    data = canonical(payload)
    return canonical({"payload":payload,
                      "signature":base64.b64encode(
                          sign(signing_key, data, runner=runner)).decode("ascii")})


def verify_receipt(wire_bytes, public_key, fence, node_id, units,
                   *, clock=time.time, runner=subprocess.run):
    if type(wire_bytes) is not bytes or not 0 < len(wire_bytes) <= MAX_RECEIPT:
        raise ValueError("unbounded independently signed quiescence receipt")
    record = authority.etcd.strict_json(wire_bytes)
    if (type(record) is not dict or set(record) != {"payload", "signature"} or
            type(record["payload"]) is not dict or
            type(record["signature"]) is not str):
        raise ValueError("invalid signed quiescence record envelope")
    payload = record["payload"]
    if set(payload) != {
        "schemaVersion","kind","fleet","nodeId","senderNodeId",
        "receiverNodeId","revision","checkpointSha256","epoch",
        "serviceUnits","serviceState","issuedUtc","expiresUtc"
    }:
        raise ValueError("invalid signed quiescence fields")
    now = int(clock())
    issued, expires = payload["issuedUtc"], payload["expiresUtc"]
    if (type(issued) is not int or type(expires) is not int or
            issued > now + CLOCK_SKEW or now >= expires or
            expires <= issued or expires - issued > MAX_AGE):
        raise ValueError("expired or unbounded signed quiescence claim")
    if (payload["schemaVersion"] != 1 or payload["kind"] != "linux-dp-quiescence" or
            payload["fleet"] != fence.client.fleet or
            payload["nodeId"] != node_id or
            payload["senderNodeId"] != fence.sender or
            payload["receiverNodeId"] != fence.receiver or
            type(payload["revision"]) is not int or
            payload["revision"] != fence.revision or
            payload["checkpointSha256"] != fence.checkpoint_sha or
            payload["epoch"] != epoch(fence) or
            payload["serviceState"] != "masked-inactive" or
            payload["serviceUnits"] != require_units(units)):
        raise ValueError("receipt does not bind exact authorized quiescence epoch")
    try:
        signature = base64.b64decode(record["signature"], validate=True)
    except (ValueError, TypeError):
        raise ValueError("untrusted quiescence signature encoding") from None
    if not verify(public_key, canonical(payload), signature, runner=runner):
        raise ValueError("independent node quiescence P-256 signature invalid")
    return True


def verify_two_receipts(fence, source_wire, destination_wire, *,
                        sender_key, receiver_key, sender_units,
                        receiver_units, clock=time.time, runner=subprocess.run):
    # The quorum must already have been pinned at receiver preflight.
    if (fence.sender == fence.receiver or
            not getattr(fence, "_identity", None) or
            fence.remaining_seconds() < 10):
        raise ValueError("fresh authenticated recovery epoch required")
    if (canonical_p256_spki(sender_key, runner=runner) ==
            canonical_p256_spki(receiver_key, runner=runner)):
        raise ValueError("same P-256 SPKI identity cannot witness two nodes")
    first = verify_receipt(source_wire, sender_key, fence, fence.sender,
                           sender_units, clock=clock, runner=runner)
    second = verify_receipt(destination_wire, receiver_key, fence, fence.receiver,
                           receiver_units, clock=clock, runner=runner)
    return first and second


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-offline", action="store_true")
    for name in ("fleet-quorum-inventory", "fleet", "sender-node-id",
                 "receiver-node-id", "checkpoint-sha256", "etcd-ca",
                 "etcd-certificate", "etcd-private-key", "node-id",
                 "signing-private-key", "output-receipt"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--recovery-revision", required=True, type=int)
    parser.add_argument("--writer-unit", action="append", required=True)
    options = parser.parse_args(argv)
    try:
        if not options.approved_offline or not sys.platform.startswith("linux"):
            raise ValueError("explicit operator approval and Linux required")
        inventory = wire.read_private_path(options.fleet_quorum_inventory, 8192)
        doc = authority.etcd.strict_json(inventory)
        if (type(doc) is not dict or set(doc) != {
                "schemaVersion","fleet","clusterId","endpoints"} or
                doc["schemaVersion"] != 1 or doc["fleet"] != options.fleet or
                type(doc["endpoints"]) is not list):
            raise ValueError("unapproved independent Raft cluster inventory")
        fence = authority.RecoveryFence(
            options.fleet, doc["endpoints"], doc["clusterId"],
            options.etcd_ca, options.etcd_certificate, options.etcd_private_key,
            options.sender_node_id, options.receiver_node_id,
            options.recovery_revision, options.checkpoint_sha256)
        out = options.output_receipt
        wire.canonical_absolute(out)
        fd = wire.private_directory(os.path.dirname(out))
        os.close(fd)
        if os.path.lexists(out):
            raise ValueError("signed writer receipt may not be overwritten")
        binary = issue(fence, options.node_id, tuple(options.writer_unit),
                       options.signing_private_key)
        wire.safe_write(out, binary)
        fd = wire.private_directory(os.path.dirname(out))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # Never expose signed receipts, TLS keys, service identities, paths,
        # private exception content or real systemd output.
        stages = {"init","preflight","stop-registered-writer",
                  "mask-registered-writer","verify-masked-inactive",
                  "verify-live-quorum-after-stop","sign-node-quiescence"}
        print("FAIL: signed Linux DP writer quiescence at " +
              (STAGE if STAGE in stages else "unclassified"), file=sys.stderr)
        return 1
    print("PASS: independently signed and still-masked OFFLINE service witness; "
          "not a production promotion authorization")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
