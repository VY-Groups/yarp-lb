#!/usr/bin/env python3
"""Explicit offline pinned mTLS receive plus independently signed .NET DP restore.

This receiver does not authorize a live-node promotion, elect leaders, advance
a trusted revision floor or export wrapping keys/cookies. The independently
approved published restore bundle is pinned as a complete tree, not just an
apphost that could dynamically load an untrusted DLL beside it.
"""
import argparse
import hashlib
import hmac
import ipaddress
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.parse import urlsplit

import linux_dp_mtls_transport as wire

MAX_BUNDLE_FILES = 256
MAX_BUNDLE_BYTES = 256 * 1024 * 1024
MAX_SINGLE_FILE = 64 * 1024 * 1024
RESTORE_APP = "LinuxDpEncryptedSnapshot"
STAGE = "init"


def disjoint(a, b):
    a = os.path.realpath(a)
    b = os.path.realpath(b)
    return os.path.commonpath((a, b)) not in (a, b)


def trusted_dir(path, owner_only=False):
    wire.canonical_absolute(str(path))
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid()):
        raise ValueError("untrusted offline tool directory")
    if stat.S_IMODE(info.st_mode) & (0o077 if owner_only else 0o022):
        raise ValueError("writable or broad recovery directory")
    return Path(path)


def tree_hash(folder):
    """Fixed domain-separated deterministic hash of ALL binary/dependency bytes."""
    root = trusted_dir(folder)
    files = []
    size = 0
    for base, dirs, names in os.walk(root, followlinks=False):
        for item in dirs:
            path = Path(base) / item
            trusted_dir(path)
        for name in names:
            path = Path(base) / name
            if path.is_symlink():
                raise ValueError("offline application contains symlink")
            info = os.lstat(path)
            if (not stat.S_ISREG(info.st_mode) or
                    info.st_uid not in (0, os.geteuid()) or
                    info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022 or
                    not 0 < info.st_size <= MAX_SINGLE_FILE):
                raise ValueError("untrusted bundled restore executable or dependency")
            rel = path.relative_to(root).as_posix()
            if not rel or rel.startswith("/") or ".." in rel.split("/"):
                raise ValueError("invalid published bundle member")
            files.append((rel, path, info))
            size += info.st_size
            if len(files) > MAX_BUNDLE_FILES or size > MAX_BUNDLE_BYTES:
                raise ValueError("unbounded offline recovery tool bundle")
    if not files:
        raise ValueError("empty offline signed-restore bundle")
    digest = hashlib.sha256()
    digest.update(b"GatewayCore.LinuxDp.PublishedRestoreBundle.v1\n")
    for rel, path, before in sorted(files):
        # Read an inode opened with O_NOFOLLOW, and compare both metadata
        # snapshots. Root-owned read-only deployed libraries may be 0644.
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            start = os.fstat(fd)
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(start, item) != getattr(before, item) for item in fields):
                raise ValueError("recovery bundle changed during inspection")
            with os.fdopen(fd, "rb") as stream:
                fd = -1
                raw = stream.read(MAX_SINGLE_FILE + 1)
                after = os.fstat(stream.fileno())
                if any(getattr(after, item) != getattr(before, item)
                       for item in fields):
                    raise ValueError("recovery bundle changed during read")
        finally:
            if fd >= 0:
                os.close(fd)
        if len(raw) != before.st_size:
            raise ValueError("incomplete offline tool bundle")
        name = rel.encode("utf-8", "strict")
        digest.update(len(name).to_bytes(4, "big"))
        digest.update(name)
        digest.update(len(raw).to_bytes(8, "big"))
        digest.update(raw)
    return digest.hexdigest().upper()


def verify_restore_app(app_dir, approved_hash):
    if type(approved_hash) is not str or not wire.HEX_SHA.fullmatch(approved_hash):
        raise ValueError("independent exact bundle SHA-256 approval required")
    app_dir = trusted_dir(app_dir)
    exe = app_dir / RESTORE_APP
    info = os.lstat(exe)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
            not info.st_mode & stat.S_IXUSR or info.st_mode & 0o022):
        raise ValueError("approved restore apphost is absent or unsafe")
    if tree_hash(app_dir) != approved_hash:
        raise ValueError("published restore application bundle differs from approval")
    return exe


def require_approved_authority(fence, phase):
    if fence is not None and fence.current(phase) is not True:
        raise ValueError("independent signed DP recovery quorum refused phase")


def build_quorum_authority(args):
    names = (
        "fleet_quorum_inventory", "fleet", "sender_node_id",
        "receiver_node_id", "recovery_revision", "checkpoint_sha256",
        "etcd_ca", "etcd_certificate", "etcd_private_key"
    )
    values = [getattr(args, name, None) for name in names]
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError("incomplete externally approved DP recovery authority")
    import linux_dp_quorum_authority as authority
    inventory_path = args.fleet_quorum_inventory
    for path in (inventory_path, args.etcd_ca, args.etcd_certificate,
                 args.etcd_private_key):
        wire.canonical_absolute(path)
        if (not disjoint(path, args.destination_root) or
                not disjoint(path, args.state_root) or
                not disjoint(path, args.restore_bundle)):
            raise ValueError("independent DP recovery authority overlaps untrusted state")
    raw = wire.read_private_path(inventory_path, 8192)
    config = authority.etcd.strict_json(raw)
    if (type(config) is not dict or set(config) !=
            {"schemaVersion", "fleet", "clusterId", "endpoints"} or
            type(config["schemaVersion"]) is not int or
            config["schemaVersion"] != 1 or
            config["fleet"] != args.fleet or
            type(config["endpoints"]) is not list):
        raise ValueError("unapproved independent etcd recovery inventory")
    return authority.RecoveryFence(
        args.fleet, config["endpoints"], config["clusterId"],
        args.etcd_ca, args.etcd_certificate, args.etcd_private_key,
        args.sender_node_id, args.receiver_node_id, args.recovery_revision,
        args.checkpoint_sha256)


def signed_node_quiescence(args, fence, loopback):
    """Both independent systemd identities must attest the SAME live epoch."""
    fields = ("sender_quiescence_receipt", "receiver_quiescence_receipt",
              "sender_quiescence_public_key", "receiver_quiescence_public_key",
              "sender_writer_units", "receiver_writer_units")
    values = [getattr(args, field, None) for field in fields]
    if all(value is None for value in values):
        if not loopback:
            raise ValueError("remote signed DP recovery requires two independent writer guards")
        return None
    if any(value is None for value in values) or fence is None:
        raise ValueError("partial independent writer fencing authority rejected")
    import linux_dp_quiescence as witness
    for path in values[:4]:
        wire.canonical_absolute(path)
        for unsafe in (args.destination_root, args.state_root,
                       args.restore_bundle):
            if not disjoint(path, unsafe):
                raise ValueError("writer fencing proof overlaps restored state")
    receipts = (wire.read_private_path(values[0], witness.MAX_RECEIPT),
                wire.read_private_path(values[1], witness.MAX_RECEIPT))
    return (witness, receipts, values[2], values[3],
            values[4], values[5])


def require_signed_node_quiescence(proof, fence):
    if proof is None:
        return
    witness, receipts, sender_key, receiver_key, sender_units, receiver_units = proof
    if witness.verify_two_receipts(
            fence, *receipts, sender_key=sender_key, receiver_key=receiver_key,
            sender_units=sender_units, receiver_units=receiver_units) is not True:
        raise ValueError("two-node signed writer quiescence rejected")


def restore_once(args, *, fetch=wire.fetch_pinned, stage=wire.stage_received,
                 invoke=subprocess.run, fence=None):
    global STAGE
    STAGE = "platform-and-operator-approval"
    if not sys.platform.startswith("linux") or not args.approved_offline:
        raise ValueError("explicit offline Linux writer-fencing approval required")
    # A remotely reachable sender requires an independently held quorum
    # authority; an operator's local flag and a pinned leaf alone cannot
    # fence both sides of a fleet partition or authorize remote recovery.
    host = urlsplit(args.server_url).hostname
    try:
        loopback = host is not None and ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    if not loopback and fence is None:
        raise ValueError("remote DP recovery requires independent quorum")
    require_approved_authority(fence, "preflight")
    for path in (args.destination_root, args.state_root, args.trusted_public_key,
                 args.minimum_revision_file, args.restore_bundle):
        wire.canonical_absolute(str(path))
    STAGE = "private-recovery-directories"
    inbox = wire.private_directory(str(args.destination_root))
    os.close(inbox)
    state = wire.private_directory(str(args.state_root))
    os.close(state)
    if (not disjoint(args.destination_root, args.state_root) or
            not disjoint(args.restore_bundle, args.state_root) or
            not disjoint(args.restore_bundle, args.destination_root) or
            not disjoint(args.trusted_public_key, args.destination_root) or
            not disjoint(args.minimum_revision_file, args.destination_root)):
        raise ValueError("restored state, inbox, tool and independent trust must be disjoint")
    STAGE = "independent-trust-custody"
    for item in (args.trusted_public_key, args.minimum_revision_file):
        wire.read_private_path(str(item), 16384)
    if os.path.lexists(os.path.join(args.state_root, "data-protection-keys")):
        raise ValueError("live or previously restored DP ring must not be overwritten")
    STAGE = "independent-two-node-writer-quiescence"
    proof = signed_node_quiescence(args, fence, loopback)
    require_signed_node_quiescence(proof, fence)
    STAGE = "pinned-complete-dotnet-bundle"
    app = verify_restore_app(args.restore_bundle, args.restore_bundle_sha256)
    STAGE = "pinned-mtls-fetch"
    require_approved_authority(fence, "before-transfer")
    require_signed_node_quiescence(proof, fence)
    binary = fetch(args.server_url, args.label, args.server_cert_sha256, args.ca,
                   args.certificate, args.private_key)
    if type(binary) is not bytes or len(binary) > wire.MAX_BUNDLE:
        raise ValueError("untrusted encrypted transfer")
    STAGE = "atomic-received-archive"
    received = stage(str(args.destination_root), args.label, binary)
    # .NET treats the parent of --archive as an untrusted state root and
    # correctly rejects a checkpoint stored INSIDE that snapshot tree.
    # Materialize the signed (still-untrusted) checkpoint as a separate,
    # non-overwriting private file alongside the archive label. The SPKI
    # public key and monotonic floor remain independently provisioned OUTSIDE
    # the entire inbox. Merely moving a checkpoint never grants authority.
    STAGE = "independent-checkpoint-staging"
    raw_checkpoint = wire.read_private_path(
        os.path.join(received, "checkpoint.json"), wire.MAX_MANIFEST)
    if fence is not None:
        # A sender's mTLS cert cannot authorize an unrelated P-256 signed
        # recovery checkpoint. The actual signed .NET restore also verifies
        # signature and independent monotonic revision before installation.
        if (type(fence.checkpoint_sha) is not str or
                not hmac.compare_digest(
                    hashlib.sha256(raw_checkpoint).hexdigest().upper(),
                    fence.checkpoint_sha)):
            raise ValueError("received DP checkpoint differs from quorum epoch")
    require_approved_authority(fence, "after-transfer")
    require_signed_node_quiescence(proof, fence)
    checkpoint = os.path.join(args.destination_root,
                              "." + args.label + ".signed-checkpoint.json")
    wire.safe_write(checkpoint, raw_checkpoint)
    root_fd = wire.private_directory(str(args.destination_root))
    try:
        os.fsync(root_fd)
    finally:
        os.close(root_fd)
    if not disjoint(checkpoint, received):
        raise ValueError("signed checkpoint cannot be inside archive state root")
    ring = os.path.join(received, "ring")
    command = [str(app), "restore", "--archive", ring,
               "--state-root", str(args.state_root),
               "--checkpoint", checkpoint,
               "--trusted-public-key", str(args.trusted_public_key),
               "--minimum-revision-file", str(args.minimum_revision_file)]
    # No shell, NuGet restore, private output capture, network dependency
    # resolution, automatic retry or script supplied by the sender.
    environment = {"PATH": "/usr/bin:/bin",
                   "DOTNET_CLI_TELEMETRY_OPTOUT": "1",
                   "DOTNET_SKIP_FIRST_TIME_EXPERIENCE": "1"}
    # Never import ambient DOTNET_ROOT[_X64] from a shell, service account,
    # runner or sender. A runtime outside the system apphost discovery path
    # requires a separately approved canonical root on this *receiver*.
    # The operator must pin it at the same authorization boundary as the
    # exact whole-application bundle. An unapproved environment variable
    # cannot redirect the recovery executable to a foreign runtime.
    STAGE = "approved-dotnet-runtime"
    runtime_root = getattr(args, "dotnet_runtime_root", None)
    if runtime_root is not None:
        if type(runtime_root) is not str:
            raise ValueError("approved .NET runtime root must be a path")
        trusted_dir(runtime_root)
        host = os.path.join(runtime_root, "dotnet")
        info = os.lstat(host)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid not in
                (0, os.geteuid()) or not info.st_mode & stat.S_IXUSR or
                info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o022):
            raise ValueError("approved .NET runtime executable not trusted")
        environment["DOTNET_ROOT"] = runtime_root
        environment["DOTNET_ROOT_X64"] = runtime_root
    STAGE = "signed-dotnet-restore-subprocess"
    require_approved_authority(fence, "before-signed-restore")
    require_signed_node_quiescence(proof, fence)
    restore_timeout = 180
    if fence is not None:
        # A 120s maximum etcd lease must NEVER authorize an unbounded 180s
        # .NET subprocess. Count from the oldest accepted member's TTL read,
        # not the last server response; leave five seconds to reattest
        # and refuse/reconcile a potentially installed OFFLINE stage.
        remaining = fence.remaining_seconds()
        if (type(remaining) not in (float, int) or
                not math.isfinite(remaining) or remaining < 10):
            raise ValueError("insufficient independently fenced restore runway")
        restore_timeout = min(restore_timeout, int(remaining - 5))
        if restore_timeout < 1:
            raise ValueError("independently authorized restore lease expired")
    process = invoke(command, shell=False, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=environment, timeout=restore_timeout, check=False)
    if process.returncode != 0:
        # No raw child stdout/stderr is ever emitted. An allowlisted numeric
        # process exit distinguishes a .NET host bootstrap failure from a
        # signed restore refusal without exposing private recovery paths.
        STAGE = ("signed-dotnet-exit-" + str(process.returncode)
                 if process.returncode in (1, 131, 134, 150)
                 else "signed-dotnet-exit-other")
        raise ValueError("independent signed .NET snapshot restore refused")
    # Detect externally changed binaries/dependencies after execution.
    STAGE = "post-execution-bundle-integrity"
    if tree_hash(args.restore_bundle) != args.restore_bundle_sha256:
        raise ValueError("restore application changed during execution")
    STAGE = "restored-private-ring-integrity"
    restored = os.path.join(args.state_root, "data-protection-keys")
    if not os.path.lexists(restored):
        raise ValueError("restore exited without installing encrypted key ring")
    directory = wire.private_directory(restored)
    try:
        files = os.listdir(directory)
        if not files or len(files) > wire.MAX_XML_FILES:
            raise ValueError("restored encrypted ring absent or unbounded")
        for name in files:
            if not wire.XML_NAME.fullmatch(name):
                raise ValueError("restored ring contains unknown file")
            wire.private_file(name, directory, wire.MAX_XML)
    finally:
        os.close(directory)
    STAGE = "post-restore-quorum"
    require_approved_authority(fence, "after-signed-restore")
    require_signed_node_quiescence(proof, fence)
    return received


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-offline", action="store_true")
    parser.add_argument("--server-url", required=True)
    parser.add_argument("--server-cert-sha256", required=True)
    parser.add_argument("--destination-root", required=True)
    parser.add_argument("--state-root", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--private-key", required=True)
    parser.add_argument("--trusted-public-key", required=True)
    parser.add_argument("--minimum-revision-file", required=True)
    parser.add_argument("--restore-bundle", required=True)
    parser.add_argument("--restore-bundle-sha256", required=True)
    parser.add_argument("--dotnet-runtime-root",
                        help="optional independently approved non-writable .NET root")
    # All-or-nothing, private operator-provisioned external authority.
    # Issuer mTLS private keys must NOT be reused for this read-only verifier.
    for name in ("fleet-quorum-inventory", "fleet", "sender-node-id",
                 "receiver-node-id", "checkpoint-sha256", "etcd-ca",
                 "etcd-certificate", "etcd-private-key"):
        parser.add_argument("--" + name)
    parser.add_argument("--recovery-revision", type=int)
    for name in ("sender-quiescence-receipt", "receiver-quiescence-receipt",
                 "sender-quiescence-public-key", "receiver-quiescence-public-key"):
        parser.add_argument("--" + name)
    parser.add_argument("--sender-writer-units", nargs="+")
    parser.add_argument("--receiver-writer-units", nargs="+")
    options = parser.parse_args(argv)
    try:
        authority = build_quorum_authority(options)
        restore_once(options, fence=authority)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("FAIL: pinned offline ciphertext transfer or signed restore refused",
              file=sys.stderr)
        return 1
    print("PASS: verified encrypted transfer and offline signed restore; "
          "not authorized for live fleet promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
