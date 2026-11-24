#!/usr/bin/env python3
"""Explicit offline pinned mTLS receive plus independently signed .NET DP restore.

This receiver does not authorize a live-node promotion, elect leaders, advance
a trusted revision floor or export wrapping keys/cookies. The independently
approved published restore bundle is pinned as a complete tree, not just an
apphost that could dynamically load an untrusted DLL beside it.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

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


def restore_once(args, *, fetch=wire.fetch_pinned, stage=wire.stage_received,
                 invoke=subprocess.run):
    global STAGE
    STAGE = "platform-and-operator-approval"
    if not sys.platform.startswith("linux") or not args.approved_offline:
        raise ValueError("explicit offline Linux writer-fencing approval required")
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
    STAGE = "pinned-complete-dotnet-bundle"
    app = verify_restore_app(args.restore_bundle, args.restore_bundle_sha256)
    STAGE = "pinned-mtls-fetch"
    binary = fetch(args.server_url, args.label, args.server_cert_sha256, args.ca,
                   args.certificate, args.private_key)
    if type(binary) is not bytes or len(binary) > wire.MAX_BUNDLE:
        raise ValueError("untrusted encrypted transfer")
    STAGE = "atomic-received-archive"
    received = stage(str(args.destination_root), args.label, binary)
    checkpoint = os.path.join(received, "checkpoint.json")
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
    # An official .NET runtime installed outside /usr/share/dotnet may use
    # DOTNET_ROOT. Preserve only independently trusted, non-writable,
    # canonical runtime-root paths, never an arbitrary inherited search path
    # or untrusted runtime injection setting.
    STAGE = "approved-dotnet-runtime"
    for name in ("DOTNET_ROOT", "DOTNET_ROOT_X64"):
        if name in os.environ:
            path = os.environ[name]
            trusted_dir(path)
            environment[name] = path
    STAGE = "signed-dotnet-restore-subprocess"
    process = invoke(command, shell=False, stdin=subprocess.DEVNULL,
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     env=environment, timeout=180, check=False)
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
    options = parser.parse_args(argv)
    try:
        restore_once(options)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("FAIL: pinned offline ciphertext transfer or signed restore refused",
              file=sys.stderr)
        return 1
    print("PASS: verified encrypted transfer and offline signed restore; "
          "not authorized for live fleet promotion")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
