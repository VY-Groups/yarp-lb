"""Narrow local dashboard bridge for an independently provisioned WAF operation."""
import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct

import verify_signed_policy as signed
import waf_fleet_rollout as rollout

MAX_REQUEST = 1024


def dispatch(raw, approved, peer_uid, allowed_uid):
    if peer_uid != allowed_uid:
        return "refused-or-failed"
    try:
        request = signed._json(raw)
        if (type(request) is not dict or set(request) != {"operation", "revision", "digest"} or
                request["operation"] not in ("preflight", "execute") or
                type(request["revision"]) is not int or
                request["revision"] != approved.confirm_revision or
                request["digest"] != approved.confirm_policy_sha256):
            return "refused-or-failed"
        # Never interpret web data as command arguments. The signed
        # coordinator validates the exact approved file and current fence.
        args = argparse.Namespace(**vars(approved))
        args.execute = request["operation"] == "execute"
        result = rollout.run(args)
        expected = "applied-uncommitted" if args.execute else "preflight-only"
        return result if result == expected else "refused-or-failed"
    except Exception:
        return "refused-or-failed"


def serve(socket_path, manifest):
    if not hasattr(socket, "SO_PEERCRED"):
        raise ValueError("Linux peer credentials required")
    path = Path(manifest)
    # Independent operator must own the manifest and its parent. The
    # service UID must not be the gateway's UID.
    metadata = path.lstat()
    if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
        raise ValueError("manifest must be operator-owned and private")
    config = signed._json(signed._read_file(path))
    if (type(config) is not dict or set(config) != {"gatewayUid", "argv"} or
            type(config["gatewayUid"]) is not int or config["gatewayUid"] <= 0 or
            config["gatewayUid"] == os.geteuid() or not isinstance(config["argv"], list) or
            not all(isinstance(a, str) for a in config["argv"]) or "--execute" in config["argv"]):
        raise ValueError("invalid operator manifest")
    approved = rollout.parse_args(config["argv"])
    if approved.execute:
        raise ValueError("manifest cannot enable execute automatically")
    target = Path(socket_path)
    if not target.is_absolute() or target.exists() or target.is_symlink():
        raise ValueError("new absolute socket path required")
    parent = target.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o022:
        raise ValueError("socket parent must be operator-owned and not group/world writable")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            self.connection.settimeout(5)
            peer = self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            _, uid, _ = struct.unpack("3i", peer)
            if uid != config["gatewayUid"]:
                return
            raw = self.rfile.readline(MAX_REQUEST + 1)
            result = "refused-or-failed"
            if len(raw) <= MAX_REQUEST and raw.endswith(b"\n"):
                result = dispatch(raw, approved, uid, config["gatewayUid"])
            self.wfile.write((result + "\n").encode("ascii"))

    old = os.umask(0o077)
    try:
        with socketserver.UnixStreamServer(str(target), Handler) as server:
            os.chmod(target, 0o660)
            try:
                server.serve_forever()
            finally:
                target.unlink(missing_ok=True)
    finally:
        os.umask(old)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--manifest", required=True)
    options = parser.parse_args()
    serve(options.socket, options.manifest)
