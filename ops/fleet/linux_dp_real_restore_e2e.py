#!/usr/bin/env python3
"""Disposable real pinned mTLS encrypted Linux DP snapshot + signed .NET restore.

Called by the existing LinuxKeyProtectionTests after they create a genuine
certificate-wrapped Data Protection ring and independent P-256 checkpoint.
All TLS keys are generated only inside this isolated one-off acceptance run.
No automatic production key transfer, release or service promotion.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace

import linux_dp_quiescence as quiescence
import linux_dp_mtls_transport as transport
import linux_dp_receive_restore as receiver

STAGE = "startup"


def openssl(*args):
    proc = subprocess.run(["openssl", *args], stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                          timeout=30, check=False)
    if proc.returncode:
        raise ValueError("disposable TLS identity generation failed")


def identities(root):
    ca, private = root / "root.pem", root / "root.key"
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
            "-days", "1", "-subj", "/CN=GatewayCore Disposable Recovery CA",
            "-keyout", str(private), "-out", str(ca))
    private.chmod(0o600)
    out = {}
    for label, eku in (("sender", "serverAuth"), ("receiver", "clientAuth")):
        cert = root / (label + ".pem")
        secret = root / (label + ".key")
        request = root / (label + ".csr")
        extensions = root / (label + ".ext")
        extensions.write_text(
            "extendedKeyUsage=" + eku + "\n" +
            ("subjectAltName=IP:127.0.0.1\n" if eku == "serverAuth" else "") +
            "keyUsage=digitalSignature,keyEncipherment\n",
            encoding="ascii")
        openssl("req", "-new", "-nodes", "-newkey", "rsa:2048",
                "-subj", "/CN=" + label,
                "-keyout", str(secret), "-out", str(request))
        openssl("x509", "-req", "-in", str(request), "-CA", str(ca),
                "-CAkey", str(private), "-CAcreateserial", "-out", str(cert),
                "-days", "1", "-sha256", "-extfile", str(extensions))
        secret.chmod(0o600)
        der = subprocess.run(
            ["openssl", "x509", "-in", str(cert), "-outform", "DER"],
            stdin=subprocess.DEVNULL, capture_output=True,
            timeout=10, check=True).stdout
        out[label] = (str(cert), str(secret),
                      hashlib.sha256(der).hexdigest().upper())
    return str(ca), out


class DisposableEpochFence:
    """Test-only quorum phase oracle: never a real Raft/host acceptance."""

    sender, receiver = "gateway-a", "gateway-b"
    _identity = (999, 90, 456, "a" * 32)
    client = SimpleNamespace(fleet="fleet-disposable")

    def __init__(self, checkpoint):
        raw = Path(checkpoint).read_bytes()
        doc = json.loads(raw)
        self.revision = doc["Revision"]
        self.checkpoint_sha = hashlib.sha256(raw).hexdigest().upper()
        self.deadline = time.monotonic() + 110
        self.phases = []

    def remaining_seconds(self):
        return max(0.0, self.deadline - time.monotonic())

    def current(self, phase):
        self.phases.append(phase)
        return self.remaining_seconds() > 10


def disposable_systemctl(command, **kwargs):
    """Synthetic systemd only; separate CI job checks the real manager."""
    if command[0] != quiescence.SYSTEMCTL:
        return subprocess.run(command, **kwargs)
    if "show" in command:
        return SimpleNamespace(returncode=0, stdout=(
            "LoadState=masked\nActiveState=inactive\nSubState=dead\n"
            "MainPID=0\nUnitFileState=masked-runtime\n"
            "KillMode=control-group\n").encode("ascii"))
    return SimpleNamespace(returncode=0, stdout=b"")


def disposable_node_witnesses(root, fence):
    receipts = {}
    units = ("gatewaycore.service",)
    for node in (fence.sender, fence.receiver):
        signing = root / (node + ".signing.pem")
        public = root / (node + ".trust.pub")
        receipt = root / (node + ".quiescence")
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout",
                "-out", str(signing))
        openssl("pkey", "-in", str(signing), "-pubout", "-out", str(public))
        signing.chmod(0o600)
        public.chmod(0o600)
        payload = quiescence.issue(
            fence, node, units, str(signing), runner=disposable_systemctl)
        receipt.write_bytes(payload)
        receipt.chmod(0o600)
        receipts[node] = (str(receipt), str(public))
    return receipts


def integration(args):
    global STAGE
    STAGE = "linux-check"
    if not sys.platform.startswith("linux"):
        raise ValueError("Linux is required for real Data Protection crypto acceptance")
    # Same actual independent P-256 checkpoint and protected RSA-wrapped
    # XML that have already passed their own .NET acceptance in the parent.
    STAGE = "private-xml-archive"
    payload = transport.build_bundle(args.source_root, args.label, args.checkpoint)
    with tempfile.TemporaryDirectory(prefix="dp-real-mtls-net10-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        STAGE = "disposable-openssl-identities"
        ca, identities_map = identities(root)
        server_cert, server_key, server_pin = identities_map["sender"]
        client_cert, client_key, client_pin = identities_map["receiver"]
        STAGE = "independent-p256-node-cryptographic-fixtures"
        fence = DisposableEpochFence(args.checkpoint)
        witnesses = disposable_node_witnesses(root, fence)
        # The synthetic service manager above never claims actual two-host
        # admission. Only the P-256 signature, epoch, and composed .NET
        # restoration path are real in this disposable integration.
        STAGE = "pinned-mtls-server-start"
        with transport.make_server(
            "127.0.0.1", 0, payload, args.label, client_pin,
            ca, server_cert, server_key) as server:
            worker = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .02},
                                      daemon=True)
            worker.start()
            try:
                STAGE = "trusted-dotnet-bundle-inspection"
                request = argparse.Namespace(
                    approved_offline=True,
                    server_url="https://127.0.0.1:" + str(server.server_port),
                    label=args.label,
                    server_cert_sha256=server_pin,
                    destination_root=args.inbox,
                    state_root=args.state_root,
                    ca=ca, certificate=client_cert, private_key=client_key,
                    restore_bundle=args.restore_bundle,
                    restore_bundle_sha256=receiver.tree_hash(args.restore_bundle),
                    dotnet_runtime_root=args.dotnet_runtime_root,
                    trusted_public_key=args.trusted_public_key,
                    minimum_revision_file=args.minimum_revision_file,
                    sender_quiescence_receipt=witnesses[fence.sender][0],
                    receiver_quiescence_receipt=witnesses[fence.receiver][0],
                    sender_quiescence_public_key=witnesses[fence.sender][1],
                    receiver_quiescence_public_key=witnesses[fence.receiver][1],
                    sender_writer_units=["gatewaycore.service"],
                    receiver_writer_units=["gatewaycore.service"])
                STAGE = "mutual-tls-receive-and-signed-dotnet-restore"
                fence.phases.clear()
                returned = receiver.restore_once(request, fence=fence)
                if (fence.phases[:4] != [
                        "preflight", "before-transfer", "after-transfer",
                        "after-transfer"] or
                        fence.phases.count("before-signed-restore") < 2 or
                        fence.phases[-2:] != [
                            "after-signed-restore", "after-signed-restore"] or
                        any(phase not in (
                            "preflight", "before-transfer", "after-transfer",
                            "before-signed-restore", "after-signed-restore")
                            for phase in fence.phases)):
                    raise ValueError("live quorum checks missing during real .NET recovery")
                # Both receipt signatures were actually checked at every
                # quorum boundary, not only once before starting the socket.
                STAGE = "restored-archive-identity"
                if returned != os.path.join(args.inbox, args.label):
                    raise ValueError("signed recovery staged under wrong identity")
                # Re-sending to the same label must not overwrite the archive
                # or a live/restored Data Protection ring. This is a genuine
                # TLS fetch, not an in-memory fake.
                STAGE = "reject-duplicate"
                try:
                    receiver.restore_once(request, fence=fence)
                except ValueError:
                    pass
                else:
                    raise ValueError("duplicate pinned restore was replayed")
            finally:
                server.shutdown()
                worker.join(5)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "label", "checkpoint", "trusted-public-key",
                 "minimum-revision-file", "state-root", "inbox",
                 "restore-bundle", "dotnet-runtime-root"):
        p.add_argument("--" + name, required=True)
    args = p.parse_args(argv)
    try:
        integration(args)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # Do not leak even synthetic TLS keys, auth cookies, origin host,
        # local source paths or private exception text into public CI.
        # Fixed source-authored stages only; never echo exception text or
        # trust paths. Keep diagnostic stable in customer-safe CI logs.
        stage = STAGE
        if stage == "mutual-tls-receive-and-signed-dotnet-restore":
            stage = "receiver-" + receiver.STAGE
        print("FAIL: real pinned mTLS to .NET signed DP restore at " + stage,
              file=sys.stderr)
        return 1
    print("PASS: actual pinned mTLS + independent P-256 node signatures + "
          "bounded quorum-phase oracle + signed .NET restore; duplicate refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
