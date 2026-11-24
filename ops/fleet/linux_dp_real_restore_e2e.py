#!/usr/bin/env python3
"""Disposable real pinned mTLS encrypted Linux DP snapshot + signed .NET restore.

Called by the existing LinuxKeyProtectionTests after they create a genuine
certificate-wrapped Data Protection ring and independent P-256 checkpoint.
All TLS keys are generated only inside this isolated one-off acceptance run.
No automatic production key transfer, release or service promotion.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

import linux_dp_mtls_transport as transport
import linux_dp_receive_restore as receiver


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


def integration(args):
    if not sys.platform.startswith("linux"):
        raise ValueError("Linux is required for real Data Protection crypto acceptance")
    # Same actual independent P-256 checkpoint and protected RSA-wrapped
    # XML that have already passed their own .NET acceptance in the parent.
    payload = transport.build_bundle(args.source_root, args.label, args.checkpoint)
    with tempfile.TemporaryDirectory(prefix="dp-real-mtls-net10-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        ca, identities_map = identities(root)
        server_cert, server_key, server_pin = identities_map["sender"]
        client_cert, client_key, client_pin = identities_map["receiver"]
        with transport.make_server(
            "127.0.0.1", 0, payload, args.label, client_pin,
            ca, server_cert, server_key) as server:
            worker = threading.Thread(target=server.serve_forever,
                                      kwargs={"poll_interval": .02},
                                      daemon=True)
            worker.start()
            try:
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
                    trusted_public_key=args.trusted_public_key,
                    minimum_revision_file=args.minimum_revision_file)
                returned = receiver.restore_once(request)
                if returned != os.path.join(args.inbox, args.label):
                    raise ValueError("signed recovery staged under wrong identity")
                # Re-sending to the same label must not overwrite the archive
                # or a live/restored Data Protection ring. This is a genuine
                # TLS fetch, not an in-memory fake.
                try:
                    receiver.restore_once(request)
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
                 "restore-bundle"):
        p.add_argument("--" + name, required=True)
    args = p.parse_args(argv)
    try:
        integration(args)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        # Do not leak even synthetic TLS keys, auth cookies, origin host,
        # local source paths or private exception text into public CI.
        print("FAIL: real pinned mTLS to .NET signed DP restore acceptance",
              file=sys.stderr)
        return 1
    print("PASS: actual pinned mTLS plus signed .NET restore, duplicate refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
