#!/usr/bin/env python3
"""Offline, pinned-mutual-TLS encrypted Linux DP snapshot distribution (#48).

The wire bundle contains only certificate-wrapped Data Protection XML plus a
separately P-256-signed inventory checkpoint. No wrapping private key, TLS
private key, signer private key, cookie, token or restored live state is sent.
The recipient MUST use the existing independently anchored .NET restore CLI
against a separate trusted signer key and external monotonic floor.
"""
import argparse
import ctypes
import hashlib
import hmac
import http.client
import io
import os
from pathlib import Path
import re
import shutil
import ssl
import stat
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
import zipfile

MAX_BUNDLE = 32 * 1024 * 1024
MAX_XML = 1024 * 1024
MAX_MANIFEST = 16384
MAX_XML_FILES = 512
LABEL = re.compile(r"[a-z0-9][a-z0-9._-]{0,47}\Z", re.ASCII)
XML_NAME = re.compile(r"(?:key|revocation)-[a-zA-Z0-9_.-]{1,110}\.xml\Z", re.ASCII)
HEX_SHA = re.compile(r"[A-F0-9]{64}\Z", re.ASCII)
CONTENT_TYPE = "application/vnd.gatewaycore.linux-dp-ciphertext+zip"
PRIVATE_DIRECTORY = 0o700
PRIVATE_FILE = 0o600
O_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
O_FILE = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def valid_label(value):
    if type(value) is not str or not LABEL.fullmatch(value):
        raise ValueError("invalid snapshot identity")
    return value


def canonical_absolute(value):
    if type(value) is not str or not value.startswith("/") or \
            os.path.normpath(value) != value or os.path.realpath(value) != value:
        raise ValueError("noncanonical or symlinked local path")
    return value


def private_directory(path):
    canonical_absolute(path)
    fd = os.open(path, O_DIR)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or
                stat.S_IMODE(info.st_mode) & 0o077):
            raise ValueError("recovery directory is not owner-private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_file(name, directory_fd, cap):
    if not name or "/" in name or name in (".", ".."):
        raise ValueError("untrusted file identity")
    fd = os.open(name, O_FILE, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or
                before.st_uid != os.geteuid() or before.st_nlink != 1 or
                stat.S_IMODE(before.st_mode) & 0o077 or
                before.st_size < 1 or before.st_size > cap):
            raise ValueError("untrusted or unbounded recovery file")
        with os.fdopen(fd, "rb") as file:
            fd = -1
            data = file.read(cap + 1)
            after = os.fstat(file.fileno())
        if (len(data) != before.st_size or len(data) > cap or
                (before.st_ino, before.st_dev, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_size) !=
                (after.st_ino, after.st_dev, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_size)):
            raise ValueError("recovery file changed during authenticated read")
        return data
    finally:
        if fd != -1:
            os.close(fd)


def read_private_path(path, cap):
    canonical_absolute(path)
    base, name = os.path.split(path)
    directory_fd = private_directory(base)
    try:
        return private_file(name, directory_fd, cap)
    finally:
        os.close(directory_fd)


def read_snapshot(source_root, label, checkpoint):
    """Pin directory descriptors and read a quiesced new-only XML archive."""
    valid_label(label)
    root_fd = private_directory(source_root)
    try:
        fd = os.open(label, O_DIR, dir_fd=root_fd)
        try:
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise ValueError("snapshot directory is not owner-private")
            names = sorted(os.listdir(fd))
            if not 1 <= len(names) <= MAX_XML_FILES or \
                    len({n.lower() for n in names}) != len(names) or \
                    not all(XML_NAME.fullmatch(n) for n in names):
                raise ValueError("unexpected encrypted snapshot entries")
            payload = {}
            total = 0
            for name in names:
                item = private_file(name, fd, MAX_XML)
                total += len(item)
                if total > MAX_BUNDLE - MAX_MANIFEST - 8192:
                    raise ValueError("encrypted snapshot exceeds bounded relay budget")
                payload[name] = item
            if sorted(os.listdir(fd)) != names:
                raise ValueError("snapshot inventory changed during read")
        finally:
            os.close(fd)
    finally:
        os.close(root_fd)
    # Independently signed checkpoint is NOT taken from the restored state.
    # The recipient checks its P-256 signature and the external revision floor.
    checkpoint_bytes = read_private_path(checkpoint, MAX_MANIFEST)
    return payload, checkpoint_bytes


def build_bundle(source_root, label, checkpoint):
    files, signed_checkpoint = read_snapshot(source_root, label, checkpoint)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED,
                         allowZip64=False) as archive:
        for name, raw in [("checkpoint.json", signed_checkpoint)] + [
            ("ring/" + name, value) for name, value in sorted(files.items())
        ]:
            item = zipfile.ZipInfo(name)
            item.create_system = 3
            item.external_attr = (stat.S_IFREG | PRIVATE_FILE) << 16
            archive.writestr(item, raw)
            if output.tell() > MAX_BUNDLE:
                raise ValueError("encrypted snapshot wire bundle exceeds cap")
    result = output.getvalue()
    if not result or len(result) > MAX_BUNDLE:
        raise ValueError("unbounded encrypted DP transfer")
    return result


def verify_bundle(blob):
    if type(blob) is not bytes or not blob or len(blob) > MAX_BUNDLE:
        raise ValueError("invalid encrypted DP wire bundle size")
    entries = {}
    seen_names = set()
    total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(blob), "r", allowZip64=False) as zipdata:
            if zipdata.comment or not 2 <= len(zipdata.infolist()) <= MAX_XML_FILES + 1:
                raise ValueError("unbounded encrypted snapshot members")
            for info in zipdata.infolist():
                name = info.filename
                if (name != "checkpoint.json" and not
                        (name.startswith("ring/") and XML_NAME.fullmatch(name[5:]))):
                    raise ValueError("unexpected archive member path")
                if name.casefold() in seen_names or \
                        (info.external_attr >> 16) & 0o170000 != stat.S_IFREG:
                    raise ValueError("linked, aliased or duplicate archive member")
                seen_names.add(name.casefold())
                if info.compress_type != zipfile.ZIP_STORED or info.flag_bits & 1:
                    raise ValueError("compressed or encrypted wire member refused")
                limit = MAX_MANIFEST if name == "checkpoint.json" else MAX_XML
                if not 0 < info.file_size <= limit or info.compress_size != info.file_size:
                    raise ValueError("unbounded authenticated transfer member")
                total += info.file_size
                if total > MAX_BUNDLE:
                    raise ValueError("unbounded authenticated transfer total")
                raw = zipdata.read(info)
                if len(raw) != info.file_size:
                    raise ValueError("incomplete encrypted transfer member")
                entries[name] = raw
    except (zipfile.BadZipFile, EOFError, OSError, RuntimeError):
        raise ValueError("invalid encrypted transfer archive") from None
    if "checkpoint.json" not in entries or len(entries) < 2:
        raise ValueError("checkpoint or encrypted XML missing")
    return entries


def safe_write(path, data):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 os.O_NOFOLLOW | os.O_CLOEXEC, PRIVATE_FILE)
    try:
        with os.fdopen(fd, "wb") as out:
            fd = -1
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
    finally:
        if fd >= 0:
            os.close(fd)


def publish_no_replace(staging, final):
    """Linux renameat2 RENAME_NOREPLACE for a directory (no TOCTOU overwrite)."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise ValueError("atomic non-overwriting Linux directory publish unavailable")
    renameat2.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    renameat2.restype = ctypes.c_int
    if renameat2(-100, os.fsencode(staging), -100,
                 os.fsencode(final), 1) != 0:
        raise ValueError("encrypted transfer target already exists or cannot be published")


def stage_received(dest_root, label, blob):
    valid_label(label)
    entries = verify_bundle(blob)
    root_fd = private_directory(dest_root)
    try:
        final = os.path.join(dest_root, label)
        if os.path.lexists(final):
            raise ValueError("encrypted recovery label already exists")
        staging = tempfile.mkdtemp(prefix=".dp-recv-", dir=dest_root)
        try:
            os.chmod(staging, PRIVATE_DIRECTORY)
            ring = os.path.join(staging, "ring")
            os.mkdir(ring, PRIVATE_DIRECTORY)
            for name, raw in entries.items():
                path = os.path.join(staging, name)
                safe_write(path, raw)
            for directory in (ring, staging):
                fd = os.open(directory, O_DIR)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            publish_no_replace(staging, final)
            # The source directory no longer exists after an atomic publish.
            os.fsync(root_fd)
            return final
        finally:
            if os.path.lexists(staging):
                shutil.rmtree(staging)
    finally:
        os.close(root_fd)


def pin(value):
    if type(value) is not str or not HEX_SHA.fullmatch(value):
        raise ValueError("approved leaf certificate SHA-256 is required")
    return value


def private_tls_key(path):
    canonical_absolute(path)
    info = os.lstat(path)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or
            info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077):
        raise ValueError("TLS client/server key file must be owner-private")
    return path


def server_tls(ca, cert, key):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=canonical_absolute(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(certfile=canonical_absolute(cert),
                        keyfile=private_tls_key(key))
    return ctx


def client_tls(ca, cert, key):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=canonical_absolute(ca))
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=canonical_absolute(cert),
                        keyfile=private_tls_key(key))
    return ctx


class SnapshotServer(ThreadingHTTPServer):
    """Never perform a TLS handshake inside the single accept loop.

    A stalled unauthenticated socket can otherwise indefinitely block every
    legitimate backup client, even though mutual TLS is later required.
    Bound worker count and handshake wall time BEFORE HTTP parsing.
    """
    request_queue_size = 12
    allow_reuse_address = False
    daemon_threads = True
    max_handshakes = 8
    handshake_timeout_seconds = 4

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.handshake_slots = threading.BoundedSemaphore(self.max_handshakes)

    def process_request(self, request, client_address):
        if not self.handshake_slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            request.close()
            self.handshake_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        secured = None
        try:
            request.settimeout(self.handshake_timeout_seconds)
            secured = self.tls_context.wrap_socket(
                request, server_side=True, do_handshake_on_connect=False)
            # Only this bounded worker waits on pre-auth TLS. The accept
            # loop can continue to dispatch a second legitimate client.
            secured.do_handshake()
            secured.settimeout(12)
            super().process_request_thread(secured, client_address)
        except (OSError, ssl.SSLError, TimeoutError):
            if secured is not None:
                secured.close()
            else:
                request.close()
        finally:
            self.handshake_slots.release()


class SnapshotHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GatewayCoreOfflineDpTransfer/1"
    sys_version = ""

    def log_message(self, *_):
        pass  # Never log client identity, URL or headers in CI/customer logs.

    def do_GET(self):
        self.connection.settimeout(15)
        peer = self.connection.getpeercert(binary_form=True)
        actual = hashlib.sha256(peer or b"").hexdigest().upper()
        if not peer or not hmac.compare_digest(actual, self.server.client_pin):
            self.send_error(403, "forbidden")
            return
        if self.path != "/v1/linux-dp-snapshot/" + self.server.approved_label or \
                self.headers.get("Content-Length") is not None or \
                self.headers.get("Transfer-Encoding") is not None:
            self.send_error(404, "not found")
            return
        data = self.server.encrypted_bundle
        self.send_response(200)
        self.send_header("Content-Type", CONTENT_TYPE)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-SHA256", hashlib.sha256(data).hexdigest().upper())
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.send_error(405, "method not allowed")


def make_server(bind, port, bundle, label, approved_client, ca, cert, key,
                allow_nonloopback=False):
    if bind != "127.0.0.1" and not allow_nonloopback:
        raise ValueError("remote listener requires explicit nonloopback opt-in")
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("invalid pinned listener port")
    valid_label(label)
    approved_client = pin(approved_client)
    if type(bundle) is not bytes or not 0 < len(bundle) <= MAX_BUNDLE:
        raise ValueError("invalid encrypted transfer")
    srv = SnapshotServer((bind, port), SnapshotHandler)
    try:
        srv.approved_label = label
        srv.encrypted_bundle = bundle
        srv.client_pin = approved_client
        # Keep the listening socket PLAINTEXT internally. Every accepted
        # peer is wrapped + handshaken only inside a bounded worker thread,
        # before BaseHTTPRequestHandler sees any request bytes.
        srv.tls_context = server_tls(ca, cert, key)
        return srv
    except BaseException:
        srv.server_close()
        raise


def fetch_pinned(server_url, label, expected_server_pin, ca, cert, key):
    valid_label(label)
    expected_server_pin = pin(expected_server_pin)
    target = urlsplit(server_url)
    if (target.scheme != "https" or not target.hostname or
            target.username or target.password or target.path not in ("", "/") or
            target.query or target.fragment or target.port is None):
        raise ValueError("explicit HTTPS host and port required")
    conn = http.client.HTTPSConnection(target.hostname, target.port, timeout=20,
                                       context=client_tls(ca, cert, key))
    try:
        conn.connect()
        peer = conn.sock.getpeercert(binary_form=True) if conn.sock else None
        if not peer or not hmac.compare_digest(
                hashlib.sha256(peer).hexdigest().upper(), expected_server_pin):
            raise ValueError("remote DP server certificate pin mismatch")
        conn.request("GET", "/v1/linux-dp-snapshot/" + label,
                     headers={"Accept": CONTENT_TYPE, "Connection": "close"})
        response = conn.getresponse()
        headers = response.headers
        lengths = headers.get_all("Content-Length", [])
        hashes = headers.get_all("X-Content-SHA256", [])
        if (response.status != 200 or
                headers.get("Content-Type") != CONTENT_TYPE or
                headers.get_all("Transfer-Encoding") or
                len(lengths) != 1 or len(hashes) != 1 or
                not lengths[0].isascii() or not lengths[0].isdecimal() or
                not 0 < int(lengths[0]) <= MAX_BUNDLE or
                not HEX_SHA.fullmatch(hashes[0])):
            raise ValueError("invalid pinned DP transfer response")
        body = response.read(MAX_BUNDLE + 1)
        if (len(body) != int(lengths[0]) or
                not hmac.compare_digest(hashlib.sha256(body).hexdigest().upper(),
                                        hashes[0])):
            raise ValueError("truncated or changed encrypted DP transport")
        verify_bundle(body)
        return body
    finally:
        conn.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    host = commands.add_parser("serve")
    host.add_argument("--source-root", required=True)
    host.add_argument("--label", required=True)
    host.add_argument("--checkpoint", required=True)
    host.add_argument("--listen", default="127.0.0.1")
    host.add_argument("--port", type=int, required=True)
    host.add_argument("--allow-nonloopback", action="store_true")
    host.add_argument("--client-cert-sha256", required=True)
    receive = commands.add_parser("receive")
    receive.add_argument("--server-url", required=True)
    receive.add_argument("--server-cert-sha256", required=True)
    receive.add_argument("--destination-root", required=True)
    receive.add_argument("--label", required=True)
    for cli in (host, receive):
        cli.add_argument("--ca", required=True)
        cli.add_argument("--certificate", required=True)
        cli.add_argument("--private-key", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "serve":
            bundle = build_bundle(args.source_root, args.label, args.checkpoint)
            with make_server(args.listen, args.port, bundle, args.label,
                             args.client_cert_sha256, args.ca,
                             args.certificate, args.private_key,
                             allow_nonloopback=args.allow_nonloopback) as server:
                print("PASS: pinned-mTLS encrypted read-only DP relay ready",
                      flush=True)
                server.serve_forever(poll_interval=.25)
        else:
            bundle = fetch_pinned(args.server_url, args.label,
                                  args.server_cert_sha256, args.ca,
                                  args.certificate, args.private_key)
            dest = stage_received(args.destination_root, args.label, bundle)
            # The receiver DOES NOT trust this staged archive for activation.
            # Independent .NET P-256 signed inventory verification, external
            # floor, wrapping certificate and writer fencing are mandatory.
            print("PASS: pinned-mTLS ciphertext-only transfer staged; "
                  "restore remains OFFLINE and requires independent signed verification")
        return 0
    except (OSError, ValueError, ssl.SSLError, EOFError, RuntimeError,
            zipfile.BadZipFile, OverflowError):
        print("FAIL: authenticated Linux DP transfer refused", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
