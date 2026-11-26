"""Independent TLS bridge for signed WAF or DNS operator workflows.
The web request never supplies paths, endpoints, signing keys or shell arguments.
"""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socketserver
import ssl
import stat
import sys

import dashboard_broker as waf
import waf_fleet_rollout
import verify_signed_policy as signed
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "acceptance"))
import gslb_signed_rollout as dns

DIGEST = re.compile(r"[A-F0-9]{64}\Z")


def private_input(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("operator-owned private manifest required")
    return signed._json(signed._read_file(path))


def dns_plan(manifest):
    if set(manifest) != {"planFile", "journal"}:
        raise ValueError("exact DNS broker manifest required")
    plan = private_input(manifest["planFile"])
    if set(plan) != {"nodes", "beforeSerials"} or len(plan["nodes"]) != 2:
        raise ValueError("two-node signed plan required")
    for row in plan["nodes"]:
        private_input(row["prepareFile"])
    nodes = [dns.Node(row) for row in plan["nodes"]]
    before = plan["beforeSerials"]
    # Bind the exact in-memory signed envelopes used by the coordinator,
    # targets and baseline serials; never hash only an unsigned zone draft.
    bound = {"beforeSerials": before, "nodes": [
        {"origin": n.origin.geturl(), "pin": n.pin, "dnsIp": n.host,
         "dnsPort": n.port, "prepare": n.prepare} for n in nodes]}
    digest = hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest().upper()
    revision = nodes[0].prepare["sequence"]
    if type(revision) is not int or not 1 <= revision <= 9007199254740991:
        raise ValueError("invalid sequence")
    journal = Path(manifest["journal"])
    if not journal.is_absolute():
        raise ValueError("absolute private journal required")
    return nodes, before, journal, revision, digest


def dispatch_dns(raw, plan):
    try:
        request = signed._json(raw)
        nodes, before, journal, revision, digest = plan
        if (type(request) is not dict or set(request) != {"operation", "revision", "digest"} or
                request["operation"] not in ("preflight", "execute") or
                type(request["revision"]) is not int or request["revision"] != revision or
                request["digest"] != digest):
            return "refused-or-failed"
        dns.preflight(nodes, before)
        if request["operation"] == "preflight":
            return "preflight-only"
        with dns.Journal(journal) as receipt:
            dns.execute(nodes, before, receipt)
        return "applied-uncommitted"
    except Exception:
        return "refused-or-failed"


def pinned_peer(connection, pin):
    der = connection.getpeercert(binary_form=True)
    return bool(der) and hashlib.sha256(der).hexdigest().upper() == pin


def create_server(args, dispatch):
    ip = ipaddress.IPv4Address(args.bind)
    if not (ip.is_private or ip.is_loopback) or ip.is_unspecified or ip.is_multicast or ip.is_link_local:
        raise ValueError("explicit private IPv4 management bind required")
    if not 1025 <= args.port <= 65535 or not DIGEST.fullmatch(args.client_sha256):
        raise ValueError("invalid port or client pin")
    for path in (args.server_certificate, args.server_key, args.client_ca):
        if not Path(path).is_absolute():
            raise ValueError("absolute TLS references required")
    key = Path(args.server_key).lstat()
    if not stat.S_ISREG(key.st_mode) or key.st_uid != os.geteuid() or key.st_mode & 0o077:
        raise ValueError("private operator TLS key required")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(args.server_certificate, args.server_key)
    context.load_verify_locations(cafile=args.client_ca)

    class Server(socketserver.TCPServer):
        def get_request(self):
            connection, address = super().get_request()
            try:
                connection.settimeout(5)
                return context.wrap_socket(connection, server_side=True), address
            except (OSError, ssl.SSLError):
                connection.close()
                raise

    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            if not pinned_peer(self.connection, args.client_sha256):
                return
            raw = self.rfile.readline(1025)
            result = "refused-or-failed"
            if len(raw) <= 1024 and raw.endswith(b"\n"):
                result = dispatch(raw)
            self.wfile.write((result + "\n").encode("ascii"))

    # Serial handling prevents concurrent operator transactions through one broker.
    return Server((str(ip), args.port), Handler)


def serve(args, dispatch):
    with create_server(args, dispatch) as server:
        server.serve_forever()


def main():
    if not sys.platform.startswith("linux"):
        raise ValueError("independent Linux operator host required")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", choices=["waf", "gslb"], required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--bind")
    parser.add_argument("--port", type=int)
    parser.add_argument("--server-certificate")
    parser.add_argument("--server-key")
    parser.add_argument("--client-ca")
    parser.add_argument("--client-sha256")
    args = parser.parse_args()
    manifest = private_input(args.manifest)
    if args.module == "waf":
        if set(manifest) != {"argv"} or not isinstance(manifest["argv"], list) or not all(isinstance(a, str) for a in manifest["argv"]) or "--execute" in manifest["argv"]:
            raise ValueError("exact approved WAF arguments required")
        approved = waf_fleet_rollout.parse_args(manifest["argv"])
        if approved.execute:
            raise ValueError("manifest cannot enable execution")
        revision, digest = approved.confirm_revision, approved.confirm_policy_sha256
        dispatch = lambda raw: waf.dispatch_approved(raw, approved)
    else:
        plan = dns_plan(manifest)
        revision, digest = plan[3:]
        dispatch = lambda raw: dispatch_dns(raw, plan)
    if args.describe:
        print(json.dumps({"revision": revision, "digest": digest}))
        return
    if not all((args.bind, args.port, args.server_certificate, args.server_key, args.client_ca, args.client_sha256)):
        parser.error("TLS listener and certificate arguments required")
    serve(args, dispatch)


if __name__ == "__main__":
    main()
