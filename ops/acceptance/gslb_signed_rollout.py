"""Explicitly approved, two-node signed DNS rolling operator workflow.

No signing key, lease creation, automatic retry, or old-serial rollback.
Only use on independently authorized hosts; noncommercial mode is lab-only.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import struct
import sys
from urllib.parse import urlsplit

import dns_wire_probe as wire

DIGEST = re.compile(r"[A-F0-9]{64}\Z")
TX = re.compile(r"[A-Za-z0-9_-]{12,80}\Z")
BASE = "/agent/v1/engines/gslb/config/"


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result or key.casefold() in (k.casefold() for k in result):
            raise ValueError("duplicate or aliased JSON property")
        result[key] = value
    return result


def load(path):
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("absolute operator file required")
    with path.open("rb") as stream:
        raw = stream.read(262145)
    if len(raw) > 262144:
        raise ValueError("operator input too large")
    return json.loads(raw, object_pairs_hook=unique)


def serials(config):
    zones = config["Zones"]
    if not isinstance(zones, list) or not 1 <= len(zones) <= 64:
        raise ValueError("bounded authoritative zones required")
    result = {}
    for zone in zones:
        name = zone["Name"].rstrip(".").lower()
        wire.name_wire(name)
        serial = zone["SoaSerial"]
        if name in result or not zone.get("NameServers") or type(serial) is not int or not 0 < serial <= 0xffffffff:
            raise ValueError("each zone needs unique authoritative name and serial")
        result[name] = serial
    return result


def soa_serial(response, txid, name):
    flags, records = wire.parse(response, txid, name, 6)
    wire.require(flags & 0x0400 and not flags & 0x0200 and flags & 15 == 0,
                 "authoritative complete NOERROR SOA required")
    wire.require(wire.has_rr(records, "answer", name, 6), "apex SOA missing")
    _, _, _, answers, _, _ = struct.unpack_from("!HHHHHH", response)
    _, pos = wire.read_name(response, 12)
    pos += 4
    serial_values = []
    for _ in range(answers):
        owner, pos = wire.read_name(response, pos)
        kind, klass, _, size = struct.unpack_from("!HHIH", response, pos)
        pos += 10
        end = pos + size
        if kind == 6 and klass == 1 and owner == wire.labels_for(name):
            _, cursor = wire.read_name(response, pos)
            _, cursor = wire.read_name(response, cursor)
            wire.require(cursor + 20 == end, "invalid SOA RDATA")
            serial_values.append(struct.unpack_from("!I", response, cursor)[0])
        pos = end
    wire.require(len(serial_values) == 1, "exactly one apex SOA required")
    return serial_values[0]


class Node:
    def __init__(self, row):
        self.origin = urlsplit(row["origin"])
        self.pin = row["serverSha256"]
        self.host = str(ipaddress.ip_address(row["dnsIp"]))
        self.port = row["dnsPort"]
        if (self.origin.scheme != "https" or not self.origin.hostname or
                self.origin.username or self.origin.password or self.origin.path not in ("", "/") or
                self.origin.query or self.origin.fragment or not DIGEST.fullmatch(self.pin) or
                type(self.port) is not int or not 1 <= self.port <= 65535):
            raise ValueError("invalid pinned agent or DNS endpoint")
        if not all(Path(row[key]).is_absolute() for key in ("ca", "certificate", "privateKey")):
            raise ValueError("absolute operator credential references required")
        self.context = ssl.create_default_context(cafile=row["ca"])
        self.context.load_cert_chain(row["certificate"], row["privateKey"])
        self.prepare = load(row["prepareFile"])
        p = self.prepare
        if (set(p) != {"transactionId","expectedRevision","config","expiresUnixSeconds","sequence","keyId","signature"} or
                not TX.fullmatch(p["transactionId"]) or not DIGEST.fullmatch(p["expectedRevision"]) or
                type(p["sequence"]) is not int or p["sequence"] < 1):
            raise ValueError("invalid signed prepare envelope")
        self.after = serials(p["config"])

    def request(self, action, body=None):
        connection = http.client.HTTPSConnection(self.origin.hostname, self.origin.port or 443,
                                                   context=self.context, timeout=75 if action == "restart" else 10)
        try:
            connection.connect()
            actual = hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest().upper()
            if actual != self.pin:
                raise ValueError("agent TLS leaf pin mismatch")
            connection.request("GET" if body is None else "POST", BASE + action,
                body=None if body is None else json.dumps(body, separators=(",", ":")).encode(),
                headers={"Content-Type":"application/json","Accept":"application/json"})
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise ValueError("agent operation not confirmed")
            return json.loads(raw, object_pairs_hook=unique)
        finally:
            connection.close()

    def verify(self, digest, expected):
        state = self.request("revision")
        if (state.get("restartEnabled") is not True or state.get("fileRevision") != digest or
                state.get("loadedRevision") != digest):
            raise ValueError("agent file/runtime revision mismatch")
        for name, serial in expected.items():
            for tcp in (False, True):
                txid, packet = wire.question(name, 6)
                # Nonrecursive query; no UDP-to-TCP fallback can count as UDP proof.
                packet = packet[:2] + b"\0\0" + packet[4:]
                response = wire.exchange(self.host, self.port, packet, tcp, 3)
                if soa_serial(response, txid, name) != serial:
                    raise ValueError("authoritative SOA serial mismatch")


class Journal:
    def __init__(self, path):
        path = Path(path)
        if not path.is_absolute() or path.parent.is_symlink():
            raise ValueError("absolute private journal path required")
        if os.name == "posix" and path.parent.stat().st_mode & 0o077:
            raise ValueError("journal parent must be private")
        self.fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        os.close(self.fd)

    def record(self, phase, index=None):
        raw = (json.dumps({"phase":phase,"node":index},separators=(",",":"))+"\n").encode()
        with os.fdopen(os.dup(self.fd),"ab") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())


def preflight(nodes, before):
    if len(nodes) != 2:
        raise ValueError("two independent authorities required")
    a,b = nodes
    if (a.pin == b.pin or (a.origin.hostname, a.origin.port or 443) == (b.origin.hostname,b.origin.port or 443) or
        (a.host,a.port) == (b.host,b.port) or a.prepare["transactionId"] != b.prepare["transactionId"] or
        a.prepare["sequence"] != b.prepare["sequence"] or a.after != b.after or set(before) != set(a.after)):
        raise ValueError("independent nodes and one identical signed serial transition required")
    for name, old in before.items():
        new = a.after[name]
        if type(old) is not int or not 0 < old <= 0xffffffff or not 0 < (new-old) % (2**32) < 2**31:
            raise ValueError("every authoritative serial must advance")
    for node in nodes:
        node.verify(node.prepare["expectedRevision"], before)


def execute(nodes, before, journal):
    tx = nodes[0].prepare["transactionId"]
    prepared = []
    journal.record("intent")
    try:
        for i,node in enumerate(nodes):
            journal.record("prepare-attempt", i)
            result = node.request("prepare", node.prepare)
            digest = result.get("preparedRevision")
            if (result.get("state") != "prepared" or result.get("transactionId") != tx or
                result.get("originalRevision") != node.prepare["expectedRevision"] or
                not isinstance(digest,str) or not DIGEST.fullmatch(digest)):
                raise ValueError("prepare not confirmed")
            prepared.append(digest)
            journal.record("prepared",i)
        for i,node in enumerate(nodes):
            other = 1-i
            nodes[other].verify(prepared[other] if i else nodes[other].prepare["expectedRevision"],
                                nodes[other].after if i else before)
            node.verify(node.prepare["expectedRevision"],before)
            request = {"transactionId":tx,"preparedRevision":prepared[i]}
            journal.record("activate-attempt",i)
            result = node.request("activate",request)
            if result.get("state") != "activated-file-only" or result.get("revision") != prepared[i]:
                raise ValueError("activation not confirmed")
            journal.record("restart-attempt-no-replay",i)
            result = node.request("restart",request)
            if result.get("state") != "restarted-revision-confirmed" or result.get("revision") != prepared[i]:
                raise ValueError("restart not confirmed")
            node.verify(prepared[i],node.after)
            journal.record("runtime-and-dns-verified",i)
        for i,node in enumerate(nodes):
            node.verify(prepared[i],node.after)
        journal.record("both-verified-independent-authority-commit-required")
    except Exception:
        journal.record("unconfirmed-stop-and-reconcile")
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--journal")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        manifest = load(args.manifest)
        if set(manifest) != {"nodes","beforeSerials"} or len(manifest["nodes"]) != 2:
            raise ValueError("exact two-node manifest required")
        nodes = [Node(row) for row in manifest["nodes"]]
        before = manifest["beforeSerials"]
        preflight(nodes,before)
        if not args.execute:
            print("PASS: read-only preflight")
        else:
            if not args.journal:
                raise ValueError("execution requires a new private journal")
            with Journal(args.journal) as journal:
                execute(nodes,before,journal)
            print("PASS: both runtime revisions and authoritative SOA verified; independent authority commit required")
        return 0
    except Exception:
        print("FAIL: rollout refused or unconfirmed; inspect private journal before any retry",file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
