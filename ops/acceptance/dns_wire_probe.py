#!/usr/bin/env python3
"""Disposable authoritative DNS UDP/TCP wire acceptance; no third-party packages.

Example: python3 ops/acceptance/dns_wire_probe.py --host 127.0.0.1 --port 5353 --zone example.test
Only target a DNS instance you own. Exit nonzero on any failed assertion.
"""
import argparse
import ipaddress
import secrets
import socket
import struct
import sys


def name_wire(name):
    parts = name.rstrip(".").encode("ascii").split(b".")
    if not parts or any(not part or len(part) > 63 for part in parts):
        raise ValueError("invalid DNS name")
    result = b"".join(bytes((len(part),)) + part for part in parts) + b"\0"
    if len(result) > 255:
        raise ValueError("DNS name too long")
    return result


def question(name, qtype, *, edns=False, advertised=1232, version=0, do=False):
    txid = secrets.randbelow(65536)
    header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, int(edns))
    q = name_wire(name) + struct.pack("!HH", qtype, 1)
    opt = (b"\0" + struct.pack("!HHIH", 41, advertised,
           (version << 16) | (0x8000 if do else 0), 0)) if edns else b""
    return txid, header + q + opt


def read_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise AssertionError("TCP DNS response ended early")
        data.extend(block)
    return bytes(data)


def exchange(host, port, payload, tcp, timeout):
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        if tcp:
            sock.sendall(struct.pack("!H", len(payload)) + payload)
            size = struct.unpack("!H", read_exact(sock, 2))[0]
            return read_exact(sock, size)
        sock.send(payload)
        return sock.recv(65535)


def skip_name(data, pos):
    """Bounds-check compressed names without following untrusted pointer chains."""
    length = 0
    while True:
        if pos >= len(data):
            raise AssertionError("truncated DNS name")
        size = data[pos]
        pos += 1
        if size & 0xC0 == 0xC0:
            if pos >= len(data):
                raise AssertionError("truncated compression pointer")
            return pos + 1
        if size & 0xC0:
            raise AssertionError("invalid label encoding")
        if size == 0:
            return pos
        length += size + 1
        if length > 255 or pos + size > len(data):
            raise AssertionError("invalid DNS name length")
        pos += size


def parse(response, txid):
    if len(response) < 12:
        raise AssertionError("short DNS header")
    rid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", response)
    assert rid == txid, "transaction ID mismatch"
    assert flags & 0x8000, "not a response"
    assert not (flags & 0x0080), "recursion unexpectedly available"
    pos = 12
    for _ in range(qd):
        pos = skip_name(response, pos)
        assert pos + 4 <= len(response), "truncated question"
        pos += 4
    rrsets = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            pos = skip_name(response, pos)
            assert pos + 10 <= len(response), "truncated RR header"
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", response, pos)
            pos += 10
            assert pos + rdlen <= len(response), "truncated RDATA"
            rrsets.append((section, rtype, rclass, ttl))
            pos += rdlen
    assert pos == len(response), "trailing DNS response bytes"
    return flags, rrsets


def check(host, port, zone, name, qtype, tcp, timeout, *, edns=False, version=0):
    txid, packet = question(name, qtype, edns=edns, version=version)
    response = exchange(host, port, packet, tcp, timeout)
    flags, records = parse(response, txid)
    return flags, records, len(response)


def run(args):
    zone = args.zone.rstrip(".").lower()
    name_wire(zone)
    # NS and SOA at the apex must be authoritative and must not recurse.
    for qtype, label in ((2, "NS"), (6, "SOA")):
        for tcp in (False, True):
            flags, records, size = check(args.host, args.port, zone, zone, qtype, tcp, args.timeout)
            assert flags & 0x0400, f"{label}: AA missing"
            assert (flags & 0xF) == 0, f"{label}: RCODE not NOERROR"
            assert any(section == "answer" and typ == qtype for section, typ, _, _ in records), (
                f"{label}: missing apex RRset")
            print(f"PASS {label} {'TCP' if tcp else 'UDP'} {size} bytes")
    unknown = "unconfigured-" + secrets.token_hex(6) + "." + zone
    for tcp in (False, True):
        flags, records, size = check(args.host, args.port, zone, unknown, 1, tcp, args.timeout)
        assert flags & 0x0400, "NXDOMAIN: AA missing"
        assert (flags & 0xF) == 3, "unknown owner must be NXDOMAIN"
        assert any(section == "authority" and typ == 6 for section, typ, _, _ in records), (
            "NXDOMAIN missing negative-caching SOA")
        print(f"PASS NXDOMAIN {'TCP' if tcp else 'UDP'} {size} bytes")
    flags, records, size = check(args.host, args.port, zone, zone, 1, False, args.timeout, edns=True)
    assert (flags & 0xF) == 0 and any(t == 41 for _, t, _, _ in records), (
        "EDNS0 response missing OPT or returned error")
    assert size <= 1232, "EDNS0 UDP response exceeded advertised 1232-byte limit"
    print(f"PASS EDNS0 UDP {size} bytes")
    flags, records, _ = check(args.host, args.port, zone, zone, 6, False, args.timeout,
                              edns=True, version=1)
    assert any(t == 41 and (ttl >> 24) == 16 for _, t, _, ttl in records), (
        "unsupported EDNS version did not report BADVERS extended RCODE")
    print("PASS EDNS BADVERS")
    print("PASS authoritative UDP/TCP interoperability; no physical/soak certification implied")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1", help="literal IPv4/IPv6 address")
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--zone", required=True, help="configured authoritative zone apex")
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    try:
        ipaddress.ip_address(args.host)
        if not 1 <= args.port <= 65535 or not 0 < args.timeout <= 30:
            raise ValueError("invalid port or timeout")
        run(args)
    except (AssertionError, OSError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
