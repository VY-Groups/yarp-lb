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


def read_name(data, pos):
    """Decode one bounded DNS name and reject invalid compression pointers."""
    labels = []
    expanded_length = 1
    cursor = pos
    resume = None
    visited_targets = set()
    while True:
        if cursor >= len(data):
            raise AssertionError("truncated DNS name")
        size = data[cursor]
        if size & 0xC0 == 0xC0:
            if cursor + 1 >= len(data):
                raise AssertionError("truncated compression pointer")
            target = ((size & 0x3F) << 8) | data[cursor + 1]
            if target >= len(data):
                raise AssertionError("compression pointer outside DNS packet")
            if target in visited_targets:
                raise AssertionError("compression pointer cycle")
            visited_targets.add(target)
            if resume is None:
                resume = cursor + 2
            cursor = target
            continue
        if size & 0xC0:
            raise AssertionError("invalid label encoding")
        cursor += 1
        if size == 0:
            return tuple(labels), resume if resume is not None else cursor
        expanded_length += size + 1
        if expanded_length > 255 or cursor + size > len(data):
            raise AssertionError("invalid DNS name length")
        labels.append(data[cursor:cursor + size].lower())
        cursor += size


def parse(response, txid, expected_name, expected_qtype):
    if len(response) < 12:
        raise AssertionError("short DNS header")
    rid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", response)
    assert rid == txid, "transaction ID mismatch"
    assert flags & 0x8000, "not a response"
    assert not (flags & 0x0080), "recursion unexpectedly available"
    assert qd == 1, "response must echo exactly one question"
    pos = 12
    question_name, pos = read_name(response, pos)
    assert question_name == tuple(label.lower() for label in
                                  expected_name.rstrip(".").encode("ascii").split(b".")), (
        "question name mismatch")
    assert pos + 4 <= len(response), "truncated question"
    question_type, question_class = struct.unpack_from("!HH", response, pos)
    assert question_type == expected_qtype and question_class == 1, "question type/class mismatch"
    pos += 4
    rrsets = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            _, pos = read_name(response, pos)
            assert pos + 10 <= len(response), "truncated RR header"
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", response, pos)
            pos += 10
            assert pos + rdlen <= len(response), "truncated RDATA"
            rrsets.append((section, rtype, rclass, ttl))
            pos += rdlen
    assert pos == len(response), "trailing DNS response bytes"
    return flags, rrsets


def validate_parser_guards():
    txid = 0x1234
    header = struct.pack("!HHHHHH", txid, 0x8000, 1, 0, 0, 0)
    valid_question = name_wire("example.test") + struct.pack("!HH", 1, 1)

    def rejected(question_bytes, expected_name="example.test", expected_qtype=1):
        try:
            parse(header + question_bytes, txid, expected_name, expected_qtype)
        except AssertionError:
            return True
        return False

    outside_pointer = b"\xff\xff" + struct.pack("!HH", 1, 1)
    cyclic_pointer = b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    mismatched_name = name_wire("other.test") + struct.pack("!HH", 1, 1)
    mismatched_type = name_wire("example.test") + struct.pack("!HH", 28, 1)
    assert parse(header + valid_question, txid, "EXAMPLE.TEST.", 1)[0] == 0x8000
    assert rejected(outside_pointer), "out-of-packet compression pointer was accepted"
    assert rejected(cyclic_pointer), "cyclic compression pointer was accepted"
    assert rejected(mismatched_name), "mismatched response question name was accepted"
    assert rejected(mismatched_type), "mismatched response question type was accepted"
    print("PASS DNS parser rejects invalid compression and mismatched questions")


def check(host, port, zone, name, qtype, tcp, timeout, *, edns=False, version=0):
    txid, packet = question(name, qtype, edns=edns, version=version)
    response = exchange(host, port, packet, tcp, timeout)
    flags, records = parse(response, txid, name, qtype)
    return flags, records, len(response)


def run(args):
    zone = args.zone.rstrip(".").lower()
    name_wire(zone)
    validate_parser_guards()
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
    # RFC 6891: the OPT TTL high byte is the upper eight bits of the
    # twelve-bit RCODE. BADVERS=16 uses extended code 1 and header RCODE 0.
    assert any(t == 41 and (((ttl >> 24) << 4) | (flags & 0xF)) == 16
               for _, t, _, ttl in records), (
        "unsupported EDNS version did not report BADVERS RCODE 16")
    print("PASS EDNS BADVERS")
    # An existing apex with an unsupported RR type is NODATA, not NXDOMAIN.
    for tcp in (False, True):
        flags, records, _ = check(args.host, args.port, zone, zone, 15, tcp, args.timeout)
        assert (flags & 0x0400) and (flags & 0xF) == 0, "apex MX NODATA returned incorrect flags"
        assert not any(section == "answer" and typ == 15 for section, typ, _, _ in records), (
            "unexpected apex MX RRset")
        assert any(section == "authority" and typ == 6 for section, typ, _, _ in records), (
            "NODATA missing negative-caching SOA")
        print(f"PASS NODATA {'TCP' if tcp else 'UDP'}")
    # The listener is authoritative for configured zones only.
    outside = "not-served.invalid"
    for tcp in (False, True):
        flags, _, _ = check(args.host, args.port, zone, outside, 1, tcp, args.timeout)
        assert (flags & 0xF) == 5 and not (flags & 0x0080), "outside zone did not refuse recursion"
        print(f"PASS REFUSED {'TCP' if tcp else 'UDP'}")
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
