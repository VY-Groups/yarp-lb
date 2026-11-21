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
    if name == ".":
        return b"\0"
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
    # DNS over TCP has a 16-bit length prefix (RFC 1035). Reject an
    # unframeable request before opening a socket or contacting a listener.
    # UDP cannot carry more than the maximum IP datagram payload either.
    require(0 < len(payload) <= 65535, "DNS query exceeds wire message limit")
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
            if target >= cursor:
                raise AssertionError("compression pointer does not reference prior data")
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


def require(condition, message):
    """Keep acceptance checks active even when Python optimization is enabled."""
    if not condition:
        raise AssertionError(message)


def labels_for(name):
    if name == ".":
        return ()
    name_wire(name)  # Validate the input before canonicalizing it.
    return tuple(label.lower() for label in name.rstrip(".").encode("ascii").split(b"."))


def parse(response, txid, expected_name, expected_qtype, *, allow_truncated=False):
    if len(response) < 12:
        raise AssertionError("short DNS header")
    rid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", response)
    require(rid == txid, "transaction ID mismatch")
    require(flags & 0x8000, "not a response")
    require(not (flags & 0x7800), "response opcode must be QUERY")
    require(not (flags & 0x0040), "reserved DNS Z bit set")
    require(not (flags & 0x0080), "recursion unexpectedly available")
    require(qd == 1, "response must echo exactly one question")
    pos = 12
    question_name, pos = read_name(response, pos)
    require(question_name == labels_for(expected_name), "question name mismatch")
    require(pos + 4 <= len(response), "truncated question")
    question_type, question_class = struct.unpack_from("!HH", response, pos)
    require(question_type == expected_qtype and question_class == 1,
            "question type/class mismatch")
    pos += 4
    if flags & 0x0200 and allow_truncated:
        # A UDP TC=1 response may end in the middle of an RR. Its header and
        # echoed question are validated, but its RR sections are not evidence.
        return flags, []
    rrsets = []
    for section, count in (("answer", an), ("authority", ns), ("additional", ar)):
        for _ in range(count):
            owner, pos = read_name(response, pos)
            require(pos + 10 <= len(response), "truncated RR header")
            rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", response, pos)
            pos += 10
            require(pos + rdlen <= len(response), "truncated RDATA")
            if rtype == 41:
                # EDNS option RDATA is a sequence of bounded CODE/LENGTH/DATA
                # tuples. An RR-level RDLENGTH check alone cannot detect a
                # truncated option header or an overclaimed option payload.
                option_pos = pos
                option_end = pos + rdlen
                while option_pos < option_end:
                    require(option_pos + 4 <= option_end,
                            "truncated EDNS option header")
                    _, option_length = struct.unpack_from("!HH", response, option_pos)
                    option_pos += 4
                    require(option_pos + option_length <= option_end,
                            "EDNS option overruns OPT RDATA")
                    option_pos += option_length
            rrsets.append((section, owner, rtype, rclass, ttl))
            pos += rdlen
    require(pos == len(response), "trailing DNS response bytes")
    return flags, rrsets


def has_rr(records, section, owner, rtype):
    expected_owner = labels_for(owner)
    return any(record_section == section and record_owner == expected_owner and
               record_type == rtype and record_class == 1
               for record_section, record_owner, record_type, record_class, _ in records)


def validate_edns0_response(records):
    """Validate the response OPT envelope, not just its presence.

    RFC 6891 reserves the OPT TTL low 16 bits for EDNS flags; only DO is
    defined. An ordinary EDNS0 query without DO must not receive unexpected
    flags or a nonzero EDNS version.
    """
    opts = [(section, owner, rclass, ttl) for section, owner, rtype, rclass, ttl in records
            if rtype == 41]
    require(len(opts) == 1, "EDNS0 response must contain exactly one OPT RR")
    section, owner, payload_size, ttl = opts[0]
    require(section == "additional", "EDNS0 OPT must be in additional section")
    require(owner == (), "EDNS0 OPT owner must be the root")
    require(payload_size >= 512, "EDNS0 response advertised invalid UDP size")
    require(((ttl >> 16) & 0xFF) == 0, "EDNS0 response version must be zero")
    require((ttl & 0xFFFF) == 0, "EDNS0 response contains unexpected flags")
    require((ttl >> 24) == 0, "EDNS0 response has unexpected extended RCODE")


def validate_badvers_response(flags, records):
    """Validate the full EDNS BADVERS response, including its OPT envelope.

    BADVERS is the extended RCODE 16, encoded as OPT extended RCODE 1
    and legacy header RCODE 0. Version and reserved flags must be zero.
    """
    opts = [(section, owner, rclass, ttl) for section, owner, rtype, rclass, ttl in records
            if rtype == 41]
    require(len(opts) == 1, "BADVERS response must contain exactly one OPT RR")
    section, owner, payload_size, ttl = opts[0]
    require(section == "additional", "BADVERS OPT must be in additional section")
    require(owner == (), "BADVERS OPT owner must be root")
    require(payload_size >= 512, "BADVERS advertised invalid UDP size")
    require(((ttl >> 16) & 0xFF) == 0, "BADVERS response EDNS version must be zero")
    require((ttl & 0xFFFF) == 0, "BADVERS response contains unexpected flags")
    require((flags & 0xF) == 0 and (ttl >> 24) == 1,
            "unsupported EDNS version did not report BADVERS RCODE 16")


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
    forward_pointer = b"\xc0\x0e" + struct.pack("!HH", 1, 1) + b"\0"
    mismatched_name = name_wire("other.test") + struct.pack("!HH", 1, 1)
    mismatched_type = name_wire("example.test") + struct.pack("!HH", 28, 1)
    require(parse(header + valid_question, txid, "EXAMPLE.TEST.", 1)[0] == 0x8000,
            "valid response question was rejected")
    require(rejected(outside_pointer), "out-of-packet compression pointer was accepted")
    require(rejected(cyclic_pointer), "cyclic compression pointer was accepted")
    require(rejected(forward_pointer), "forward compression pointer was accepted")
    require(rejected(mismatched_name), "mismatched response question name was accepted")
    require(rejected(mismatched_type), "mismatched response question type was accepted")
    malformed_opcode = struct.pack("!HHHHHH", txid, 0x8800, 1, 0, 0, 0)
    malformed_z = struct.pack("!HHHHHH", txid, 0x8040, 1, 0, 0, 0)
    for malformed in (malformed_opcode, malformed_z):
        try:
            parse(malformed + valid_question, txid, "example.test", 1)
        except AssertionError:
            continue
        raise AssertionError("invalid response header flags were accepted")
    wrong_owner = [("answer", labels_for("other.test"), 2, 1, 60)]
    require(not has_rr(wrong_owner, "answer", "example.test", 2),
            "unrelated answer owner was accepted as the apex RRset")
    print("PASS DNS parser rejects invalid compression and mismatched questions")


def check(host, port, zone, name, qtype, tcp, timeout, *, edns=False, version=0):
    txid, packet = question(name, qtype, edns=edns, version=version)
    response = exchange(host, port, packet, tcp, timeout)
    if not tcp:
        require(len(response) <= (1232 if edns else 512),
                "UDP response exceeded advertised payload limit")
    flags, records = parse(response, txid, name, qtype, allow_truncated=not tcp)
    if flags & 0x0200:
        # RFC 1035: truncated UDP replies are not complete evidence. Reissue
        # the same question over TCP and verify its independently framed reply.
        require(not tcp, "TCP response unexpectedly truncated")
        response = exchange(host, port, packet, True, timeout)
        flags, records = parse(response, txid, name, qtype)
        require(not (flags & 0x0200), "TCP fallback response remains truncated")
    return flags, records, len(response)


def run(args):
    zone = args.zone.rstrip(".").lower()
    name_wire(zone)
    validate_parser_guards()
    # NS and SOA at the apex must be authoritative and must not recurse.
    for qtype, label in ((2, "NS"), (6, "SOA")):
        for tcp in (False, True):
            flags, records, size = check(args.host, args.port, zone, zone, qtype, tcp, args.timeout)
            require(flags & 0x0400, f"{label}: AA missing")
            require((flags & 0xF) == 0, f"{label}: RCODE not NOERROR")
            require(has_rr(records, "answer", zone, qtype),
                    f"{label}: missing apex RRset")
            print(f"PASS {label} {'TCP' if tcp else 'UDP'} {size} bytes")
    unknown = "unconfigured-" + secrets.token_hex(6) + "." + zone
    for tcp in (False, True):
        flags, records, size = check(args.host, args.port, zone, unknown, 1, tcp, args.timeout)
        require(flags & 0x0400, "NXDOMAIN: AA missing")
        require((flags & 0xF) == 3, "unknown owner must be NXDOMAIN")
        require(has_rr(records, "authority", zone, 6),
                "NXDOMAIN missing negative-caching SOA")
        print(f"PASS NXDOMAIN {'TCP' if tcp else 'UDP'} {size} bytes")
    flags, records, size = check(args.host, args.port, zone, zone, 1, False, args.timeout, edns=True)
    require((flags & 0xF) == 0, "EDNS0 response must return NOERROR")
    validate_edns0_response(records)
    require(size <= 1232, "EDNS0 UDP response exceeded advertised 1232-byte limit")
    print(f"PASS EDNS0 UDP {size} bytes")
    flags, records, _ = check(args.host, args.port, zone, zone, 6, False, args.timeout,
                              edns=True, version=1)
    # RFC 6891: the OPT TTL high byte is the upper eight bits of the
    # twelve-bit RCODE. BADVERS=16 uses extended code 1 and header RCODE 0.
    validate_badvers_response(flags, records)
    print("PASS EDNS BADVERS")
    # An existing apex with an unsupported RR type is NODATA, not NXDOMAIN.
    for tcp in (False, True):
        flags, records, _ = check(args.host, args.port, zone, zone, 15, tcp, args.timeout)
        require((flags & 0x0400) and (flags & 0xF) == 0,
                "apex MX NODATA returned incorrect flags")
        require(not has_rr(records, "answer", zone, 15),
                "unexpected apex MX RRset")
        require(has_rr(records, "authority", zone, 6),
                "NODATA missing negative-caching SOA")
        print(f"PASS NODATA {'TCP' if tcp else 'UDP'}")
    # The listener is authoritative for configured zones only.
    outside = "not-served.invalid"
    for tcp in (False, True):
        flags, _, _ = check(args.host, args.port, zone, outside, 1, tcp, args.timeout)
        require((flags & 0xF) == 5 and not (flags & 0x0080),
                "outside zone did not refuse recursion")
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
