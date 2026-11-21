#!/usr/bin/env python3
"""Deterministic DNS wire-probe regression tests; no DNS server required."""
import importlib.util
import pathlib
import struct
import unittest
from unittest.mock import patch

MODULE = pathlib.Path(__file__).with_name("dns_wire_probe.py")
spec = importlib.util.spec_from_file_location("dns_wire_probe", MODULE)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


def reply(packet, flags):
    txid = struct.unpack_from("!H", packet)[0]
    # Echo the original question, but never echo the EDNS OPT request.
    question_end = 12
    while packet[question_end]:
        question_end += packet[question_end] + 1
    question_end += 5
    return struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0) + packet[12:question_end]


class DnsWireProbeTests(unittest.TestCase):
    def test_parser_guards(self):
        probe.validate_parser_guards()

    def test_edns_opt_rdata_accepts_bounded_unknown_options(self):
        # Unknown EDNS options may be ignored, but their TLV wire format
        # must still be checked before the response is accepted.
        txid = 0x1234
        question = probe.name_wire("example.test") + struct.pack("!HH", 1, 1)
        options = struct.pack("!HH", 65000, 3) + b"abc" + struct.pack("!HH", 15, 0)
        packet = (struct.pack("!HHHHHH", txid, 0x8000, 1, 0, 0, 1) +
                  question + b"\0" + struct.pack("!HHIH", 41, 1232, 0, len(options)) + options)
        flags, records = probe.parse(packet, txid, "example.test", 1)
        self.assertEqual(flags, 0x8000)
        probe.validate_edns0_response(records)

    def test_edns_opt_rdata_rejects_truncated_tlv(self):
        txid = 0x1234
        question = probe.name_wire("example.test") + struct.pack("!HH", 1, 1)
        cases = (
            (b"\\x00\\x0f\\x00", "truncated EDNS option header"),
            (struct.pack("!HH", 15, 4) + b"ab", "EDNS option overruns OPT RDATA"),
            (struct.pack("!HH", 15, 0) + b"\x00", "truncated EDNS option header"),
        )
        for options, message in cases:
            with self.subTest(options=options):
                packet = (struct.pack("!HHHHHH", txid, 0x8000, 1, 0, 0, 1) +
                          question + b"\0" +
                          struct.pack("!HHIH", 41, 1232, 0, len(options)) + options)
                with self.assertRaisesRegex(AssertionError, message):
                    probe.parse(packet, txid, "example.test", 1)

    def test_edns0_response_envelope_accepts_valid_opt(self):
        probe.validate_edns0_response([("additional", (), 41, 1232, 0)])

    def test_edns0_response_envelope_rejects_malformed_opt(self):
        valid = ("additional", (), 41, 1232, 0)
        cases = (
            ([], "exactly one"),
            ([valid, valid], "exactly one"),
            ([("answer", (), 41, 1232, 0)], "additional section"),
            ([("additional", (b"example",), 41, 1232, 0)], "root"),
            ([("additional", (), 41, 511, 0)], "UDP size"),
            ([("additional", (), 41, 1232, 0x00010000)], "version"),
            ([("additional", (), 41, 1232, 0x00008000)], "flags"),
            ([("additional", (), 41, 1232, 0x01000000)], "extended RCODE"),
        )
        for records, message in cases:
            with self.subTest(records=records):
                with self.assertRaisesRegex(AssertionError, message):
                    probe.validate_edns0_response(records)

    def test_badvers_response_envelope_accepts_valid_opt(self):
        probe.validate_badvers_response(0x8000, [("additional", (), 41, 1232, 0x01000000)])

    def test_badvers_response_envelope_rejects_malformed_opt(self):
        valid = ("additional", (), 41, 1232, 0x01000000)
        cases = (
            (0x8000, [], "exactly one"),
            (0x8000, [valid, valid], "exactly one"),
            (0x8000, [("answer", (), 41, 1232, 0x01000000)], "additional section"),
            (0x8000, [("additional", (b"bad",), 41, 1232, 0x01000000)], "root"),
            (0x8000, [("additional", (), 41, 511, 0x01000000)], "UDP size"),
            (0x8000, [("additional", (), 41, 1232, 0x01010000)], "version"),
            (0x8000, [("additional", (), 41, 1232, 0x01008000)], "flags"),
            (0x8001, [valid], "RCODE 16"),
            (0x8000, [("additional", (), 41, 1232, 0)], "RCODE 16"),
            (0x8000, [("additional", (), 41, 1232, 0x02000000)], "RCODE 16"),
        )
        for flags, records, message in cases:
            with self.subTest(flags=flags, records=records):
                with self.assertRaisesRegex(AssertionError, message):
                    probe.validate_badvers_response(flags, records)

    def test_truncated_udp_retries_tcp_with_same_query(self):
        seen = []
        def transport(host, port, packet, tcp, timeout):
            seen.append((packet, tcp))
            return reply(packet, 0x8200 if not tcp else 0x8000)
        with patch.object(probe, "exchange", side_effect=transport):
            flags, records, size = probe.check("127.0.0.1", 5353, "example.test",
                                                "example.test", 1, False, 1)
        self.assertEqual(flags, 0x8000)
        self.assertEqual(records, [])
        self.assertGreater(size, 12)
        self.assertEqual([tcp for _, tcp in seen], [False, True])
        self.assertEqual(seen[0][0], seen[1][0])

    def test_partial_rr_on_truncated_udp_is_retried_over_tcp(self):
        calls = []
        def transport(host, port, packet, tcp, timeout):
            calls.append(tcp)
            if not tcp:
                # TC=1 with a declared answer and incomplete RR: legal UDP
                # truncation, but not a parseable complete RR section.
                partial = bytearray(reply(packet, 0x8200))
                struct.pack_into("!H", partial, 6, 1)
                return bytes(partial) + b"\xc0\x0c\x00"
            return reply(packet, 0x8000)
        with patch.object(probe, "exchange", side_effect=transport):
            flags, records, _ = probe.check("127.0.0.1", 5353, "example.test",
                                            "example.test", 1, False, 1)
        self.assertEqual(flags, 0x8000)
        self.assertEqual(records, [])
        self.assertEqual(calls, [False, True])

    def test_oversized_udp_reply_fails_before_tcp_retry(self):
        calls = []
        def transport(host, port, packet, tcp, timeout):
            calls.append(tcp)
            return reply(packet, 0x8200) + b"\0" * 512
        with patch.object(probe, "exchange", side_effect=transport):
            with self.assertRaisesRegex(AssertionError, "advertised payload limit"):
                probe.check("127.0.0.1", 5353, "example.test",
                            "example.test", 1, False, 1)
        self.assertEqual(calls, [False])

    def test_truncated_udp_must_echo_valid_question(self):
        def transport(host, port, packet, tcp, timeout):
            return reply(packet, 0x8200)[:12]
        with patch.object(probe, "exchange", side_effect=transport):
            with self.assertRaisesRegex(AssertionError, "truncated DNS name"):
                probe.check("127.0.0.1", 5353, "example.test",
                            "example.test", 1, False, 1)

    def test_truncated_tcp_is_rejected(self):
        with patch.object(probe, "exchange", side_effect=lambda h, p, packet, tcp, t: reply(packet, 0x8200)):
            with self.assertRaisesRegex(AssertionError, "TCP response unexpectedly truncated"):
                probe.check("127.0.0.1", 5353, "example.test", "example.test", 1, True, 1)

    def test_retried_tcp_still_truncated_is_rejected(self):
        with patch.object(probe, "exchange", side_effect=lambda h, p, packet, tcp, t: reply(packet, 0x8200)):
            with self.assertRaisesRegex(AssertionError, "TCP fallback response remains truncated"):
                probe.check("127.0.0.1", 5353, "example.test", "example.test", 1, False, 1)


if __name__ == "__main__":
    unittest.main()
