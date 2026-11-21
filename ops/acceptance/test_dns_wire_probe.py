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
