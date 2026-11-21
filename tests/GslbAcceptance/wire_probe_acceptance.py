#!/usr/bin/env python3
"""Windows/Linux real-process authoritative DNS wire acceptance.

Starts only a disposable loopback DNS authority with documentation-only IPs,
runs the independent standard-library wire probe, and removes the process.
No public zone, actual resolver, production DNS, or privileged port is used.
"""
import argparse
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "ops" / "acceptance"))
import dns_wire_probe  # noqa: E402

ZONE = "wire.integration.test"


def reserve_dual_transport_port():
    """Choose a local port available for both UDP and TCP."""
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                try:
                    udp.bind(("127.0.0.1", port))
                    return port
                except OSError:
                    continue
    raise RuntimeError("No disposable UDP/TCP loopback port available")


def run():
    dll = REPO / "engines" / "GslbDns" / "bin" / "Release" / "net10.0" / "GslbDns.dll"
    if not dll.is_file():
        raise FileNotFoundError("Build GslbDns in Release configuration first")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-dns-wire-") as temp:
        root = Path(temp)
        port = reserve_dual_transport_port()
        config = root / "wire-zone.json"
        config.write_text(json.dumps({
            "ListenHost": "127.0.0.1",
            "AllowDocumentationAddressesForTesting": True,
            "ListenPort": port,
            "ProbeIntervalSeconds": 30,
            "Zones": [{
                "Name": ZONE,
                "TtlSeconds": 10,
                "SoaSerial": 2026112101,
                "SoaContact": "hostmaster." + ZONE,
                "NameServers": [
                    {"Host": "ns1." + ZONE, "Address": "192.0.2.53"},
                    {"Host": "ns2." + ZONE, "Address": "192.0.2.54"}
                ],
                "FailClosedWhenAllSitesDown": False,
                "Sites": [{"Address": "192.0.2.17", "Weight": 1,
                           "HealthUrl": "http://127.0.0.1:1/ready"}]
            }]
        }), encoding="utf-8")
        log = root / "dns-process.log"
        with log.open("w", encoding="utf-8") as output:
            process = subprocess.Popen(["dotnet", str(dll), str(config)],
                                       cwd=REPO, stdout=output, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 20
                while True:
                    if process.poll() is not None:
                        raise RuntimeError(f"DNS authority exited with {process.returncode}")
                    try:
                        txid, wire = dns_wire_probe.question(ZONE, 6)
                        reply = dns_wire_probe.exchange("127.0.0.1", port, wire, False, 0.4)
                        flags, records = dns_wire_probe.parse(reply, txid, ZONE, 6)
                        if flags & 0x0400 and dns_wire_probe.has_rr(records, "answer", ZONE, 6):
                            break
                    except (OSError, AssertionError):
                        pass
                    if time.monotonic() > deadline:
                        raise TimeoutError("Disposable DNS authority did not become authoritative")
                    time.sleep(0.1)
                args = argparse.Namespace(host="127.0.0.1", port=port, zone=ZONE, timeout=3.0)
                dns_wire_probe.run(args)
                # Reserved zero QTYPE/QCLASS must never be normalized into
                # authoritative NODATA. Exercise both transports and ensure
                # a subsequent valid SOA query still works after rejection.
                for qtype, qclass in ((0, 1), (6, 0), (0, 0)):
                    for tcp in (False, True):
                        txid, packet = dns_wire_probe.question(ZONE, qtype)
                        frame = bytearray(packet)
                        frame[-2:] = qclass.to_bytes(2, "big")
                        try:
                            response = dns_wire_probe.exchange(
                                "127.0.0.1", port, bytes(frame), tcp, 0.4)
                        except (OSError, TimeoutError):
                            response = b""
                        except AssertionError as error:
                            # The TCP DNS server deliberately closes the
                            # connection for malformed reserved questions;
                            # the shared framed reader reports that EOF as an
                            # assertion. Treat only this exact EOF as a drop.
                            if str(error) != "TCP DNS response ended early":
                                raise
                            response = b""
                        if response:
                            # FORMERR need not echo a malformed question, so
                            # inspect only the DNS header, not the normal
                            # successful-answer parser's IN-class contract.
                            dns_wire_probe.require(len(response) >= 12 and
                                int.from_bytes(response[:2], "big") == txid and
                                (int.from_bytes(response[2:4], "big") & 0x800F) == 0x8001,
                                "reserved zero question received a non-FORMERR response")
                        valid_id, valid_packet = dns_wire_probe.question(ZONE, 6)
                        valid_reply = dns_wire_probe.exchange(
                            "127.0.0.1", port, valid_packet, tcp, 2)
                        valid_flags, valid_records = dns_wire_probe.parse(
                            valid_reply, valid_id, ZONE, 6)
                        dns_wire_probe.require((valid_flags & 0xF) == 0 and
                            dns_wire_probe.has_rr(valid_records, "answer", ZONE, 6),
                            "valid SOA recovery failed after malformed question")
                print("PASS: reserved-zero question rejection and valid recovery")
                print("PASS: disposable Windows/Linux real-process DNS wire qualification")
            except BaseException:
                output.flush()
                print(log.read_text(encoding="utf-8", errors="replace")[-8000:], file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)


if __name__ == "__main__":
    run()
