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
                        flags, records = dns_wire_probe.parse(reply, txid)
                        if flags & 0x0400 and any(section == "answer" and kind == 6
                                                  for section, kind, _, _ in records):
                            break
                    except (OSError, AssertionError):
                        pass
                    if time.monotonic() > deadline:
                        raise TimeoutError("Disposable DNS authority did not become authoritative")
                    time.sleep(0.1)
                args = argparse.Namespace(host="127.0.0.1", port=port, zone=ZONE, timeout=3.0)
                dns_wire_probe.run(args)
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
