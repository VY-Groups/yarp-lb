"""Exercise the shipping authoritative listener over native IPv6 UDP and TCP."""
import argparse
import json
import socket
import struct
import subprocess
import tempfile
import time
from pathlib import Path


def read_exact(stream, length):
    data = bytearray()
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise EOFError("DNS frame ended early")
        data.extend(chunk)
    return bytes(data)


def verify(answer):
    ident, flags, questions, records, _, _ = struct.unpack("!6H", answer[:12])
    assert ident == 42 and flags & 0x8400 == 0x8400 and flags & 15 == 0
    assert questions == records == 1
    assert answer.endswith(socket.inet_pton(socket.AF_INET6, "2001:db8::17"))


def reserve_ipv6_udp_tcp_port():
    """Select a loopback port bindable for both transports on the test host."""
    for _ in range(16):
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
            udp.bind(("::1", 0))
            port = udp.getsockname()[1]
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp:
                    tcp.bind(("::1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("Could not reserve an IPv6 loopback port for both UDP and TCP")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interop", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        port = reserve_ipv6_udp_tcp_port()
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({
            "ListenHost": "::1", "ListenPort": port, "ProbeIntervalSeconds": 1,
            "AllowDocumentationAddressesForTesting": True,
            "Zones": [{"Name": "lab.example", "TtlSeconds": 10,
                       "NameServers": [{"Host": "ns.lab.example", "Address": "2001:db8::53"}],
                       "Sites": [{
                "Address": "2001:db8::17", "Weight": 1,
                "HealthUrl": "http://127.0.0.1:1/health"
            }]}]
        }), encoding="utf-8")
        query = struct.pack("!6H", 42, 0, 1, 0, 0, 0) + b"\x03lab\x07example\x00\x00\x1c\x00\x01"
        process = subprocess.Popen(["dotnet", "engines/GslbDns/bin/Release/net10.0/GslbDns.dll", str(config)])
        try:
            deadline = time.monotonic() + 15
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                udp.settimeout(0.4)
                while process.poll() is None and time.monotonic() < deadline:
                    udp.sendto(query, ("::1", port))
                    try:
                        answer, _ = udp.recvfrom(4096)
                    except (TimeoutError, ConnectionResetError):
                        continue
                    verify(answer)
                    break
                else:
                    raise RuntimeError(f"IPv6 DNS startup failed, exit={process.poll()}")
            with socket.create_connection(("::1", port), timeout=3) as tcp:
                tcp.sendall(struct.pack("!H", len(query)) + query)
                size, = struct.unpack("!H", read_exact(tcp, 2))
                verify(read_exact(tcp, size))
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp:
                udp.connect(("::1", port))
                udp.settimeout(3)
                ns_query = query[:-4] + struct.pack("!2H", 2, 1)
                udp.send(ns_query)
                answer = udp.recv(4096)
                assert struct.unpack("!3H", answer[6:12]) == (1, 0, 1)
                glue = struct.pack("!HHIH", 28, 1, 10, 16) + socket.inet_pton(socket.AF_INET6, "2001:db8::53")
                assert answer.endswith(glue)
                owner = b"\x02ns" + query[12:-4]
                for qtype in (1, 28):
                    udp.send(query[:12] + owner + struct.pack("!2H", qtype, 1))
                    response = udp.recv(4096)
                    assert response[3] & 15 == 0
                    if qtype == 28:
                        assert response.endswith(glue)
                    else:
                        assert struct.unpack("!3H", response[6:12]) == (0, 1, 0)
            if args.interop:
                for client in ("dig", "kdig"):
                    for transport in ("+tcp", "+notcp"):
                        result = subprocess.run(
                            [client, "@::1", "-p", str(port), "lab.example.", "AAAA",
                             transport, "+bufsize=1232", "+short"],
                            capture_output=True, text=True, timeout=6, check=True,
                        )
                        assert result.stdout.strip() == "2001:db8::17", result
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


if __name__ == "__main__":
    main()
