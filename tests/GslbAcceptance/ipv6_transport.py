"""Exercise the shipping authoritative listener over native IPv6 UDP and TCP."""
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


def main():
    with tempfile.TemporaryDirectory() as directory:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as reservation:
            reservation.bind(("::1", 0))
            port = reservation.getsockname()[1]
        config = Path(directory) / "config.json"
        config.write_text(json.dumps({
            "ListenHost": "::1", "ListenPort": port, "ProbeIntervalSeconds": 1,
            "Zones": [{"Name": "lab.example", "TtlSeconds": 10, "Sites": [{
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
        finally:
            if process.poll() is None:
                process.kill()
            process.wait()


if __name__ == "__main__":
    main()
