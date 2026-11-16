"""Disposable Linux Actions test for local readiness plus two mTLS validators."""
import contextlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time


class Ready(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(self.server.verdict)
        self.end_headers()

    def log_message(self, *args):
        pass


def serve(stack, tls=None):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ready)
    stack.callback(server.server_close)
    server.verdict = 200
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stack.callback(server.shutdown)
    return server


def check(nodes, code):
    packet = struct.pack("!6H", 42, 0, 1, 0, 0, 0) + b"\x03lab\x07example\x00\x00\x01\x00\x01"
    for proc, port in nodes:
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline and proc.poll() is None:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                udp.settimeout(.4)
                udp.sendto(packet, ("127.0.0.1", port))
                try:
                    answer = udp.recv(2048)
                except TimeoutError:
                    continue
            if answer[3] & 15 == code:
                assert struct.unpack("!H", answer[6:8])[0] == (1 if code == 0 else 0)
                if code == 0:
                    assert answer.endswith(socket.inet_aton("192.0.2.17"))
                break
            time.sleep(.1)
        else:
            raise AssertionError(f"node {port} did not reach DNS rcode {code}, exit={proc.poll()}")


def main():
    dll = Path("engines/GslbDns/bin/Release/net10.0/GslbDns.dll").resolve()
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        root = Path(tmp)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)

        openssl("req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-subj", "/CN=Disposable CA", "-keyout", "ca.key", "-out", "ca.pem")
        for role, usage in [("server", "serverAuth"), ("client", "clientAuth")]:
            openssl("req", "-new", "-nodes", "-newkey", "rsa:2048", "-subj", "/CN=" + role,
                    "-keyout", role + ".key", "-out", role + ".csr")
            ext = root / "extensions"
            ext.write_text("extendedKeyUsage=" + usage + "\nsubjectAltName=IP:127.0.0.1\n")
            openssl("x509", "-req", "-in", role + ".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", role + ".pem")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(root / "server.pem", root / "server.key")
        tls.load_verify_locations(root / "ca.pem")
        tls.verify_mode = ssl.CERT_REQUIRED
        observers = [serve(stack, tls), serve(stack, tls)]
        origins = [f"https://127.0.0.1:{s.server_port}" for s in observers]
        local = serve(stack)
        env = dict(os.environ, SSL_CERT_FILE=str(root / "ca.pem"),
                   GSLB_VALIDATOR_CERT_PEM=str(root / "client.pem"),
                   GSLB_VALIDATOR_KEY_PEM=str(root / "client.key"),
                   GSLB_VALIDATOR_ORIGINS=",".join(origins))
        nodes = []
        for _ in range(2):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = root / f"{port}.json"
            config.write_text(json.dumps({"ListenHost": "127.0.0.1", "ListenPort": port,
                "ProbeIntervalSeconds": 1, "Zones": [{"Name": "lab.example", "TtlSeconds": 5,
                "FailClosedWhenAllSitesDown": True, "Sites": [{"Address": "192.0.2.17", "Weight": 1,
                "HealthUrl": f"http://127.0.0.1:{local.server_port}/ready",
                "ValidatorUrls": [o + "/ready" for o in origins]}]}]}))
            proc = subprocess.Popen(["dotnet", dll, config], env=env)
            stack.callback(proc.wait)
            stack.callback(proc.kill)
            nodes.append((proc, port))
            check(nodes, 0)
        for server in [*observers, local]:
            server.verdict = 503
            check(nodes, 2)
            server.verdict = 200
            check(nodes, 0)


if __name__ == "__main__":
    main()
