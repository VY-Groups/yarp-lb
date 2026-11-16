"""Disposable Linux Actions test for local readiness plus two mTLS validators."""
import base64
import contextlib
import hashlib
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
        if getattr(self.server, "count_checks", False):
            self.server.checks += 1
        self.send_response(self.server.verdict)
        server = self.server
        if hasattr(server, "signer") and server.mode != "unsigned":
            challenge = self.headers.get("Gslb-Challenge", "")
            target = server.origin + self.path
            if server.mode == "wrong-target":
                target += "/other"
            message = f"GatewayCore.Health.v1\n{target}\n{challenge}\n{server.verdict}".encode()
            if server.mode == "replay":
                signature = server.last_signature
            else:
                signature = base64.b64encode(subprocess.run(
                    ["openssl", "dgst", "-sha256", "-sign", server.signer],
                    input=message, capture_output=True, check=True).stdout).decode()
                server.last_signature = signature
            self.send_header("Gslb-Signature", signature)
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
        keys = {}
        for index, (server, origin) in enumerate(zip(observers, origins)):
            server.origin = origin
            server.mode = "signed"
            server.signer = root / f"observer-{index}.key"
            public = root / f"observer-{index}.pub"
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", server.signer)
            openssl("pkey", "-in", server.signer, "-pubout", "-out", public)
            keys[origin] = str(public)
        local = serve(stack)
        env = dict(os.environ, SSL_CERT_FILE=str(root / "ca.pem"),
                   GSLB_VALIDATOR_CERT_PEM=str(root / "client.pem"),
                   GSLB_VALIDATOR_KEY_PEM=str(root / "client.key"),
                   GSLB_VALIDATOR_SIGNING_KEYS=json.dumps(keys), GSLB_VALIDATOR_ORIGINS=",".join(origins))
        nodes = []
        def start_node(interval, environment, rise=1, fall=1):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = root / f"{port}.json"
            config.write_text(json.dumps({"ListenHost": "127.0.0.1", "ListenPort": port,
                "ProbeIntervalSeconds": interval, "Zones": [{"Name": "lab.example", "TtlSeconds": 5,
                "SuccessThreshold": rise, "FailureThreshold": fall, "FailClosedWhenAllSitesDown": True, "Sites": [{"Address": "192.0.2.17", "Weight": 1,
                "HealthUrl": f"http://127.0.0.1:{local.server_port}/ready",
                "ValidatorUrls": [o + "/ready" for o in origins]}]}]}))
            proc = subprocess.Popen(["dotnet", dll, config], env=environment)
            stack.callback(proc.wait)
            stack.callback(proc.kill)
            return proc, port

        for _ in range(2):
            nodes.append(start_node(1, env))
            check(nodes, 0)
        for server in [*observers, local]:
            server.verdict = 503
            check(nodes, 2)
            server.verdict = 200
            check(nodes, 0)

        for mode in ("unsigned", "replay", "wrong-target"):
            observers[0].mode = mode
            check(nodes, 2)
            observers[0].mode = "signed"
            check(nodes, 0)

        # Run the shipped .NET observers with separate keys and upstream checks.
        actual = []
        upstreams = []
        observer_dll = dll.parents[4] / "GslbObserver/bin/Release/net10.0/GslbObserver.dll"
        for index, fixture in enumerate(observers):
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            origin = f"https://127.0.0.1:{port}"
            upstream = serve(stack)
            upstreams.append(upstream)
            conf = root / f"observer-{index}.json"
            fingerprint = hashlib.sha256(ssl.PEM_cert_to_DER_cert((root / "client.pem").read_text())).hexdigest()
            conf.write_text(json.dumps({"ListenAddress": "127.0.0.1", "Port": port,
                "PublicUrl": origin + "/ready", "HealthUrl": f"http://127.0.0.1:{upstream.server_port}/ready",
                "ServerCertificatePem": str(root / "server.pem"), "ServerKeyPem": str(root / "server.key"),
                "SigningKeyPem": str(fixture.signer), "AllowedClientSha256": [fingerprint]}))
            proc = subprocess.Popen(["dotnet", observer_dll, conf], env=env)
            stack.callback(proc.wait)
            stack.callback(proc.kill)
            keys[origin] = keys[fixture.origin]
            actual.append(origin)
        fixture_origins = origins
        origins = actual
        actual_env = dict(env, GSLB_VALIDATOR_SIGNING_KEYS=json.dumps(keys), GSLB_VALIDATOR_ORIGINS=",".join(actual))
        deployed = [start_node(1, actual_env), start_node(1, actual_env)]
        check(deployed, 0)
        for upstream in upstreams:
            upstream.verdict = 503
            check(deployed, 2)
            upstream.verdict = 200
            check(deployed, 0)
        origins = fixture_origins

        # No scheduler refresh before the ten-second lease expires.
        slow = [start_node(30, env)]
        check(slow, 0)
        check(slow, 2)

        # Isolate a single node with rise=2, fall=3. A single missed signed verdict
        # must withdraw immediately and the first recovered probe must stay withdrawn.
        private_local = serve(stack)
        local = private_local
        threshold_node = [start_node(3, env, rise=2, fall=3)]
        check(threshold_node, 0)
        local.verdict = 503
        check(threshold_node, 2)
        local.checks = 0
        local.count_checks = True
        local.verdict = 200
        deadline = time.monotonic() + 6
        while local.checks == 0 and time.monotonic() < deadline:
            time.sleep(.02)
        assert local.checks == 1
        time.sleep(.5)  # allow both loopback signature checks to complete
        check(threshold_node, 2)
        assert local.checks == 1, "first healthy probe prematurely restored the site"
        check(threshold_node, 0)

        # A certificate with only serverAuth cannot authenticate as an observer client.
        wrong = dict(env, GSLB_VALIDATOR_CERT_PEM=str(root / "server.pem"),
                     GSLB_VALIDATOR_KEY_PEM=str(root / "server.key"))
        check([start_node(1, wrong)], 2)


if __name__ == "__main__":
    main()
