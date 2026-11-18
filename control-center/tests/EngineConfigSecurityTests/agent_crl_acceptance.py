#!/usr/bin/env python3
"""Exercise production-mode GatewayAgent mTLS revocation with a disposable CA."""

from __future__ import annotations

import http.client
import http.server
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time


REPO = Path(__file__).resolve().parents[3]
AGENT = REPO / "control-center/GatewayAgent/bin/Release/net10.0/GatewayCoreGatewayAgent.dll"


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)
    return result.stdout


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request_status(port: int, cert: Path, key: Path, root: Path) -> int:
    context = ssl.create_default_context(cafile=str(root))
    context.load_cert_chain(str(cert), str(key))
    context.check_hostname = False
    client = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=4)
    try:
        client.request("GET", "/agent/v1/status")
        return client.getresponse().status
    finally:
        client.close()


def require_denied(port: int, cert: Path, key: Path, root: Path, reason: str) -> None:
    try:
        status = request_status(port, cert, key, root)
        if status < 400:
            raise AssertionError(f"{reason}: unexpected HTTP {status}")
    except (ssl.SSLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError):
        pass
    print(f"PASS: production mTLS rejects {reason}", flush=True)


def main() -> None:
    if not AGENT.is_file():
        raise FileNotFoundError(f"Build GatewayAgent first: {AGENT}")
    openssl = shutil.which("openssl")
    if not openssl:
        raise RuntimeError("OpenSSL is required for disposable CRL acceptance")

    with tempfile.TemporaryDirectory(prefix="gatewaycore-agent-crl-") as temp_name:
        temp = Path(temp_name)
        ca_port = free_port()
        dead_port = free_port()
        while dead_port == ca_port:
            dead_port = free_port()
        crl_path = temp / "crl.pem"

        class CrlHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/crl.pem" or not crl_path.is_file():
                    self.send_error(404)
                    return
                payload = crl_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_: object) -> None:
                return

        crl_server = http.server.ThreadingHTTPServer(("127.0.0.1", ca_port), CrlHandler)
        crl_thread = threading.Thread(target=crl_server.serve_forever, daemon=True)
        crl_thread.start()
        try:
            (temp / "index.txt").write_text("", encoding="ascii")
            (temp / "serial").write_text("1000\n", encoding="ascii")
            (temp / "crlnumber").write_text("1000\n", encoding="ascii")
            ca_config = temp / "ca.cnf"
            ca_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {temp / 'index.txt'}
new_certs_dir = {temp}
certificate = {temp / 'root.pem'}
private_key = {temp / 'root.key'}
serial = {temp / 'serial'}
crlnumber = {temp / 'crlnumber'}
default_md = sha256
default_days = 2
default_crl_days = 1
policy = policy
copy_extensions = copy
[ policy ]
commonName = supplied
[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
crlDistributionPoints = URI:http://127.0.0.1:{ca_port}/crl.pem
[ offline_client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
crlDistributionPoints = URI:http://127.0.0.1:{dead_port}/crl.pem
[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
""", encoding="ascii")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-sha256", "-days", "2", "-subj", "/CN=GatewayCore disposable CRL root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(temp / "root.key"), "-out", str(temp / "root.pem"))

            def issue(name: str, section: str = "client_cert") -> tuple[Path, Path]:
                key = temp / f"{name}.key"
                csr = temp / f"{name}.csr"
                cert = temp / f"{name}.pem"
                run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr))
                run(openssl, "ca", "-batch", "-config", str(ca_config), "-extensions", section,
                    "-in", str(csr), "-out", str(cert))
                return cert, key

            good_cert, good_key = issue("good-controller")
            revoked_cert, revoked_key = issue("revoked-controller")
            offline_cert, offline_key = issue("offline-controller", "offline_client_cert")
            server_csr = temp / "server.csr"
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=localhost", "-keyout", str(temp / "server.key"),
                "-out", str(server_csr))
            run(openssl, "ca", "-batch", "-config", str(ca_config), "-extensions", "server_cert",
                "-in", str(server_csr), "-out", str(temp / "server.pem"))
            run(openssl, "pkcs12", "-export", "-out", str(temp / "server.pfx"),
                "-inkey", str(temp / "server.key"), "-in", str(temp / "server.pem"),
                "-passout", "pass:disposable-only")
            run(openssl, "ca", "-batch", "-config", str(ca_config), "-revoke", str(revoked_cert))
            run(openssl, "ca", "-batch", "-config", str(ca_config), "-gencrl", "-out", str(crl_path))
            run(openssl, "crl", "-in", str(crl_path), "-CAfile", str(temp / "root.pem"), "-verify", "-noout")

            port = free_port()
            pins = [run(openssl, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha1").split("=", 1)[1].replace(":", "").strip()
                    for cert in (good_cert, revoked_cert, offline_cert)]
            env = os.environ.copy()
            env.update({
                "SSL_CERT_FILE": str(temp / "root.pem"),
                "Kestrel__Endpoints__AgentHttps__Url": f"https://127.0.0.1:{port}",
                "Kestrel__Endpoints__AgentHttps__Certificate__Path": str(temp / "server.pfx"),
                "Kestrel__Endpoints__AgentHttps__Certificate__Password": "disposable-only",
                "Agent__TrustedClientThumbprints__0": pins[0],
                "Agent__TrustedClientThumbprints__1": pins[1],
                "Agent__TrustedClientThumbprints__2": pins[2],
                "Agent__EnableConfigChanges": "false",
                "Agent__EnableEngineConfigChanges": "false",
                "Agent__EnableServiceActions": "false",
            })
            process = subprocess.Popen(["dotnet", str(AGENT)], cwd=temp, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 12
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("GatewayAgent exited before its HTTPS listener started")
                    try:
                        if request_status(port, good_cert, good_key, temp / "root.pem") == 200:
                            break
                    except (ssl.SSLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError):
                        time.sleep(0.1)
                else:
                    raise TimeoutError("GatewayAgent production-mode CRL listener did not accept valid client")
                print("PASS: production mTLS accepts a CA-trusted pinned client with a fresh signed CRL", flush=True)
                require_denied(port, revoked_cert, revoked_key, temp / "root.pem", "a CA-revoked client certificate")
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after revoked-client rejection")
                print("PASS: valid client remains admitted after revoked-client rejection", flush=True)
                require_denied(port, offline_cert, offline_key, temp / "root.pem", "an unavailable CRL endpoint")
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after unavailable-CRL rejection")
                print("PASS: valid client remains admitted after unavailable-CRL rejection", flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                if process.returncode not in (0, -15):
                    stdout, stderr = process.communicate(timeout=2)
                    raise RuntimeError(f"GatewayAgent exited {process.returncode}:\n{stdout}\n{stderr}")
        finally:
            crl_server.shutdown()
            crl_server.server_close()
            crl_thread.join(timeout=2)


if __name__ == "__main__":
    main()
