#!/usr/bin/env python3
"""Validate fail-closed CRL checking for an intermediate in a live agent mTLS chain."""

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
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout


def openssl_path() -> str:
    configured = os.environ.get("GATEWAY_TEST_OPENSSL")
    found = shutil.which("openssl")
    if configured:
        return configured
    if found:
        return found
    if os.name == "nt":
        candidate = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/usr/bin/openssl.exe"
        if candidate.is_file():
            return str(candidate)
    raise RuntimeError("OpenSSL is required for the disposable intermediate CRL test")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main() -> None:
    if not AGENT.is_file():
        raise FileNotFoundError(f"Build GatewayAgent first: {AGENT}")
    openssl = openssl_path()
    with tempfile.TemporaryDirectory(prefix="gatewaycore-intermediate-crl-") as temp_name:
        work = Path(temp_name)
        root_crl_port, issuer_crl_port, listener_port = free_port(), free_port(), free_port()
        while len({root_crl_port, issuer_crl_port, listener_port}) != 3:
            root_crl_port, issuer_crl_port, listener_port = free_port(), free_port(), free_port()
        root_crl, issuer_crl = work / "root.crl", work / "issuer.crl"
        crl_requests: list[str] = []

        class CrlHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                crl_requests.append(self.path)
                if self.path == "/root.crl":
                    source = root_crl
                elif self.path == "/issuer.crl":
                    source = issuer_crl
                else:
                    self.send_error(404)
                    return
                body = source.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/pkix-crl")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: object) -> None:
                return

        root_server = http.server.ThreadingHTTPServer(("127.0.0.1", root_crl_port), CrlHandler)
        issuer_server = http.server.ThreadingHTTPServer(("127.0.0.1", issuer_crl_port), CrlHandler)
        root_thread = threading.Thread(target=root_server.serve_forever, daemon=True)
        issuer_thread = threading.Thread(target=issuer_server.serve_forever, daemon=True)
        root_thread.start()
        issuer_thread.start()
        process: subprocess.Popen[str] | None = None
        log_path = work / "gateway-agent.log"
        try:
            for name, value in (
                ("root-index.txt", ""), ("root-serial", "1000\n"), ("root-crlnumber", "1000\n"),
                ("issuer-index.txt", ""), ("issuer-serial", "2000\n"), ("issuer-crlnumber", "2000\n"),
            ):
                (work / name).write_text(value, encoding="ascii")
            path = lambda name: (work / name).as_posix()
            root_config = work / "root.cnf"
            root_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {path('root-index.txt')}
new_certs_dir = {work.as_posix()}
certificate = {path('root.pem')}
private_key = {path('root.key')}
serial = {path('root-serial')}
crlnumber = {path('root-crlnumber')}
default_md = sha256
default_days = 3
default_crl_days = 1
unique_subject = no
policy = policy
[ policy ]
commonName = supplied
[ intermediate_cert ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://127.0.0.1:{root_crl_port}/root.crl
[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = critical,serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:localhost,IP:127.0.0.1
""", encoding="ascii")
            issuer_config = work / "issuer.cnf"
            issuer_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {path('issuer-index.txt')}
new_certs_dir = {work.as_posix()}
certificate = {path('intermediate.pem')}
private_key = {path('intermediate.key')}
serial = {path('issuer-serial')}
crlnumber = {path('issuer-crlnumber')}
default_md = sha256
default_days = 3
default_crl_days = 1
policy = policy
[ policy ]
commonName = supplied
[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = critical,clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://127.0.0.1:{issuer_crl_port}/issuer.crl
""", encoding="ascii")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-days", "3", "-subj", "/CN=GatewayCore disposable CRL root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash", "-addext", "authorityKeyIdentifier=keyid:always,issuer",
                "-keyout", str(work / "root.key"), "-out", str(work / "root.pem"))
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=GatewayCore unique revoked intermediate",
                "-keyout", str(work / "intermediate.key"), "-out", str(work / "intermediate.csr"))
            run(openssl, "ca", "-batch", "-config", str(root_config), "-extensions", "intermediate_cert",
                "-in", str(work / "intermediate.csr"), "-out", str(work / "intermediate.pem"))
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=GatewayCore valid client", "-keyout", str(work / "client.key"),
                "-out", str(work / "client.csr"))
            run(openssl, "ca", "-batch", "-config", str(issuer_config), "-extensions", "client_cert",
                "-in", str(work / "client.csr"), "-out", str(work / "client.pem"))
            chain = work / "client-chain.pem"
            chain.write_bytes((work / "client.pem").read_bytes() + (work / "intermediate.pem").read_bytes())
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=GatewayCore HTTPS listener", "-keyout", str(work / "server.key"),
                "-out", str(work / "server.csr"))
            run(openssl, "ca", "-batch", "-config", str(root_config), "-extensions", "server_cert",
                "-in", str(work / "server.csr"), "-out", str(work / "server.pem"))
            run(openssl, "pkcs12", "-export", "-out", str(work / "server.pfx"),
                "-inkey", str(work / "server.key"), "-in", str(work / "server.pem"),
                "-passout", "pass:disposable-only")
            # The issuer's CRL is current and empty. Only the root CRL revokes
            # the intermediate, leaving the leaf's own issuer CRL status good.
            run(openssl, "ca", "-batch", "-config", str(issuer_config), "-gencrl", "-out", str(issuer_crl))
            run(openssl, "ca", "-batch", "-config", str(root_config), "-revoke", str(work / "intermediate.pem"))
            run(openssl, "ca", "-batch", "-config", str(root_config), "-gencrl", "-out", str(root_crl))
            intermediate_serial = run(openssl, "x509", "-in", str(work / "intermediate.pem"),
                                      "-noout", "-serial").split("=", 1)[1].strip().upper()
            root_crl_text = run(openssl, "crl", "-in", str(root_crl), "-text", "-noout")
            issuer_crl_text = run(openssl, "crl", "-in", str(issuer_crl), "-text", "-noout")
            if intermediate_serial not in root_crl_text or "Revoked Certificates:" not in root_crl_text:
                raise AssertionError(f"fresh root CRL does not revoke intermediate serial {intermediate_serial}")
            if "No Revoked Certificates" not in issuer_crl_text:
                raise AssertionError("issuer CRL unexpectedly contains revoked certificates")
            run(openssl, "verify", "-CAfile", str(work / "root.pem"), "-untrusted",
                str(work / "intermediate.pem"), str(work / "client.pem"))

            pin = run(openssl, "x509", "-in", str(work / "client.pem"), "-noout",
                      "-fingerprint", "-sha1").split("=", 1)[1].replace(":", "").strip().upper()
            env = os.environ.copy()
            env.update({
                "SSL_CERT_FILE": str(work / "root.pem"),
                "Kestrel__Endpoints__AgentHttps__Url": f"https://127.0.0.1:{listener_port}",
                "Kestrel__Endpoints__AgentHttps__Certificate__Path": str(work / "server.pfx"),
                "Kestrel__Endpoints__AgentHttps__Certificate__Password": "disposable-only",
                "Agent__EnableConfigChanges": "false",
                "Agent__EnableEngineConfigChanges": "false",
                "Agent__EnableServiceActions": "false",
                "Agent__TrustedClientThumbprints__0": pin,
            })
            if os.name == "nt":
                env["Agent__LabOnlyClientCaCertificatePath"] = str(work / "root.pem")
                env["Agent__LabOnlyClientCaCheckRevocation"] = "true"
            with log_path.open("w", encoding="utf-8") as output:
                process = subprocess.Popen(["dotnet", str(AGENT)], cwd=work, env=env,
                                           stdout=output, stderr=subprocess.STDOUT, text=True)
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("GatewayAgent exited before listening")
                    try:
                        with socket.create_connection(("127.0.0.1", listener_port), timeout=.2):
                            break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise TimeoutError("GatewayAgent HTTPS listener did not start")

                context = ssl.create_default_context(cafile=str(work / "root.pem"))
                context.load_cert_chain(str(chain), str(work / "client.key"))
                context.check_hostname = False
                client = http.client.HTTPSConnection("127.0.0.1", listener_port, context=context, timeout=10)
                try:
                    client.request("GET", "/agent/v1/status")
                    response = client.getresponse()
                    body = response.read()
                    if response.status == 200:
                        raise AssertionError(
                            f"valid leaf {pin} received HTTP 200 although root CRL revokes intermediate "
                            f"{intermediate_serial}; CRL requests={crl_requests}")
                    raise AssertionError(f"revocation must terminate TLS before HTTP; got {response.status}: {body[:100]!r}")
                except (ssl.SSLError, ConnectionError, TimeoutError, http.client.RemoteDisconnected):
                    pass
                finally:
                    client.close()
                logs = log_path.read_text(encoding="utf-8", errors="replace")
                if pin not in logs or "Revoked" not in logs:
                    raise AssertionError(
                        f"agent did not log leaf {pin} rejected for Revoked chain status; "
                        f"intermediate serial={intermediate_serial}, CRL requests={crl_requests}\n{logs}")
                if "/root.crl" not in crl_requests:
                    raise AssertionError(f"root CRL not retrieved for intermediate serial {intermediate_serial}: {crl_requests}")
                print(
                    f"PASS: live agent rejected leaf {pin} for Revoked intermediate serial "
                    f"{intermediate_serial}; CRL requests={crl_requests}", flush=True)
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            root_server.shutdown()
            root_server.server_close()
            root_thread.join(timeout=2)
            issuer_server.shutdown()
            issuer_server.server_close()
            issuer_thread.join(timeout=2)


if __name__ == "__main__":
    main()
