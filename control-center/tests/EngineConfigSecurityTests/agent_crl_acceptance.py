#!/usr/bin/env python3
"""Exercise production GatewayAgent CRL enforcement with a disposable CA.

TLS 1.3 clients can observe the TLS socket as established before Kestrel reports
the client-chain result. Rejected certificates must receive no HTTP response;
the test also matches a server-side chain rejection by that certificate's pin.

On Windows, run only on a disposable CI/VM: the test temporarily adds its generated
root to CurrentUser\\Root and removes that exact thumbprint in finally. Some local
automation hosts block certificate-store writes; that is an environment limitation,
not a product result. GitHub's hosted Windows runner is the acceptance environment.
"""

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
TEST_HOST = REPO / "control-center/tests/EngineConfigSecurityTests/bin/Release/net10.0/EngineConfigSecurityTests.dll"


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)
    return result.stdout


def find_openssl() -> str:
    openssl = shutil.which("openssl")
    if openssl:
        return openssl
    if os.name == "nt":
        candidates = [
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git/usr/bin/openssl.exe",
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "OpenSSL-Win64/bin/openssl.exe",
        ]
        for candidate in candidates:
            if candidate.is_file():
                return str(candidate)
    raise RuntimeError("OpenSSL is required for disposable CRL acceptance")


def openssl_config_path(path: Path) -> str:
    # OpenSSL config files parse backslashes as escapes on Windows.
    return path.as_posix()


def update_windows_test_root(operation: str, value: str) -> None:
    if not TEST_HOST.is_file():
        raise FileNotFoundError(f"Build EngineConfigSecurityTests first: {TEST_HOST}")
    subprocess.run(["dotnet", str(TEST_HOST), f"--crl-test-root-{operation}", value],
                   check=True, capture_output=True, text=True, timeout=20)


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


def require_no_http_response(port: int, cert: Path, key: Path, root: Path, reason: str) -> None:
    """Ensure a rejected certificate cannot obtain any HTTP response."""
    context = ssl.create_default_context(cafile=str(root))
    context.load_cert_chain(str(cert), str(key))
    context.check_hostname = False
    raw = socket.create_connection(("127.0.0.1", port), timeout=4)
    try:
        try:
            tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass
        else:
            try:
                tls.settimeout(4)
                tls.sendall(b"GET /agent/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                response = tls.recv(4096)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                response = b""
            finally:
                tls.close()
            if response:
                raise AssertionError(
                    f"{reason}: server returned application-layer data instead of rejecting the client chain: "
                    f"{response.splitlines()[0]!r}")
    finally:
        raw.close()
    print(f"PASS: production mTLS returned no HTTP response for {reason}; chain log is checked at teardown",
          flush=True)


def main() -> None:
    if not AGENT.is_file():
        raise FileNotFoundError(f"Build GatewayAgent first: {AGENT}")
    openssl = find_openssl()

    with tempfile.TemporaryDirectory(prefix="gatewaycore-agent-crl-") as temp_name:
        temp = Path(temp_name)
        ca_port = free_port()
        dead_port = free_port()
        while dead_port == ca_port:
            dead_port = free_port()
        crl_path = temp / "crl.pem"
        root_installed = False
        root_thumbprint = ""

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
            (temp / "unknown-index.txt").write_text("", encoding="ascii")
            (temp / "unknown-serial").write_text("2000\n", encoding="ascii")
            ca_config = temp / "ca.cnf"
            ca_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {openssl_config_path(temp / 'index.txt')}
new_certs_dir = {openssl_config_path(temp)}
certificate = {openssl_config_path(temp / 'root.pem')}
private_key = {openssl_config_path(temp / 'root.key')}
serial = {openssl_config_path(temp / 'serial')}
crlnumber = {openssl_config_path(temp / 'crlnumber')}
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
            unknown_ca_config = temp / "unknown-ca.cnf"
            unknown_ca_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {openssl_config_path(temp / 'unknown-index.txt')}
new_certs_dir = {openssl_config_path(temp)}
certificate = {openssl_config_path(temp / 'unknown-root.pem')}
private_key = {openssl_config_path(temp / 'unknown-root.key')}
serial = {openssl_config_path(temp / 'unknown-serial')}
default_md = sha256
default_days = 2
policy = policy
[ policy ]
commonName = supplied
[ unknown_client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
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

            def issue_expired(name: str) -> tuple[Path, Path]:
                key = temp / f"{name}.key"
                csr = temp / f"{name}.csr"
                cert = temp / f"{name}.pem"
                run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                    "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr))
                run(openssl, "ca", "-batch", "-config", str(ca_config), "-extensions", "client_cert",
                    "-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
                    "-in", str(csr), "-out", str(cert))
                return cert, key

            good_cert, good_key = issue("good-controller")
            revoked_cert, revoked_key = issue("revoked-controller")
            offline_cert, offline_key = issue("offline-controller", "offline_client_cert")
            expired_cert, expired_key = issue_expired("expired-controller")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-days", "2", "-subj", "/CN=GatewayCore unknown disposable root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-keyout", str(temp / "unknown-root.key"), "-out", str(temp / "unknown-root.pem"))
            unknown_csr = temp / "unknown-controller.csr"
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=unknown-controller", "-keyout", str(temp / "unknown-controller.key"),
                "-out", str(unknown_csr))
            run(openssl, "ca", "-batch", "-config", str(unknown_ca_config),
                "-extensions", "unknown_client_cert", "-in", str(unknown_csr),
                "-out", str(temp / "unknown-controller.pem"))
            unknown_cert = temp / "unknown-controller.pem"
            unknown_key = temp / "unknown-controller.key"
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

            if os.name == "nt":
                # Windows X509Chain uses the OS trust store; SSL_CERT_FILE only
                # supplies roots to OpenSSL-based runtimes. The CI VM is
                # disposable, and the exact temporary root is removed in finally.
                root_der = temp / "root.cer"
                run(openssl, "x509", "-in", str(temp / "root.pem"), "-outform", "DER",
                    "-out", str(root_der))
                root_thumbprint = run(openssl, "x509", "-in", str(temp / "root.pem"),
                    "-noout", "-fingerprint", "-sha1").split("=", 1)[1].replace(":", "").strip().upper()
                root_installed = True
                cleanup_path = os.environ.get("GATEWAY_CRL_TEST_ROOT_THUMBPRINT_FILE")
                if cleanup_path:
                    Path(cleanup_path).write_text(root_thumbprint, encoding="ascii")
                update_windows_test_root("add", str(root_der))
                print("PASS: installed disposable CRL test root in the Windows current-user trust store", flush=True)

            port = free_port()
            certificates = (good_cert, revoked_cert, offline_cert, expired_cert, unknown_cert)
            pins = [run(openssl, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha1").split("=", 1)[1].replace(":", "").strip()
                    for cert in certificates]
            env = os.environ.copy()
            env.update({
                "SSL_CERT_FILE": str(temp / "root.pem"),
                "Kestrel__Endpoints__AgentHttps__Url": f"https://127.0.0.1:{port}",
                "Kestrel__Endpoints__AgentHttps__Certificate__Path": str(temp / "server.pfx"),
                "Kestrel__Endpoints__AgentHttps__Certificate__Password": "disposable-only",
                "Agent__EnableConfigChanges": "false",
                "Agent__EnableEngineConfigChanges": "false",
                "Agent__EnableServiceActions": "false",
            })
            env.update({f"Agent__TrustedClientThumbprints__{index}": pin
                        for index, pin in enumerate(pins)})
            agent_log = temp / "gateway-agent.log"
            agent_log_stream = agent_log.open("w", encoding="utf-8")
            try:
                process = subprocess.Popen(["dotnet", str(AGENT)], cwd=temp, env=env,
                                           stdout=agent_log_stream, stderr=subprocess.STDOUT, text=True)
            except Exception:
                agent_log_stream.close()
                raise
            expected_chain_rejections: list[tuple[str, tuple[str, ...], str]] = []
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
                require_no_http_response(port, revoked_cert, revoked_key, temp / "root.pem",
                                         "a CA-revoked client certificate")
                expected_chain_rejections.append((pins[1], ("Revoked",), "revoked certificate"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after revoked-client rejection")
                print("PASS: valid client remains admitted after revoked-client rejection", flush=True)
                require_no_http_response(port, offline_cert, offline_key, temp / "root.pem",
                                         "an unavailable CRL endpoint")
                expected_chain_rejections.append((pins[2],
                                                  ("OfflineRevocation", "RevocationStatusUnknown"),
                                                  "unavailable CRL endpoint"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after unavailable-CRL rejection")
                print("PASS: valid client remains admitted after unavailable-CRL rejection", flush=True)
                require_no_http_response(port, expired_cert, expired_key, temp / "root.pem",
                                         "an expired client certificate")
                expected_chain_rejections.append((pins[3], ("NotTimeValid",), "expired client certificate"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after expired-client rejection")
                print("PASS: valid client remains admitted after expired-client rejection", flush=True)
                require_no_http_response(port, unknown_cert, unknown_key, temp / "root.pem",
                                         "a client certificate from an untrusted CA")
                expected_chain_rejections.append((pins[4], ("PartialChain",), "unknown client CA"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after unknown-chain rejection")
                print("PASS: valid client remains admitted after unknown-chain rejection", flush=True)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                agent_log_stream.flush()
                agent_log_stream.close()
                logs = agent_log.read_text(encoding="utf-8", errors="replace")
                request_prefix = f"Request starting HTTP/1.1 GET https://127.0.0.1:{port}/agent/v1/status"
                if sum(request_prefix in line for line in logs.splitlines()) != 5:
                    raise AssertionError(
                        "expected only the five valid-client requests to reach the HTTP pipeline; logs:\n" + logs)
                for thumbprint, statuses, reason in expected_chain_rejections:
                    event_lines = [line for line in logs.splitlines()
                                   if "Rejected TLS client certificate " + thumbprint in line]
                    matching_statuses = [status for status in statuses
                                         if any(status in line for line in event_lines)]
                    if not matching_statuses:
                        raise AssertionError(
                            f"{reason}: expected production chain rejection for thumbprint {thumbprint} "
                            f"with status {statuses}; agent logs:\n{logs}")
                    status = matching_statuses[0]
                    print(f"PASS: agent chain log identifies {reason} with status {status}", flush=True)
                if process.returncode not in (0, -15):
                    raise RuntimeError(f"GatewayAgent exited {process.returncode}; logs:\n" + logs)
        finally:
            crl_server.shutdown()
            crl_server.server_close()
            crl_thread.join(timeout=2)
            if root_installed:
                # Fail the test if cleanup cannot remove this exact generated root.
                update_windows_test_root("remove", root_thumbprint)
                print("PASS: removed disposable CRL test root from the Windows current-user trust store", flush=True)
                cleanup_path = os.environ.get("GATEWAY_CRL_TEST_ROOT_THUMBPRINT_FILE")
                if cleanup_path:
                    Path(cleanup_path).unlink(missing_ok=True)


if __name__ == "__main__":
    main()
