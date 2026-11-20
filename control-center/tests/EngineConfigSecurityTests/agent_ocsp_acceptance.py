#!/usr/bin/env python3
"""Run the shipping GatewayAgent against a disposable two-tier CA and OCSP responder."""

from __future__ import annotations

import http.client
import http.server
import base64
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from urllib.parse import unquote


REPO = Path(__file__).resolve().parents[3]
AGENT = REPO / "control-center/GatewayAgent/bin/Release/net10.0/GatewayCoreGatewayAgent.dll"


def run(*args: str) -> str:
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=20)
    return result.stdout


def config_path(path: Path) -> str:
    return path.as_posix()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def fingerprint(openssl: str, cert: Path) -> str:
    return run(openssl, "x509", "-in", str(cert), "-noout", "-fingerprint", "-sha1") \
        .split("=", 1)[1].replace(":", "").strip()


def load_chain(cert: Path, key: Path, root: Path) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=str(root))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    # Kestrel presents the leaf certificate; trust the isolated intermediate
    # directly for the client-side listener check while the agent validates
    # incoming client chains from the root anchor.
    intermediate = root.with_name("intermediate.pem")
    if intermediate.is_file():
        context.load_verify_locations(cafile=str(intermediate))
    context.load_cert_chain(str(cert), str(key))
    context.check_hostname = False
    return context


def request_status(port: int, cert: Path, key: Path, root: Path) -> int:
    client = http.client.HTTPSConnection(
        "127.0.0.1", port, context=load_chain(cert, key, root), timeout=10)
    try:
        client.request("GET", "/agent/v1/status")
        return client.getresponse().status
    finally:
        client.close()


def require_no_http_response(port: int, cert: Path, key: Path, root: Path, reason: str) -> None:
    context = load_chain(cert, key, root)
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        try:
            tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        except (ssl.SSLError, ConnectionError, TimeoutError):
            tls = None
        if tls is not None:
            try:
                tls.settimeout(10)
                tls.sendall(b"GET /agent/v1/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                response = tls.recv(4096)
            except (ssl.SSLError, ConnectionError, TimeoutError):
                response = b""
            finally:
                tls.close()
            if response:
                raise AssertionError(f"{reason}: rejected client received HTTP data: {response.splitlines()[0]!r}")
    finally:
        raw.close()


def wait_for_listener(port: int, process: subprocess.Popen[str], name: str) -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"{name} exited before its HTTPS listener started")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError(f"{name} HTTPS listener did not start")


def stop_process(process: subprocess.Popen[str], name: str) -> None:
    terminated = process.poll() is None
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
    expected = (0, 1) if os.name == "nt" else (0, -15)
    if not terminated or process.returncode not in expected:
        raise RuntimeError(f"{name} exited unexpectedly with {process.returncode}")


def issue(openssl: str, ca_config: Path, root: Path, name: str, section: str = "client_cert",
          dates: tuple[str, str] | None = None) -> tuple[Path, Path, Path]:
    key, csr, cert = (root / f"{name}.{suffix}" for suffix in ("key", "csr", "pem"))
    run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
        "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(csr))
    date_args = [] if dates is None else ["-startdate", dates[0], "-enddate", dates[1]]
    run(openssl, "ca", "-batch", "-config", str(ca_config), "-extensions", section,
        *date_args, "-in", str(csr), "-out", str(cert))
    chain = root / f"{name}-chain.pem"
    chain.write_bytes(cert.read_bytes() + (root / "intermediate.pem").read_bytes())
    return cert, key, chain


def main() -> None:
    if not AGENT.is_file():
        raise FileNotFoundError(f"Build GatewayAgent first: {AGENT}")
    openssl = os.environ.get("GATEWAY_TEST_OPENSSL") or "openssl"
    with tempfile.TemporaryDirectory(prefix="gatewaycore-agent-ocsp-") as temp_name:
        root = Path(temp_name)
        port = free_port()
        root_port = free_port()
        while root_port == port:
            root_port = free_port()
        issuer_port = free_port()
        while issuer_port in (port, root_port):
            issuer_port = free_port()
        dead_port = free_port()
        while dead_port in (port, root_port, issuer_port):
            dead_port = free_port()
        (root / "root-index.txt").write_text("", encoding="ascii")
        (root / "root-serial").write_text("0100\n", encoding="ascii")
        (root / "index.txt").write_text("", encoding="ascii")
        (root / "serial").write_text("1000\n", encoding="ascii")
        (root / "crlnumber").write_text("1000\n", encoding="ascii")

        root_config = root / "root-ca.cnf"
        root_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {config_path(root / 'root-index.txt')}
new_certs_dir = {config_path(root)}
certificate = {config_path(root / 'root.pem')}
private_key = {config_path(root / 'root.key')}
serial = {config_path(root / 'root-serial')}
default_md = sha256
default_days = 5
policy = policy
[ policy ]
commonName = supplied
[ intermediate_cert ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:http://127.0.0.1:{root_port}
[ ocsp_signer ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
# RFC 6960 delegated responder: do not recursively require OCSP for
# the short-lived responder certificate itself.
noCheck = ignored
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""", encoding="ascii")
        ca_config = root / "intermediate-ca.cnf"
        ca_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {config_path(root / 'index.txt')}
new_certs_dir = {config_path(root)}
certificate = {config_path(root / 'intermediate.pem')}
private_key = {config_path(root / 'intermediate.key')}
serial = {config_path(root / 'serial')}
crlnumber = {config_path(root / 'crlnumber')}
default_md = sha256
default_days = 5
default_crl_days = 1
policy = policy
copy_extensions = copy
[ policy ]
commonName = supplied
[ client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:http://127.0.0.1:{port},caIssuers;URI:http://127.0.0.1:{issuer_port}/intermediate.pem
[ offline_client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:http://127.0.0.1:{dead_port},caIssuers;URI:http://127.0.0.1:{issuer_port}/intermediate.pem
[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
subjectAltName = DNS:localhost,IP:127.0.0.1
[ ocsp_signer ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
# RFC 6960 delegated responder: do not recursively require OCSP for
# the short-lived responder certificate itself.
noCheck = ignored
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""", encoding="ascii")

        run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
            "-days", "5", "-subj", "/CN=GatewayCore OCSP root",
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash",
            "-keyout", str(root / "root.key"), "-out", str(root / "root.pem"))
        run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
            "-subj", "/CN=GatewayCore OCSP intermediate",
            "-keyout", str(root / "intermediate.key"), "-out", str(root / "intermediate.csr"))
        run(openssl, "ca", "-batch", "-config", str(root_config), "-extensions", "intermediate_cert",
            "-in", str(root / "intermediate.csr"), "-out", str(root / "intermediate.pem"))
        root_ocsp_key, root_ocsp_csr, root_ocsp_cert = (
            root / f"root-ocsp-signer.{suffix}" for suffix in ("key", "csr", "pem"))
        run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
            "-subj", "/CN=GatewayCore root OCSP signer", "-keyout", str(root_ocsp_key),
            "-out", str(root_ocsp_csr))
        run(openssl, "ca", "-batch", "-config", str(root_config), "-extensions", "ocsp_signer",
            "-in", str(root_ocsp_csr), "-out", str(root_ocsp_cert))
        class IssuerHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if self.path != "/intermediate.pem":
                    self.send_error(404)
                    return
                body = (root / "intermediate.pem").read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "application/x-pem-file")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_: object) -> None:
                return

        issuer_server = http.server.ThreadingHTTPServer(("127.0.0.1", issuer_port), IssuerHandler)
        issuer_thread = threading.Thread(target=issuer_server.serve_forever, daemon=True)
        issuer_thread.start()

        good_cert, good_key, good_chain = issue(openssl, ca_config, root, "ocsp-good")
        revoked_cert, revoked_key, revoked_chain = issue(openssl, ca_config, root, "ocsp-revoked")
        expired_cert, expired_key, expired_chain = issue(
            openssl, ca_config, root, "ocsp-expired", dates=("20200101000000Z", "20200102000000Z"))
        offline_cert, offline_key, offline_chain = issue(openssl, ca_config, root, "ocsp-offline",
                                                         "offline_client_cert")
        # A valid chain whose serial is absent from the issuer database yields
        # OCSP Cert Status: unknown rather than a PartialChain validation error.
        unknown_key = root / "ocsp-unknown.key"
        unknown_csr = root / "ocsp-unknown.csr"
        unknown_cert = root / "ocsp-unknown.pem"
        run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
            "-subj", "/CN=ocsp-unknown", "-keyout", str(unknown_key), "-out", str(unknown_csr))
        run(openssl, "x509", "-req", "-in", str(unknown_csr), "-CA", str(root / "intermediate.pem"),
            "-CAkey", str(root / "intermediate.key"), "-set_serial", "9000", "-days", "5", "-sha256",
            "-extfile", str(ca_config), "-extensions", "client_cert", "-out", str(unknown_cert))
        unknown_chain = root / "ocsp-unknown-chain.pem"
        unknown_chain.write_bytes(unknown_cert.read_bytes() + (root / "intermediate.pem").read_bytes())
        run(openssl, "ca", "-batch", "-config", str(ca_config), "-revoke", str(revoked_cert))

        ocsp_key, ocsp_csr, ocsp_cert = (root / f"ocsp-signer.{suffix}" for suffix in ("key", "csr", "pem"))
        run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
            "-subj", "/CN=GatewayCore OCSP signer", "-keyout", str(ocsp_key), "-out", str(ocsp_csr))
        run(openssl, "ca", "-batch", "-config", str(ca_config), "-extensions", "ocsp_signer",
            "-in", str(ocsp_csr), "-out", str(ocsp_cert))
        server_cert, server_key, _ = issue(openssl, ca_config, root, "ocsp-server", "server_cert")
        run(openssl, "pkcs12", "-export", "-out", str(root / "server.pfx"),
            "-inkey", str(server_key), "-in", str(server_cert),
            "-certfile", str(root / "intermediate.pem"), "-passout", "pass:disposable-only")

        ocsp_debug: list[str] = []
        ocsp_requests: list[str] = []
        # Prove that the fixture actually produces correctly signed, fresh
        # responses for each verdict before relying on OS chain diagnostics.
        def check_responder(index: Path, signer: Path, signer_key: Path,
                            issuer: Path, certificate: Path, expected: str) -> None:
            query = root / "preflight-query.der"
            response = root / "preflight-response.der"
            run(openssl, "ocsp", "-issuer", str(issuer), "-cert", str(certificate),
                "-no_nonce", "-reqout", str(query))
            run(openssl, "ocsp", "-index", str(index), "-rsigner", str(signer),
                "-rkey", str(signer_key), "-CA", str(issuer), "-reqin", str(query),
                "-nmin", "5", "-respout", str(response))
            verified = subprocess.run([openssl, "ocsp", "-respin", str(response),
                "-issuer", str(issuer), "-cert", str(certificate), "-no_nonce",
                "-CAfile", str(root / "root.pem"), "-verify_other",
                str(root / "intermediate.pem")], check=True, capture_output=True,
                text=True, timeout=15)
            if "Response verify OK" not in verified.stderr or not any(
                    line.strip().endswith(": " + expected)
                    for line in verified.stdout.splitlines()):
                raise AssertionError("OCSP fixture did not produce verified " + expected + " response")
            print("PASS: independently verified signed OCSP fixture verdict " + expected, flush=True)

        check_responder(root / "root-index.txt", root_ocsp_cert, root_ocsp_key,
                        root / "root.pem", root / "intermediate.pem", "good")
        for certificate, expected in ((good_cert, "good"), (revoked_cert, "revoked"),
                                      (unknown_cert, "unknown")):
            check_responder(root / "index.txt", ocsp_cert, ocsp_key,
                            root / "intermediate.pem", certificate, expected)
        class OcspHandler(http.server.BaseHTTPRequestHandler):
            index_file = root / "index.txt"
            signing_cert = ocsp_cert
            signing_key = ocsp_key
            issuer_cert = root / "intermediate.pem"
            responder_name = "intermediate"

            def _respond(self, request_bytes: bytes) -> None:
                try:
                    if not request_bytes or len(request_bytes) > 65536:
                        self.send_error(400)
                        return
                    request_file = root / f"ocsp-request-{time.time_ns()}.der"
                    response_file = request_file.with_name(request_file.stem + "-response.der")
                    request_file.write_bytes(request_bytes)
                    ocsp_requests.append(f"{self.server.RequestHandlerClass.responder_name}:{self.command}")
                    run(openssl, "ocsp", "-index", str(self.index_file),
                        "-rsigner", str(self.signing_cert), "-rkey", str(self.signing_key),
                        "-CA", str(self.issuer_cert), "-reqin", str(request_file),
                        "-nmin", "5", "-respout", str(response_file))
                    response = response_file.read_bytes()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/ocsp-response")
                    self.send_header("Content-Length", str(len(response)))
                    self.end_headers()
                    self.wfile.write(response)
                except Exception as error:
                    detail = getattr(error, "stderr", None)
                    ocsp_debug.append(f"{error!r}: {detail.strip() if isinstance(detail, str) else ''}")
                    self.send_error(500)

            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/" or length < 1 or length > 65536:
                    self.send_error(400)
                    return
                request_bytes = self.rfile.read(length)
                self._respond(request_bytes)

            def do_GET(self) -> None:
                # RFC 5019 responders encode the DER request in the URL path.
                encoded = unquote(self.path.lstrip("/").split("?", 1)[0])
                if not encoded or len(encoded) > 90000:
                    self.send_error(400)
                    return
                try:
                    request_bytes = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
                except (ValueError, base64.binascii.Error):
                    self.send_error(400)
                    return
                self._respond(request_bytes)

            def log_message(self, *_: object) -> None:
                return

        responder_server = http.server.ThreadingHTTPServer(("127.0.0.1", port), OcspHandler)
        responder_thread = threading.Thread(target=responder_server.serve_forever, daemon=True)
        responder_thread.start()
        class RootOcspHandler(OcspHandler):
            index_file = root / "root-index.txt"
            signing_cert = root_ocsp_cert
            signing_key = root_ocsp_key
            issuer_cert = root / "root.pem"
            responder_name = "root"

        root_responder_server = http.server.ThreadingHTTPServer(("127.0.0.1", root_port), RootOcspHandler)
        root_responder_thread = threading.Thread(target=root_responder_server.serve_forever, daemon=True)
        root_responder_thread.start()

        listener_port = free_port()
        agent_log = root / "agent.log"
        env = os.environ.copy()
        env.update({
            "SSL_CERT_FILE": str(root / "root.pem"),
            "Kestrel__Endpoints__AgentHttps__Url": f"https://127.0.0.1:{listener_port}",
            "Kestrel__Endpoints__AgentHttps__Certificate__Path": str(root / "server.pfx"),
            "Kestrel__Endpoints__AgentHttps__Certificate__Password": "disposable-only",
            "Agent__EnableConfigChanges": "false",
            "Agent__EnableEngineConfigChanges": "false",
            "Agent__EnableServiceActions": "false",
        })
        certs = (good_cert, revoked_cert, expired_cert, unknown_cert)
        pins = [fingerprint(openssl, cert) for cert in certs]
        for index, pin in enumerate(pins):
            env[f"Agent__TrustedClientThumbprints__{index}"] = pin
        if os.name == "nt":
            env["Agent__LabOnlyClientCaCertificatePath"] = str(root / "root.pem")
            env["Agent__LabOnlyClientCaCheckRevocation"] = "true"

        process = None
        rejections: list[tuple[str, tuple[str, ...], str]] = []
        with agent_log.open("w", encoding="utf-8") as output:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    pass
                process = subprocess.Popen(["dotnet", str(AGENT)], cwd=root, env=env,
                                           stdout=output, stderr=subprocess.STDOUT, text=True)
                wait_for_listener(listener_port, process, "OCSP GatewayAgent")
                try:
                    good_status = request_status(listener_port, good_chain, good_key, root / "root.pem")
                except Exception as error:
                    raise AssertionError(
                        f"good OCSP status request failed ({error}); responder requests={ocsp_requests}; "
                        f"responder errors={ocsp_debug}; root index={(root / 'root-index.txt').read_text(encoding='ascii')!r}; "
                        f"agent log:\n"
                        + agent_log.read_text(encoding="utf-8", errors="replace")) from error
                if good_status != 200:
                    raise AssertionError("good OCSP status did not admit a trusted client")
                if "root:GET" not in ocsp_requests and "root:POST" not in ocsp_requests:
                    raise AssertionError("the intermediate certificate did not receive a root-issued OCSP check")
                if "intermediate:GET" not in ocsp_requests and "intermediate:POST" not in ocsp_requests:
                    raise AssertionError("the client certificate did not receive an intermediate-issued OCSP check")
                print("PASS: root+intermediate chain with good OCSP status is accepted", flush=True)
                require_no_http_response(listener_port, revoked_chain, revoked_key, root / "root.pem",
                                         "an OCSP-revoked client")
                rejections.append((pins[1], ("Revoked",), "OCSP-revoked client"))
                require_no_http_response(listener_port, unknown_chain, unknown_key, root / "root.pem",
                                         "a client with unknown OCSP status")
                rejections.append((pins[3], ("RevocationStatusUnknown", "OfflineRevocation"),
                                   "unknown OCSP status"))
                require_no_http_response(listener_port, expired_chain, expired_key, root / "root.pem",
                                         "an expired OCSP client")
                rejections.append((pins[2], ("NotTimeValid",), "expired client"))
            finally:
                if process is not None:
                    alive = process.poll() is None
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                    logs = agent_log.read_text(encoding="utf-8", errors="replace")
                    prefix = "Rejected lab TLS client certificate " if os.name == "nt" else "Rejected TLS client certificate "
                    for thumbprint, statuses, label in rejections:
                        lines = [line for line in logs.splitlines() if prefix + thumbprint in line]
                        if not any(status in line for line in lines for status in statuses):
                            raise AssertionError(f"{label}: chain rejection {statuses} absent from logs; "
                                                 f"responder requests={ocsp_requests}; "
                                                 f"responder errors={ocsp_debug}:\n{logs}")
                    expected = (0, 1) if os.name == "nt" else (0, -15)
                    if not alive or process.returncode not in expected:
                        raise RuntimeError(f"OCSP GatewayAgent exited unexpectedly: {process.returncode}")

        # Use a separate issuer/responder URL and no listener so a cached good
        # OCSP result cannot mask the fail-closed offline-revocation behavior.
        offline_listener = free_port()
        offline_env = env.copy()
        offline_env["Kestrel__Endpoints__AgentHttps__Url"] = f"https://127.0.0.1:{offline_listener}"
        offline_pin = fingerprint(openssl, offline_cert)
        for key in tuple(offline_env):
            if key.startswith("Agent__TrustedClientThumbprints__"):
                del offline_env[key]
        offline_env["Agent__TrustedClientThumbprints__0"] = offline_pin
        offline_log = root / "agent-offline.log"
        offline_process = None
        with offline_log.open("w", encoding="utf-8") as output:
            try:
                offline_process = subprocess.Popen(["dotnet", str(AGENT)], cwd=root, env=offline_env,
                                                   stdout=output, stderr=subprocess.STDOUT, text=True)
                wait_for_listener(offline_listener, offline_process, "offline OCSP GatewayAgent")
                require_no_http_response(offline_listener, offline_chain, offline_key, root / "root.pem",
                                         "an unavailable OCSP responder")
            finally:
                if offline_process is not None:
                    alive = offline_process.poll() is None
                    offline_process.terminate()
                    try:
                        offline_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        offline_process.kill()
                        offline_process.wait(timeout=3)
                    expected = (0, 1) if os.name == "nt" else (0, -15)
                    if not alive or offline_process.returncode not in expected:
                        raise RuntimeError(f"offline OCSP agent exited unexpectedly: {offline_process.returncode}")
        logs = offline_log.read_text(encoding="utf-8", errors="replace")
        prefix = "Rejected lab TLS client certificate " if os.name == "nt" else "Rejected TLS client certificate "
        if prefix + offline_pin not in logs or not any(
                status in logs for status in ("OfflineRevocation", "RevocationStatusUnknown")):
            raise AssertionError("offline OCSP did not fail closed:\n" + logs)
        print("PASS: unknown and unavailable OCSP status fail closed on the real agent", flush=True)
        issuer_server.shutdown()
        issuer_server.server_close()
        issuer_thread.join(timeout=2)
        root_responder_server.shutdown()
        root_responder_server.server_close()
        root_responder_thread.join(timeout=2)
        responder_server.shutdown()
        responder_server.server_close()
        responder_thread.join(timeout=2)


if __name__ == "__main__":
    main()
