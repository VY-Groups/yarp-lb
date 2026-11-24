#!/usr/bin/env python3
"""Exercise production GatewayAgent CRL enforcement with a disposable CA.

TLS 1.3 clients can observe the TLS socket as established before Kestrel reports
the client-chain result. Rejected certificates must receive no HTTP response;
the test also matches a server-side chain rejection by that certificate's pin.

On Windows, the agent uses its loopback-only test CA trust mode with online revocation
explicitly enabled. The public test root is process-scoped; no OS certificate store
is changed. This verifies Windows chain/CRL handling on the real Kestrel endpoint,
but does not validate the default System trust store or enterprise deployment.
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
import sys
import tempfile
import threading
import time


REPO = Path(__file__).resolve().parents[3]
AGENT = REPO / "control-center/GatewayAgent/bin/Release/net10.0/GatewayCoreGatewayAgent.dll"


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


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


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


def was_stopped_by_test(returncode: int | None, terminated_by_test: bool) -> bool:
    # Python's terminate() uses TerminateProcess on Windows, whose expected
    # process exit status is 1; POSIX reports SIGTERM as -15.
    accepted_codes = (0, 1) if os.name == "nt" else (0, -15)
    return terminated_by_test and returncode in accepted_codes


def verify_termination_contract() -> None:
    if was_stopped_by_test(0, False) or was_stopped_by_test(1, False) or \
            was_stopped_by_test(-15, False) or was_stopped_by_test(None, False):
        raise AssertionError("an agent exit without test-initiated termination was accepted")
    accepted = (0, 1) if os.name == "nt" else (0, -15)
    if any(not was_stopped_by_test(code, True) for code in accepted):
        raise AssertionError("a test-initiated process termination status was rejected")


def request_status(port: int, cert: Path, key: Path, root: Path) -> int:
    context = ssl.create_default_context(cafile=str(root))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    context.check_hostname = False
    # Leave room for the agent's bounded five-second online CRL retrieval.
    client = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=10)
    try:
        client.request("GET", "/agent/v1/status")
        return client.getresponse().status
    finally:
        client.close()


def require_no_http_response(port: int, cert: Path, key: Path, root: Path, reason: str) -> None:
    """Ensure a rejected certificate cannot obtain any HTTP response."""
    context = ssl.create_default_context(cafile=str(root))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(cert), str(key))
    context.check_hostname = False
    raw = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        try:
            tls = context.wrap_socket(raw, server_hostname="127.0.0.1")
        except (ssl.SSLError, ConnectionError, TimeoutError):
            pass
        else:
            try:
                tls.settimeout(10)
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
    verify_termination_contract()
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
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://127.0.0.1:{ca_port}/crl.pem
[ server_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
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
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
""", encoding="ascii")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-sha256", "-days", "2", "-subj", "/CN=GatewayCore disposable CRL root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always,issuer",
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
            expired_cert, expired_key = issue_expired("expired-controller")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-days", "2", "-subj", "/CN=GatewayCore unknown disposable root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always,issuer",
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

            port = free_port()
            certificates = (good_cert, revoked_cert, expired_cert, unknown_cert)
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
            if os.name == "nt":
                env["Agent__LabOnlyClientCaCertificatePath"] = str(temp / "root.pem")
                env["Agent__LabOnlyClientCaCheckRevocation"] = "true"
            agent_log = temp / "gateway-agent.log"
            agent_log_stream = agent_log.open("w", encoding="utf-8")
            try:
                process = subprocess.Popen(["dotnet", str(AGENT)], cwd=temp, env=env,
                                           stdout=agent_log_stream, stderr=subprocess.STDOUT, text=True)
            except Exception:
                agent_log_stream.close()
                raise
            expected_chain_rejections: list[tuple[str, tuple[str, ...], str]] = []
            terminated_by_test = False
            try:
                deadline = time.monotonic() + 30
                last_connect_error: BaseException | None = None
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise RuntimeError("GatewayAgent exited before its HTTPS listener started")
                    try:
                        if request_status(port, good_cert, good_key, temp / "root.pem") == 200:
                            break
                    except (ssl.SSLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError) as error:
                        last_connect_error = error
                        time.sleep(0.1)
                else:
                    raise TimeoutError(
                        "GatewayAgent CRL listener did not accept valid client; last request error: "
                        + repr(last_connect_error))
                print("PASS: production mTLS accepts a CA-trusted pinned client with a fresh signed CRL", flush=True)
                require_no_http_response(port, revoked_cert, revoked_key, temp / "root.pem",
                                         "a CA-revoked client certificate")
                expected_chain_rejections.append((pins[1], ("Revoked",), "revoked certificate"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after revoked-client rejection")
                print("PASS: valid client remains admitted after revoked-client rejection", flush=True)
                require_no_http_response(port, expired_cert, expired_key, temp / "root.pem",
                                         "an expired client certificate")
                expected_chain_rejections.append((pins[2], ("NotTimeValid",), "expired client certificate"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after expired-client rejection")
                print("PASS: valid client remains admitted after expired-client rejection", flush=True)
                require_no_http_response(port, unknown_cert, unknown_key, temp / "root.pem",
                                         "a client certificate from an untrusted CA")
                expected_chain_rejections.append((pins[3], ("PartialChain",), "unknown client CA"))
                if request_status(port, good_cert, good_key, temp / "root.pem") != 200:
                    raise AssertionError("valid client stopped working after unknown-chain rejection")
                print("PASS: valid client remains admitted after unknown-chain rejection", flush=True)
            finally:
                terminated_by_test = process.poll() is None
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
                if sum(request_prefix in line for line in logs.splitlines()) != 4:
                    raise AssertionError(
                        "expected only the five valid-client requests to reach the HTTP pipeline; logs:\n" + logs)
                for thumbprint, statuses, reason in expected_chain_rejections:
                    rejection_prefix = ("Rejected lab TLS client certificate " if os.name == "nt"
                                        else "Rejected TLS client certificate ")
                    event_lines = [line for line in logs.splitlines()
                                   if rejection_prefix + thumbprint in line]
                    matching_statuses = [status for status in statuses
                                         if any(status in line for line in event_lines)]
                    if not matching_statuses:
                        raise AssertionError(
                            f"{reason}: expected production chain rejection for thumbprint {thumbprint} "
                            f"with status {statuses}; agent logs:\n{logs}")
                    status = matching_statuses[0]
                    print(f"PASS: agent chain log identifies {reason} with status {status}", flush=True)
                if not was_stopped_by_test(process.returncode, terminated_by_test):
                    raise RuntimeError(f"GatewayAgent exited {process.returncode}; logs:\n" + logs)

            # Mutations must use production chain validation on both OSes.
            # On Windows provision only the unique disposable CA into the
            # hosted runner's machine root store and remove it after the test.
            # Never perform these mutations on a developer or customer host.
            if os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted":
                windows_root_pin = None
                if os.name == "nt":
                    windows_root_pin=run(openssl,"x509","-in",str(temp/"root.pem"),"-noout","-fingerprint","-sha1").split("=",1)[1].replace(":","").strip()
                    run(openssl,"x509","-in",str(temp/"root.pem"),"-outform","DER","-out",str(temp/"fleet-root.cer"))
                recovery_dll = os.environ.get("GATEWAY_FLEET_RECOVERY_TEST_DLL")
                if not recovery_dll or not Path(recovery_dll).is_file():
                    raise AssertionError("missing shared recovery helper fixture executable")
                run(openssl,"ecparam","-name","prime256v1","-genkey","-noout","-out",str(temp/"fleet-private.pem"))
                run(openssl,"ec","-in",str(temp/"fleet-private.pem"),"-pubout","-out",str(temp/"fleet-public.pem"))
                recovery_ports = [free_port(),free_port()]
                while recovery_ports[0] == recovery_ports[1]:
                    recovery_ports[1] = free_port()
                processes = [None,None]
                streams = []
                commercial_setting=os.environ.get("GATEWAY_COMMERCIAL_RECOVERY_ROOT")
                commercial=Path(commercial_setting).resolve() if commercial_setting else None
                if commercial and (os.name!="posix" or os.environ.get("CI")!="true" or os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted"):
                    raise AssertionError("Commercial recovery scenario is restricted to disposable hosted Linux CI")
                if commercial:
                    fixture=commercial/"fixture/OfflineLicensing.dll"
                    commercial_agent=commercial/"agent/GatewayCoreGatewayAgent.dll"
                    commercial_gateway=commercial/"gateway/GatewayCoreYarp.dll"
                    keys=commercial/"keys"
                    for required in (fixture,commercial_agent,commercial_gateway,keys/"trust.json"):
                        if not required.is_file():raise FileNotFoundError(required)
                    def command(*args,env=None):
                        result=subprocess.run(["dotnet",*map(str,args)],env=env,capture_output=True,text=True,timeout=45)
                        if result.returncode:raise AssertionError(result.stdout+result.stderr)
                        return result.stdout
                    revoked_nodes=set()
                controller_root = temp/"fleet-controller"
                journal_dir = (controller_root/"state"/"fleet-rollouts" if os.name != "nt" else temp/"fleet-journals")
                journal_dir.mkdir(parents=True,mode=0o700)
                journal_path = journal_dir/"rollout_AAAAAAAAAAAAAAAAAAAAAAAA.json"
                def start_node(i):
                    node = temp/f"recovery-node-{i}"
                    node.mkdir(exist_ok=True)
                    config_file = node/"gateway.json"
                    if not config_file.exists():
                        config_file.write_text('{"ReverseProxy":{"Routes":{},"Clusters":{}},"fixture":"original"}')
                    child = dict(env, Agent__EnableConfigChanges="true",
                        Agent__GatewayConfigPath=str(config_file), Agent__StageDirectory=str(node/"stage"),
                        Agent__ControllerSigningPublicKeyPath=str(temp/"fleet-public.pem"),
                        Kestrel__Endpoints__AgentHttps__Url=f"https://127.0.0.1:{recovery_ports[i]}")
                    child.pop("Agent__LabOnlyClientCaCertificatePath",None)
                    child.pop("Agent__LabOnlyClientCaCheckRevocation",None)
                    for key in tuple(child):
                        if key.startswith("Agent__TrustedClientThumbprints__") and key != "Agent__TrustedClientThumbprints__0":
                            del child[key]
                    agent_binary=AGENT
                    if commercial:
                        agent_binary=commercial_agent
                        child["GATEWAYCORE_ENGINE_LICENSE_DIR"]=str(node/"identity")
                        request=node/"activation.gcr"
                        if not request.exists():
                            command(agent_binary,"--license-init",env=child)
                            command(agent_binary,"--license-request",request,env=child)
                            envelope=node/"active.lic"
                            command(fixture,"--ci-fleet-three-license",keys,request,envelope,"dc" if i==0 else "dr")
                            command(agent_binary,"--license-import",envelope,env=child)
                        if i in revoked_nodes:child["GATEWAYCORE_AGENT_RECOVERY_ONLY"]="true"
                    stream = (node/"agent.log").open("a",encoding="utf-8")
                    streams.append(stream)
                    processes[i]=subprocess.Popen(["dotnet",str(agent_binary)],cwd=node,env=child,stdout=stream,stderr=subprocess.STDOUT)
                    wait_for_listener(recovery_ports[i],processes[i],"fleet recovery agent")
                    deadline=time.monotonic()+12
                    while True:
                        try:
                            if request_status(recovery_ports[i],good_cert,good_key,temp/"root.pem")==200:
                                break
                        except (OSError,http.client.HTTPException):
                            pass
                        if time.monotonic()>=deadline:
                            raise TimeoutError("fleet recovery agent did not admit production mTLS")
                        time.sleep(.1)
                def stop_node(i):
                    proc=processes[i]
                    if proc is not None and proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=5)
                def revoke_node(i):
                    node=temp/f"recovery-node-{i}"
                    revocation=node/"revoked.gcv"
                    command(fixture,"--ci-engine-revoke",keys,node/"activation.gcr",revocation,"fleet")
                    child=dict(os.environ,GATEWAYCORE_ENGINE_LICENSE_DIR=str(node/"identity"))
                    # Stop first to avoid racing the process's protected-state lock.
                    stop_node(i)
                    command(commercial_agent,"--license-revoke",revocation,env=child)
                    revoked_nodes.add(i)
                def invoke(mode,revoked=False):
                    invoke_env=dict(os.environ,GC_TEST_EXPECT_REVOKED="true" if revoked else "false")
                    result=subprocess.run(["dotnet",recovery_dll,"--fleet-recovery-fixture",mode,str(temp),
                        str(good_cert),str(good_key),str(temp/"server.pem"),
                        str(recovery_ports[0]),str(recovery_ports[1]),str(journal_path)],
                        check=True,capture_output=True,text=True,timeout=35,env=invoke_env)
                    print(result.stdout,flush=True)
                    return result.stdout
                root_installed=False
                client_installed=False
                try:
                    if windows_root_pin:
                        # Mark before installing so cleanup is attempted even if
                        # the provisioning subprocess fails after changing trust.
                        root_installed=True
                        invoke("install-root")
                    start_node(0);start_node(1)
                    if os.name == "nt":
                        invoke("prepare")
                        stop_node(1)
                        if "FLEET_RECOVERY_PARTIAL" not in invoke("recover"):
                            raise AssertionError("expected partial recovery while second agent unavailable")
                        start_node(1)
                        if "FLEET_RECOVERY_COMPLETE" not in invoke("recover"):
                            raise AssertionError("expected resumed verified recovery")
                        print("PASS: Windows production-chain mutating fleet recovery completed",flush=True)
                    else:
                        # Exercise the shipping controller, not just its shared
                        # recovery helper. Signed prepares simulate a lost ACK;
                        # controller restart consumes the persisted journal.
                        import json
                        from unittest.mock import patch
                        sys.path.insert(0,str(REPO/"tests"/"E2E"))
                        from real_control_center import Client, gateway, openssl_state, backend, check
                        cwd=REPO/"control-center"
                        dll=commercial_gateway if commercial else cwd/"bin/Release/net10.0/GatewayCoreYarp.dll"
                        client_installed=True
                        invoke("install-client")
                        with patch.dict(os.environ,{"SSL_CERT_FILE":str(temp/"root.pem")}), backend() as upstream:
                            openssl_state(controller_root,upstream)
                            if commercial:
                                # Same customer SDK, but an independent third installation.
                                controller_identity=controller_root/"state"/"commercial-license"
                                command(commercial_agent,"--license-init",env=dict(os.environ,GATEWAYCORE_ENGINE_LICENSE_DIR=str(controller_identity)))
                                controller_request=controller_root/"activation.gcr"
                                signing_key=controller_root/"state"/"fleet-signing-private.pem"
                                shutil.copyfile(temp/"fleet-private.pem",signing_key)
                                signing_key.chmod(0o600)
                            node_rows=[{"id":name,"url":f"https://127.0.0.1:{recovery_ports[i]}/",
                                "clientCertificateThumbprint":pins[0]} for i,name in enumerate(("one","two"))]
                            plan={"mode":"ha-pair","controlPlane":"single-controller","dataStore":"local-file",
                                "accessPattern":"segmented","publicVip":"fixture-vip.example.invalid",
                                "upstreamHealthAware":True,"requireIndependentApproval":True,
                                "gateways":[{"id":row["id"],"hostname":f"gateway-{i}.example.invalid","agentUrl":row["url"]}
                                    for i,row in enumerate(node_rows)],
                                "workloads":[{"id":name,"application":"fixture","zone":"restricted","hostingEngine":"http",
                                    "url":f"http://127.0.0.1:{upstream}/"} for name in ("origin-a","origin-b")]}
                            with gateway(cwd,dll,controller_root,free_port()) as base:
                                admin=Client(base)
                                admin.bootstrap("fleetadmin","Disposable-fleet-admin-123!","fleetadmin@example.invalid")
                                if commercial:
                                    controller_request.write_text(admin.request("GET","/admin/api/license/request")["file"],encoding="ascii")
                                    envelope=controller_root/"active.lic"
                                    command(fixture,"--ci-fleet-three-license",keys,controller_request,envelope,"dc")
                                    active=admin.request("POST","/admin/api/license/import",{"file":envelope.read_text(encoding="ascii")})
                                    check(active["active"] and active["maxNodes"]==3,"independent commercial controller allocation")
                                    admin.request("POST","/admin/api/users",{"username":"fleetreviewer",
                                        "password":"Disposable-reviewer-123!","email":"fleetreviewer@example.invalid","role":"Administrator"})
                                admin.request("POST","/admin/api/users",{"username":"fleetoperator",
                                    "password":"Disposable-fleet-operator-123!","email":"fleetoperator@example.invalid","role":"Operator"})
                                topology=admin.request("GET","/admin/api/onboarding")
                                check(admin.request("POST","/admin/api/onboarding/validate",{"plan":plan})["issues"]==[],
                                      "recovery fixture topology validates")
                                for confirmed in (False,True):
                                    topology=admin.request("POST","/admin/api/onboarding",{"plan":plan,
                                        "confirmDesign":confirmed,"expectedRevision":topology["revision"]})
                                for row in node_rows:
                                    admin.request("POST","/admin/api/fleet",row)
                                if commercial:
                                    if os.environ.get("GC_FLEET_QUORUM_MEMBER_CONTAINERS"):invoke("reject-unfenced")
                                    reviewer=Client(base);reviewer.login("fleetreviewer","Disposable-reviewer-123!")
                                    state=admin.request("GET","/admin/api/state")
                                    payload={name:state[name] for name in ("routes","clusters","disabled","revision")}
                                    payload["routes"]["commercial-rollout"]={"ClusterId":"fixture","Match":{"Path":"/commercial-rollout/{**catch-all}"}}
                                    change=admin.request("POST","/admin/api/change-requests",{"reason":"Disposable commercial licensed fleet rollout","payload":payload})
                                    reviewer.request("POST","/admin/api/change-requests/"+change["id"]+"/decision",
                                        {"decision":"approve","reason":"Independently approved commercial acceptance"})
                                    if os.environ.get("GC_FLEET_QUORUM_MEMBER_CONTAINERS"):
                                        qfixture=os.environ["GC_FLEET_QUORUM_DLL"]
                                        qconfig=os.environ["GATEWAYCORE_FLEET_QUORUM_CONFIG"]
                                        competitor="rollout_"+"E"*24
                                        competing_epoch=command(qfixture,"acquire",qconfig,competitor,"0").strip()
                                        originals=[(temp/f"recovery-node-{i}"/"gateway.json").read_bytes() for i in range(2)]
                                        try:
                                            admin.request("POST","/admin/api/fleet/rollout/"+change["id"],{},expect=409)
                                            check(all((temp/f"recovery-node-{i}"/"gateway.json").read_bytes()==originals[i] for i in range(2)),
                                                "real competing controller cannot dispatch mutation")
                                            rows=admin.request("GET","/admin/api/fleet/rollouts")
                                            check(any(row["status"]=="rollback-verified" and all(not target["prepareSent"] for target in row["targets"])
                                                      for row in rows),"definite CAS loss leaves no unresolved mutation")
                                        finally:
                                            command(qfixture,"release",qconfig,competitor,competing_epoch)
                                    rollout=admin.request("POST","/admin/api/fleet/rollout/"+change["id"],{})
                                    check(rollout["status"]=="activated-pending-health-validation","actual commercial controller rollout validates all licensed sites and activates")
                                    for i in range(2):
                                        config=json.loads((temp/f"recovery-node-{i}"/"gateway.json").read_bytes())
                                        check("commercial-rollout" in config["ReverseProxy"]["Routes"],"actual licensed agent config activated")
                                invoke("prepare")
                                if commercial and os.environ.get("GC_FLEET_QUORUM_MEMBER_CONTAINERS"):
                                    members=json.loads(os.environ["GC_FLEET_QUORUM_MEMBER_CONTAINERS"])
                                    if len(members)!=3 or any(not name.startswith("gc-fleet-raft-") for name in members):
                                        raise AssertionError("Expected only disposable CI Raft members")
                                    paused=[]
                                    try:
                                        for name in members[1:]:
                                            subprocess.run(["docker","pause",name],check=True,timeout=15)
                                            paused.append(name)
                                        invoke("reject-partition")
                                    finally:
                                        for name in paused:
                                            subprocess.run(["docker","unpause",name],check=True,timeout=15)
                                    # Allow the real Raft majority to elect/reconnect before recovery.
                                    time.sleep(5)
                                if commercial:
                                    revocation=controller_root/"revoked.gcv"
                                    command(fixture,"--ci-engine-revoke",keys,controller_request,revocation,"fleet")
                                    revoked=admin.request("POST","/admin/api/license/revoke",{"file":revocation.read_text(encoding="ascii")})
                                    check(revoked["state"]=="revoked","controller revoked during interrupted transaction")
                            if commercial:
                                revoke_node(0);revoke_node(1)
                                start_node(0)
                            else:
                                stop_node(1)
                            endpoint="/admin/api/fleet/rollouts/"+journal_path.stem+"/recover"
                            with gateway(cwd,dll,controller_root,free_port()) as base:
                                admin=Client(base);admin.login("fleetadmin","Disposable-fleet-admin-123!")
                                operator=Client(base);operator.login("fleetoperator","Disposable-fleet-operator-123!")
                                before=journal_path.read_bytes()
                                Client(base).request("POST",endpoint,{},expect=401)
                                operator.request("POST",endpoint,{},expect=403)
                                admin.request("POST",endpoint,{},csrf=False,expect=403)
                                check(journal_path.read_bytes()==before,"unauthenticated, unauthorized and missing-CSRF recovery leave journal unchanged")
                                admin.request("DELETE","/admin/api/fleet/two",expect=402 if commercial else 409)
                                admin.request("POST",endpoint,{},expect=502)
                                state=json.loads(journal_path.read_bytes())
                                check(state["status"]=="manual-intervention-required" and
                                      state["targets"][0]["rollbackVerified"] and not state["targets"][1]["rollbackVerified"],
                                      "real controller API records partial recovery and preserves unresolved target")
                            start_node(1)
                            with gateway(cwd,dll,controller_root,free_port()) as base:
                                admin=Client(base);admin.login("fleetadmin","Disposable-fleet-admin-123!")
                                restored=admin.request("POST",endpoint,{})
                                check(restored["status"]=="rollback-verified","real controller API resumes recovery after restart")
                                admin.request("POST",endpoint,{},expect=409)
                                if "FLEET_RECOVERY_COMPLETE" not in invoke("verify",revoked=bool(commercial)):
                                    raise AssertionError("expected independent original revision and late-activation proof")
                                if commercial:
                                    admin.request("GET","/admin/api/state",expect=402)
                                    check(admin.request("GET","/admin/api/license/status")["state"]=="revoked",
                                        "recovery does not reactivate controller")
                            print("PASS: real controller HTTP recovery with RBAC, CSRF, restart and production mTLS",flush=True)
                            if commercial:print("COMMERCIAL_REAL_ROLLOUT_AND_REVOKED_RECOVERY_PASS",flush=True)
                finally:
                    try:
                        for i in range(2): stop_node(i)
                        for stream in streams: stream.close()
                        if client_installed: invoke("remove-client")
                    finally:
                        if root_installed:
                            invoke("remove-root")
            else:
                print("NOTICE: mutating fleet recovery requires a disposable GitHub Actions runner",flush=True)

            # Windows caches CRLs by issuer. Use a distinct one-use CA and agent
            # for the outage case so the good CRL above cannot satisfy it from cache.
            offline_dir = temp / "offline"
            offline_dir.mkdir()
            (offline_dir / "index.txt").write_text("", encoding="ascii")
            (offline_dir / "serial").write_text("3000\n", encoding="ascii")
            offline_config = offline_dir / "ca.cnf"
            offline_config.write_text(f"""[ ca ]
default_ca = CA_default
[ CA_default ]
database = {openssl_config_path(offline_dir / 'index.txt')}
new_certs_dir = {openssl_config_path(offline_dir)}
certificate = {openssl_config_path(offline_dir / 'root.pem')}
private_key = {openssl_config_path(offline_dir / 'root.key')}
serial = {openssl_config_path(offline_dir / 'serial')}
default_md = sha256
default_days = 2
policy = policy
copy_extensions = copy
[ policy ]
commonName = supplied
[ offline_client_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
crlDistributionPoints = URI:http://127.0.0.1:{dead_port}/crl.pem
""", encoding="ascii")
            run(openssl, "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048",
                "-sha256", "-days", "2", "-subj", "/CN=GatewayCore offline disposable root",
                "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-addext", "subjectKeyIdentifier=hash",
                "-addext", "authorityKeyIdentifier=keyid:always,issuer",
                "-keyout", str(offline_dir / "root.key"), "-out", str(offline_dir / "root.pem"))
            offline_key = offline_dir / "offline-controller.key"
            offline_csr = offline_dir / "offline-controller.csr"
            offline_cert = offline_dir / "offline-controller.pem"
            run(openssl, "req", "-new", "-nodes", "-newkey", "rsa:2048", "-sha256",
                "-subj", "/CN=offline-controller", "-keyout", str(offline_key), "-out", str(offline_csr))
            run(openssl, "ca", "-batch", "-config", str(offline_config),
                "-extensions", "offline_client_cert", "-in", str(offline_csr), "-out", str(offline_cert))
            offline_pin = run(openssl, "x509", "-in", str(offline_cert), "-noout", "-fingerprint", "-sha1").split("=", 1)[1].replace(":", "").strip()
            offline_port = free_port()
            offline_env = env.copy()
            offline_env["Kestrel__Endpoints__AgentHttps__Url"] = f"https://127.0.0.1:{offline_port}"
            offline_env["Agent__TrustedClientThumbprints__0"] = offline_pin
            # Let the isolated production-mode Linux chain trust this second CA
            # so it must evaluate its dead CRL DP rather than stopping at
            # PartialChain. The Python client explicitly trusts the main CA for
            # the HTTPS server certificate, independent of this child setting.
            offline_env["SSL_CERT_FILE"] = str(offline_dir / "root.pem")
            for key in tuple(offline_env):
                if key.startswith("Agent__TrustedClientThumbprints__") and key != "Agent__TrustedClientThumbprints__0":
                    del offline_env[key]
            if os.name == "nt":
                offline_env["Agent__LabOnlyClientCaCertificatePath"] = str(offline_dir / "root.pem")
            offline_log = temp / "gateway-agent-offline-crl.log"
            with offline_log.open("w", encoding="utf-8") as stream:
                offline_process = subprocess.Popen(["dotnet", str(AGENT)], cwd=temp, env=offline_env,
                                                   stdout=stream, stderr=subprocess.STDOUT, text=True)
                offline_terminated_by_test = False
                try:
                    wait_for_listener(offline_port, offline_process, "offline-CRL GatewayAgent")
                    require_no_http_response(offline_port, offline_cert, offline_key, temp / "root.pem",
                                             "an unavailable CRL endpoint from an uncached CA")
                finally:
                    offline_terminated_by_test = offline_process.poll() is None
                    offline_process.terminate()
                    try:
                        offline_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        offline_process.kill()
                        offline_process.wait(timeout=3)
                if not was_stopped_by_test(offline_process.returncode, offline_terminated_by_test):
                    raise RuntimeError(f"offline-CRL GatewayAgent exited {offline_process.returncode}; logs:\n"
                                       + offline_log.read_text(encoding="utf-8", errors="replace"))
            offline_logs = offline_log.read_text(encoding="utf-8", errors="replace")
            rejection_prefix = ("Rejected lab TLS client certificate " if os.name == "nt"
                                else "Rejected TLS client certificate ")
            if f"{rejection_prefix}{offline_pin}" not in offline_logs or not any(
                    status in offline_logs for status in ("OfflineRevocation", "RevocationStatusUnknown")):
                raise AssertionError("unavailable CRL was not logged as a client-chain rejection:\n" + offline_logs)
            print("PASS: production chain rejects an unavailable CRL from a separate uncached test CA", flush=True)
            # Keep OCSP in a separate two-tier CA fixture so an OCSP cache or
            # the preceding CRL responder cannot satisfy the wrong check.
            ocsp_env = os.environ.copy()
            ocsp_env["GATEWAY_TEST_OPENSSL"] = openssl
            subprocess.run(
                [sys.executable,
                 str(Path(__file__).with_name("agent_ocsp_acceptance.py"))],
                check=True, timeout=180, env=ocsp_env,
            )
            # Independently exercise the root-issued CRL for an intermediate.
            # The leaf's own issuer CRL is clean, so rejection must be due to
            # the revoked non-root CA in the presented peer chain.
            subprocess.run(
                [sys.executable,
                 str(Path(__file__).with_name("agent_intermediate_crl_acceptance.py"))],
                check=True, timeout=180, env=ocsp_env,
            )
        finally:
            crl_server.shutdown()
            crl_server.server_close()
            crl_thread.join(timeout=2)


if __name__ == "__main__":
    main()
