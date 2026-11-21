"""Disposable multi-process acceptance for mTLS signed async health reports."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import select
import tempfile
import threading
import time
import urllib.request
import urllib.error


class Ready(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(self.server.verdict)
        self.end_headers()

    def log_message(self, *_args):
        pass


class FenceProxy:
    """Disposable TCP hop that can partition authority TLS while DNS stays live."""
    def __init__(self, target_port):
        self.target_port = target_port
        self.blocked = False
        self.stopping = False
        self.lock = threading.Lock()
        self.active = set()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while not self.stopping:
            try:
                client, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self.blocked:
                client.close()
                continue
            threading.Thread(target=self._relay, args=(client,), daemon=True).start()

    def _relay(self, client):
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            remote.settimeout(2)
            remote.connect(("127.0.0.1", self.target_port))
            remote.settimeout(None)
            with self.lock:
                if self.blocked or self.stopping:
                    return
                self.active.update((client, remote))
            sockets = (client, remote)
            while not self.stopping:
                readable, _, _ = select.select(sockets, [], [], .2)
                if not readable:
                    continue
                for source in readable:
                    data = source.recv(16384)
                    if not data:
                        return
                    destination = remote if source is client else client
                    destination.sendall(data)
        except OSError:
            pass
        finally:
            with self.lock:
                self.active.discard(client)
                self.active.discard(remote)
            client.close()
            remote.close()

    def partition(self):
        self.blocked = True
        with self.lock:
            active = list(self.active)
            self.active.clear()
        for stream in active:
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            stream.close()

    def restore(self):
        self.blocked = False

    def close(self):
        self.stopping = True
        try:
            self.listener.close()
        except OSError:
            pass
        self.partition()
        self.thread.join(timeout=2)


def serve(stack):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Ready)
    server.verdict = 200
    stack.callback(server.server_close)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    stack.callback(server.shutdown)
    return server


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def secure_windows_test_directory(path: Path) -> None:
    """Give replay-state fixtures a private inherited ACL on Windows runners."""
    if os.name != "nt":
        return
    username = os.environ.get("USERNAME")
    if not username:
        raise AssertionError("Windows runner identity is unavailable for replay-state ACL fixture")
    subprocess.run([
        "icacls", str(path), "/inheritance:r", "/grant:r",
        f"{username}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F"
    ], check=True, capture_output=True, text=True)


def scrape_metrics(metrics_port):
    with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=2) as response:
        return response.read().decode("utf-8")


def wait_for_metrics(metrics_port, required_lines, timeout=6):
    """Wait for asynchronous observer evidence before asserting its DNS effect."""
    deadline = time.monotonic() + timeout
    last_metrics = ""
    while time.monotonic() < deadline:
        last_metrics = scrape_metrics(metrics_port)
        if all(line in last_metrics.splitlines() for line in required_lines):
            return last_metrics
        time.sleep(.1)
    missing = [line for line in required_lines if line not in last_metrics.splitlines()]
    raise AssertionError(
        f"timed out waiting for report metrics on port {metrics_port}; "
        f"missing={missing!r}\nlast scrape:\n{last_metrics}")


def scrape_agent_status(metrics_port):
    with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/agent-report-status", timeout=2) as response:
        return json.loads(response.read().decode("utf-8"))


def reject_malformed_agent_report(authority, agent, ca_path):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(str(agent["cert"]), str(agent["key"]))
    request = urllib.request.Request(
        f"https://127.0.0.1:{authority['report_port']}/agent-health/v1/reports",
        data=b"{malformed-json", headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(request, context=context, timeout=3)
    except urllib.error.HTTPError as error:
        assert error.code == 400, f"malformed signed report returned {error.code}, expected 400"
    else:
        raise AssertionError("malformed signed report was accepted")


def reject_agent_report_frame(authority, agent, ca_path, body, expected_status, label):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(str(agent["cert"]), str(agent["key"]))
    request = urllib.request.Request(
        f"https://127.0.0.1:{authority['report_port']}/agent-health/v1/reports",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        response = urllib.request.urlopen(request, context=context, timeout=3)
    except urllib.error.HTTPError as error:
        assert error.code == expected_status, \
            f"{label} returned {error.code}, expected {expected_status}"
    else:
        response.close()
        raise AssertionError(f"{label} was accepted")


def reject_authority_fence_frame(target_port, client_identity, ca_path, body, expected_status, label):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(str(client_identity["cert"]), str(client_identity["key"]))
    request = urllib.request.Request(
        f"https://127.0.0.1:{target_port}/authority-fence/v1/snapshot",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        response = urllib.request.urlopen(request, context=context, timeout=3)
    except urllib.error.HTTPError as error:
        assert error.code == expected_status, \
            f"{label} returned {error.code}, expected {expected_status}"
    else:
        response.close()
        raise AssertionError(f"{label} was accepted")


def post_agent_report_status(authority, agent, ca_path, body):
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(str(agent["cert"]), str(agent["key"]))
    request = urllib.request.Request(
        f"https://127.0.0.1:{authority['report_port']}/agent-health/v1/reports",
        data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, context=context, timeout=3) as response:
            return response.status
    except urllib.error.HTTPError as error:
        error.close()
        return error.code


def signed_report_frame(agent, sequence, epoch):
    observed = int(time.time())
    der = subprocess.run(["openssl", "pkey", "-pubin", "-in", str(agent["public"]),
                          "-outform", "DER"], check=True, capture_output=True).stdout
    key_id = hashlib.sha256(der).hexdigest().upper()
    report = {
        "Version": 1, "AgentId": agent["id"], "KeyId": key_id,
        "Zone": "lab.example.test", "SiteId": "mumbai", "Epoch": epoch,
        "Sequence": sequence, "ObservedAtUnixSeconds": observed,
        "ExpiresAtUnixSeconds": observed + 8, "ProbeType": "http",
        "Verdict": "healthy", "ConfidencePermille": 1000,
        "LatencyMilliseconds": 23, "Signature": "",
    }
    canonical = "\n".join((
        "GatewayCore.AgentHealth.v1", report["AgentId"], key_id,
        "lab.example.test", "mumbai", str(epoch), str(sequence), str(observed),
        str(observed + 8), "http", "healthy", "1000", "23"))
    signature = subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(agent["signer"])],
                               input=canonical.encode(), check=True, capture_output=True).stdout
    report["Signature"] = __import__("base64").b64encode(signature).decode("ascii")
    return json.dumps(report, separators=(",", ":"))


def dns_query(dns_port):
    labels = b"".join(bytes([len(label)]) + label for label in (b"lab", b"example", b"test")) + b"\0"
    packet = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(.5)
        udp.sendto(packet, ("127.0.0.1", dns_port))
        answer, _ = udp.recvfrom(2048)
    rcode = answer[3] & 15
    address = ".".join(str(octet) for octet in answer[-4:]) if rcode == 0 else None
    return rcode, address


def expect_dns(process, dns_port, wanted_rcode, wanted_address=None, timeout=12, log_paths=()):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            logs = "\n".join(f"--- {path.name} ---\n{path.read_text(errors='replace')[-3000:]}"
                              for path in log_paths if path.exists())
            raise AssertionError(f"DNS process exited {process.returncode}\n{logs}")
        try:
            last = dns_query(dns_port)
            if last[0] == wanted_rcode and (wanted_address is None or last[1] == wanted_address):
                return
        except (OSError, TimeoutError):
            pass
        time.sleep(.15)
    logs = "\n".join(f"--- {path.name} ---\n{path.read_text(errors='replace')[-3000:]}"
                      for path in log_paths if path.exists())
    raise AssertionError(f"DNS result {last}, expected rcode={wanted_rcode}, address={wanted_address}\n{logs}")


def main():
    dns_dll = Path("engines/GslbDns/bin/Release/net10.0/GslbDns.dll").resolve()
    observer_dll = Path("engines/GslbObserver/bin/Release/net10.0/GslbObserver.dll").resolve()
    with tempfile.TemporaryDirectory() as tmp, contextlib.ExitStack() as stack:
        root = Path(tmp)
        secure_windows_test_directory(root)

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)

        openssl("req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                "-subj", "/CN=Disposable report CA", "-keyout", "ca.key", "-out", "ca.pem")

        def issue(role, usage, san="IP:127.0.0.1"):
            key = root / f"{role}.key"
            csr = root / f"{role}.csr"
            cert = root / f"{role}.pem"
            ext = root / f"{role}.ext"
            openssl("req", "-new", "-nodes", "-newkey", "rsa:2048", "-subj", "/CN=" + role,
                    "-keyout", str(key), "-out", str(csr))
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                           "extendedKeyUsage=" + usage + "\nsubjectAltName=" + san + "\n")
            openssl("x509", "-req", "-in", str(csr), "-CA", "ca.pem", "-CAkey", "ca.key",
                    "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", str(cert))
            return cert, key

        dns_cert, dns_key = issue("dns-report", "serverAuth")
        server_cert, server_key = issue("observer-server", "serverAuth")
        authorities_identity = {}
        for node in ("a", "b"):
            cert, key = issue(f"authority-{node}", "serverAuth,clientAuth")
            public_key = root / f"authority-{node}-signing.pub"
            signer = root / f"authority-{node}-signing.key"
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(signer))
            openssl("pkey", "-in", str(signer), "-pubout", "-out", str(public_key))
            der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                                 capture_output=True, check=True).stdout
            authorities_identity[node] = {
                "cert": cert, "key": key, "signer": signer, "public": public_key,
                "pin": hashlib.sha256(der).hexdigest().upper()
            }
        agents = []
        for agent_id, vantage_group in (("agent-1", "vantage-mumbai"),
                                        ("agent-2", "vantage-osaka"),
                                        ("agent-3", "vantage-singapore")):
            cert, key = issue(agent_id, "clientAuth")
            public_key = root / f"{agent_id}-signing.pub"
            signer = root / f"{agent_id}-signing.key"
            openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(signer))
            openssl("pkey", "-in", str(signer), "-pubout", "-out", str(public_key))
            der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                                 capture_output=True, check=True).stdout
            agents.append({"id": agent_id, "vantage_group": vantage_group,
                           "cert": cert, "key": key, "signer": signer,
                           "public": public_key, "pin": hashlib.sha256(der).hexdigest().upper()})

        # A fourth, non-quorum test identity exercises one-process fan-out to
        # both authorities without changing the existing partition assertions.
        cert, key = issue("agent-fanout", "clientAuth")
        public_key = root / "agent-fanout-signing.pub"
        signer = root / "agent-fanout-signing.key"
        openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(signer))
        openssl("pkey", "-in", str(signer), "-pubout", "-out", str(public_key))
        der = subprocess.run(["openssl", "x509", "-in", str(cert), "-outform", "DER"],
                             capture_output=True, check=True).stdout
        fanout_agent = {"id": "agent-fanout", "vantage_group": "vantage-fanout",
                        "cert": cert, "key": key, "signer": signer,
                        "public": public_key, "pin": hashlib.sha256(der).hexdigest().upper(),
                        "upstream": serve(stack)}

        if os.name != "nt":
            def reject_observer_config(name, document, reason, expected_error):
                invalid_config = root / f"{name}.json"
                invalid_config.write_text(json.dumps(document))
                denied = subprocess.run(["dotnet", observer_dll, invalid_config],
                                         capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0 and expected_error in denied.stderr, \
                    f"observer did not reject {reason} through private-key file security; " \
                    f"exit={denied.returncode}, stdout={denied.stdout[-1000:]}, stderr={denied.stderr[-2000:]}"
                print(f"PASS: observer refuses {reason}")

            insecure_observer_key = root / "insecure-observer-signing.key"
            shutil.copyfile(agents[0]["signer"], insecure_observer_key)
            insecure_observer_key.chmod(0o644)
            observer_config = {
                "ListenAddress": "127.0.0.1", "Port": port(),
                "PublicUrl": "https://127.0.0.1:18443/ready",
                "HealthUrl": "http://127.0.0.1:1/ready",
                "ServerCertificatePem": str(server_cert), "ServerKeyPem": str(server_key),
                "SigningKeyPem": str(insecure_observer_key),
                "AllowedClientSha256": [agents[0]["pin"]]
            }
            invalid_config = root / "insecure-observer.json"
            invalid_config.write_text(json.dumps(observer_config))
            denied = subprocess.run(["dotnet", observer_dll, invalid_config],
                                     capture_output=True, text=True, timeout=10)
            assert denied.returncode != 0 and "group/other access" in denied.stderr, \
                "observer accepted a group-readable report-signing key"
            print("PASS: observer refuses group-readable report-signing private keys")

            observer_key_link = root / "observer-server-link.key"
            observer_key_link.symlink_to(server_key)
            linked_server_config = dict(observer_config, ServerKeyPem=str(observer_key_link))
            reject_observer_config("linked-observer-server", linked_server_config,
                                   "a symlinked TLS private key", "without following links")

            signing_key_link = root / "observer-signing-link.key"
            signing_key_link.symlink_to(agents[0]["signer"])
            linked_signing_config = dict(observer_config, SigningKeyPem=str(signing_key_link))
            reject_observer_config("linked-observer-signing", linked_signing_config,
                                   "a symlinked report-signing private key", "without following links")

            linked_key_directory = root / "observer-key-directory-link"
            linked_key_directory.symlink_to(root, target_is_directory=True)
            linked_parent_config = dict(observer_config,
                                        SigningKeyPem=str(linked_key_directory / agents[0]["signer"].name))
            reject_observer_config("linked-observer-key-parent", linked_parent_config,
                                   "a key path with a symlinked parent directory", "without following links")

            unsafe_key_directory = Path(tempfile.mkdtemp(prefix="gslb-observer-unsafe-key-parent-"))
            stack.callback(shutil.rmtree, unsafe_key_directory, ignore_errors=True)
            unsafe_key_directory.chmod(0o777)
            unsafe_parent_key = unsafe_key_directory / "signing.key"
            shutil.copyfile(agents[0]["signer"], unsafe_parent_key)
            unsafe_parent_key.chmod(0o600)
            replacement_key = unsafe_key_directory / "replacement.key"
            shutil.copyfile(agents[1]["signer"], replacement_key)
            replacement_key.chmod(0o600)
            os.replace(replacement_key, unsafe_parent_key)
            unsafe_parent_config = dict(observer_config, SigningKeyPem=str(unsafe_parent_key))
            reject_observer_config("unsafe-observer-key-parent", unsafe_parent_config,
                                   "a replaced key under a group/other-writable parent", "group/other writes")

            report_client_key_link = root / "observer-report-client-link.key"
            report_client_key_link.symlink_to(agents[0]["key"])
            linked_client_config = dict(observer_config)
            linked_client_config.update({
                "SigningKeyPem": str(agents[0]["signer"]),
                "ReportUrl": "https://127.0.0.1:18443/agent-health/v1/reports",
                "AgentId": "agent-1", "Zone": "lab.example.test", "SiteId": "mumbai",
                "ReportClientCertificatePem": str(agents[0]["cert"]),
                "ReportClientKeyPem": str(report_client_key_link),
                "ReportServerCaPem": str(root / "ca.pem"),
                "ReportServerRevocationMode": "NoCheck",
                "ReportSequenceStatePath": str(root / "observer-sequence.json"),
                "ReportIntervalSeconds": 1, "ReportTtlSeconds": 8
            })
            reject_observer_config("linked-observer-report-client", linked_client_config,
                                   "a symlinked report-client TLS private key", "without following links")

            unsafe_sequence_parent = Path(tempfile.mkdtemp(prefix="gslb-observer-unsafe-sequence-parent-"))
            stack.callback(shutil.rmtree, unsafe_sequence_parent, ignore_errors=True)
            unsafe_sequence_parent.chmod(0o777)
            sequence_directory = unsafe_sequence_parent / "state"
            sequence_directory.mkdir()
            sequence_directory.chmod(0o700)
            replacement_directory = unsafe_sequence_parent / "replacement"
            replacement_directory.mkdir()
            replacement_directory.chmod(0o700)
            sequence_directory.rename(unsafe_sequence_parent / "state-original")
            replacement_directory.rename(sequence_directory)
            unsafe_sequence_config = dict(linked_client_config)
            unsafe_sequence_config.update({
                "Port": port(),
                "ReportClientKeyPem": str(agents[0]["key"]),
                "ReportSequenceStatePath": str(sequence_directory / "sequence.json")
            })
            reject_observer_config("unsafe-observer-sequence-parent", unsafe_sequence_config,
                                   "sequence state below a replaceable writable ancestor", "group/other writes")

        local = serve(stack)
        for agent in agents:
            agent["upstream"] = serve(stack)

        authorities = {}
        authority_fence_ports = {node: port() for node in ("a", "b")}
        fence_a_to_b = FenceProxy(authority_fence_ports["b"])
        fence_b_to_a = FenceProxy(authority_fence_ports["a"])
        stack.callback(fence_a_to_b.close)
        stack.callback(fence_b_to_a.close)
        for node in ("a", "b"):
            dns_port = port()
            report_port = port()
            metrics_port = port()
            report_config = {
                "ListenAddress": "127.0.0.1", "ListenPort": report_port,
                "AllowNonLoopbackListener": False,
                "ServerCertificatePem": str(dns_cert), "ServerKeyPem": str(dns_key),
                "ReplayStatePath": str(root / f"dns-{node}-replay-state.json"),
                "MaxTtlSeconds": 8, "MaxAgeSeconds": 6, "MaxClockSkewSeconds": 2,
                "MaxReportsPerMinute": 120, "RevokedCertificateSha256": [],
                "Agents": [{"AgentId": a["id"], "VantageGroup": a["vantage_group"],
                            "CertificateSha256": [a["pin"]],
                            "SigningPublicKeyPems": [str(a["public"])]}
                           for a in [*agents, fanout_agent]]
            }
            peer_node = "b" if node == "a" else "a"
            peer = authorities_identity[peer_node]
            local_authority = authorities_identity[node]
            fence_proxy = fence_a_to_b if node == "a" else fence_b_to_a
            fence_config = {
                "NodeId": f"authority-{node}",
                "ListenAddress": "127.0.0.1", "ListenPort": authority_fence_ports[node],
                "AllowNonLoopbackListener": False,
                "ServerCertificatePem": str(local_authority["cert"]),
                "ServerKeyPem": str(local_authority["key"]),
                "ClientCertificatePem": str(local_authority["cert"]),
                "ClientKeyPem": str(local_authority["key"]),
                "SigningPrivateKeyPem": str(local_authority["signer"]),
                "EpochStatePath": str(root / f"authority-{node}-epoch.json"),
                "ReplayStatePath": str(root / f"authority-{node}-peer-replay.json"),
                "LeaseSeconds": 5, "PublishIntervalSeconds": 1,
                "Peer": {
                    "NodeId": f"authority-{peer_node}",
                    "Endpoint": f"https://127.0.0.1:{fence_proxy.port}/authority-fence/v1/snapshot",
                    "AllowedAddress": "127.0.0.1", "AllowedPort": fence_proxy.port,
                    "ServerCertificateSha256": [peer["pin"]],
                    "ClientCertificateSha256": [peer["pin"]],
                    "SigningPublicKeyPem": str(peer["public"])
                }
            }
            config_document = {
                "ListenHost": "127.0.0.1", "ListenPort": dns_port,
                "MetricsListenHost": "127.0.0.1", "MetricsListenPort": metrics_port,
                "ProbeIntervalSeconds": 1, "AgentReports": report_config,
                "AuthorityFence": fence_config,
                "Zones": [{"Name": "lab.example.test", "TtlSeconds": 5,
                           "FailClosedWhenAllSitesDown": True,
                           "Sites": [{"Address": "192.0.2.17",
                                      "HealthUrl": f"http://127.0.0.1:{local.server_port}/ready",
                                      "Weight": 1, "AgentSiteId": "mumbai",
                                      "AuthorityFenceSiteId": "primary",
                                      "RequiredAgentIds": [a["id"] for a in agents],
                                      "MinimumHealthyAgentReports": 2}]}]
            }
            dns_config = root / f"zones-{node}.json"
            dns_config.write_text(json.dumps(config_document))
            if node == "a" and os.name != "nt":
                insecure_dns_key = root / "insecure-dns-report-server.key"
                shutil.copyfile(dns_key, insecure_dns_key)
                insecure_dns_key.chmod(0o644)
                invalid_config = json.loads(json.dumps(config_document))
                invalid_config["AgentReports"]["ServerKeyPem"] = str(insecure_dns_key)
                invalid_config["AgentReports"]["ListenPort"] = port()
                invalid_path = root / "insecure-dns-report-server.json"
                invalid_path.write_text(json.dumps(invalid_config))
                denied = subprocess.run(["dotnet", dns_dll, invalid_path],
                                         capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0 and "group/other access" in denied.stderr, \
                    "DNS authority accepted a group-readable report TLS private key"
                print("PASS: DNS authority refuses group-readable report TLS private keys")

                linked_dns_key = root / "dns-report-server-link.key"
                linked_dns_key.symlink_to(dns_key)
                linked_config = json.loads(json.dumps(config_document))
                linked_config["AgentReports"]["ServerKeyPem"] = str(linked_dns_key)
                linked_config["AgentReports"]["ListenPort"] = port()
                linked_path = root / "linked-dns-report-server.json"
                linked_path.write_text(json.dumps(linked_config))
                denied = subprocess.run(["dotnet", dns_dll, linked_path],
                                         capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0 and "links" in denied.stderr, \
                    "DNS authority accepted a symlinked report TLS private key"
                print("PASS: DNS authority refuses symlinked report TLS private keys")

                unsafe_dns_key_directory = Path(tempfile.mkdtemp(prefix="gslb-dns-unsafe-key-parent-"))
                stack.callback(shutil.rmtree, unsafe_dns_key_directory, ignore_errors=True)
                unsafe_dns_key_directory.chmod(0o777)
                unsafe_dns_key = unsafe_dns_key_directory / "server.key"
                shutil.copyfile(dns_key, unsafe_dns_key)
                unsafe_dns_key.chmod(0o600)
                unsafe_dns_config = json.loads(json.dumps(config_document))
                unsafe_dns_config["AgentReports"]["ServerKeyPem"] = str(unsafe_dns_key)
                unsafe_dns_config["AgentReports"]["ListenPort"] = port()
                unsafe_dns_path = root / "unsafe-dns-report-server.json"
                unsafe_dns_path.write_text(json.dumps(unsafe_dns_config))
                denied = subprocess.run(["dotnet", dns_dll, unsafe_dns_path],
                                         capture_output=True, text=True, timeout=10)
                assert denied.returncode != 0 and "group/other writes" in denied.stderr, \
                    "DNS authority accepted a key under a group/other-writable parent"
                print("PASS: DNS authority refuses keys under group/other-writable parents")
            dns_log = root / f"dns-{node}.log"
            dns_log_handle = dns_log.open("w")
            stack.callback(dns_log_handle.close)
            dns = subprocess.Popen(["dotnet", dns_dll, dns_config], stdout=dns_log_handle,
                                   stderr=subprocess.STDOUT)
            stack.callback(lambda process=dns: process.wait())
            stack.callback(lambda process=dns: process.kill() if process.poll() is None else None)
            expect_dns(dns, dns_port, 2, log_paths=[dns_log])
            authorities[node] = {"dns": dns, "dns_port": dns_port, "report_port": report_port,
                                 "metrics_port": metrics_port, "dns_log": dns_log,
                                 "dns_log_handle": dns_log_handle, "dns_config": dns_config,
                                 "processes": [], "agent_logs": []}

        def restart_authority(authority):
            old = authority["dns"]
            if old.poll() is None:
                old.terminate()
                old.wait(timeout=5)
            process = subprocess.Popen(["dotnet", dns_dll, authority["dns_config"]],
                                       stdout=authority["dns_log_handle"],
                                       stderr=subprocess.STDOUT)
            stack.callback(lambda current=process: current.wait())
            stack.callback(lambda current=process: current.kill() if current.poll() is None else None)
            authority["dns"] = process
            return process

        configs = []

        def start_agent(agent, node, report_nodes=None):
            authority = authorities[node]
            listen_port = port()
            origin = f"https://127.0.0.1:{listen_port}"
            conf = root / f"{agent['id']}-{node}.json"
            report_nodes = report_nodes or [node]
            report_targets = [
                f"https://127.0.0.1:{authorities[target]['report_port']}/agent-health/v1/reports"
                for target in report_nodes]
            report_config_fields = ({"ReportUrl": report_targets[0]} if len(report_targets) == 1
                                    else {"ReportUrls": report_targets})
            observer_config = {
                "ListenAddress": "127.0.0.1", "Port": listen_port,
                "PublicUrl": origin + "/ready",
                "HealthUrl": f"http://127.0.0.1:{agent['upstream'].server_port}/ready",
                "ServerCertificatePem": str(server_cert), "ServerKeyPem": str(server_key),
                "SigningKeyPem": str(agent["signer"]), "AllowedClientSha256": [agent["pin"]],
                "AgentId": agent["id"], "Zone": "lab.example.test", "SiteId": "mumbai",
                "ReportClientCertificatePem": str(agent["cert"]),
                "ReportClientKeyPem": str(agent["key"]), "ReportServerCaPem": str(root / "ca.pem"),
                "ReportServerRevocationMode": "NoCheck",
                "ReportSequenceStatePath": str(root / (agent["id"] + f"-{node}-sequence.json")),
                "ReportIntervalSeconds": 1, "ReportTtlSeconds": 8
            }
            observer_config.update(report_config_fields)
            conf.write_text(json.dumps(observer_config))
            configs.append(conf)
            log_path = root / f"{agent['id']}-{node}.log"
            authority["agent_logs"].append(log_path)
            log_handle = log_path.open("a")
            stack.callback(log_handle.close)
            process = subprocess.Popen(["dotnet", observer_dll, conf], stdout=log_handle,
                                       stderr=subprocess.STDOUT)
            authority["processes"].append(process)
            stack.callback(process.wait)
            stack.callback(process.kill)
            return process

        def restart_agents(authority, node):
            for process in authority["processes"]:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
            for agent in agents:
                start_agent(agent, node)

        for node in ("a", "b"):
            for agent in agents:
                start_agent(agent, node)
        for node, authority in authorities.items():
            expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17",
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        print("PASS: two independent DNS authorities each admit a site with fresh mTLS observer quorum")
        authority_a = authorities["a"]
        authority_b = authorities["b"]

        reject_agent_report_frame(authority_a, agents[0], root / "ca.pem",
                                  b'{"AgentId":"untrusted","AgentId":"agent-1"}', 400,
                                  "conflicting duplicate agent identity field")
        reject_agent_report_frame(authority_a, agents[0], root / "ca.pem",
                                  b" " * (8192 + 1), 413,
                                  "oversized agent report body")
        reject_authority_fence_frame(authority_fence_ports["b"], authorities_identity["a"],
                                     root / "ca.pem",
                                     b'{"Version":1,"Sequence":1,"Sequence":2}', 400,
                                     "duplicate authority snapshot field")
        reject_authority_fence_frame(authority_fence_ports["b"], authorities_identity["a"],
                                     root / "ca.pem", b" " * (131072 + 1), 413,
                                     "oversized authority snapshot body")
        print("PASS: real mTLS ingress rejects duplicate fields and oversized report/snapshot frames")

        # Both authorities have the same local and peer-positive decision before
        # the peer transport is partitioned; DNS remains reachable throughout.
        fence_a_to_b.partition()
        fence_b_to_a.partition()
        partition_started = time.monotonic()
        for authority_name, authority in (("authority A", authority_a), ("authority B", authority_b)):
            expect_dns(authority["dns"], authority["dns_port"], 2, timeout=9,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
            assert time.monotonic() - partition_started < 9, \
                f"{authority_name} did not fail closed within the bounded peer lease"
        print("PASS: inter-authority partition withdraws both DNS authorities within the peer lease")
        fence_a_to_b.restore()
        fence_b_to_a.restore()
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17", timeout=9,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        print("PASS: both authorities recover only after fresh matching peer snapshots")

        # Exercise both asymmetric directions separately. An authority with
        # incoming positive snapshots but no outbound acceptance must also fence.
        for direction, proxy in (("A to B", fence_a_to_b), ("B to A", fence_b_to_a)):
            proxy.partition()
            started = time.monotonic()
            for authority in (authority_a, authority_b):
                expect_dns(authority["dns"], authority["dns_port"], 2, timeout=9,
                           log_paths=[authority["dns_log"], *authority["agent_logs"]])
                assert time.monotonic() - started < 9, \
                    f"one-way {direction} partition did not fence both authorities"
            proxy.restore()
            for authority in (authority_a, authority_b):
                expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17", timeout=9,
                           log_paths=[authority["dns_log"], *authority["agent_logs"]])
            print(f"PASS: one-way {direction} peer partition fences both authorities and recovers")

        # Restart one authority while the other remains active. Its persisted
        # epoch advances, while the peer's durable replay high-water prevents
        # old authority decisions from being accepted after restart.
        restarted = restart_authority(authority_b)
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17", timeout=10,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        assert restarted.poll() is None
        print("PASS: restarted authority establishes a newer authenticated epoch and fresh peer lease")
        reject_malformed_agent_report(authority_a, agents[0], root / "ca.pem")
        status = scrape_agent_status(authority_a["metrics_port"])
        assert status["type"] == "loopback-gslb-agent-report-status"
        status_rows = status["agents"]
        assert len(status_rows) == 4 and [row["agentId"] for row in status_rows] == [
            "agent-1", "agent-2", "agent-3", "agent-fanout"]
        assert all(set(row) == {"agentId", "lastAcceptedUtc", "lastAcceptedAgeSeconds",
                                "rejectedTotal", "freshReports",
                                "staleOrMissingReports"} for row in status_rows), \
            "agent report status exposed fields outside the bounded privacy-safe contract"
        first_agent = status_rows[0]
        assert first_agent["rejectedTotal"] >= 1
        assert isinstance(first_agent["lastAcceptedUtc"], str) and \
            first_agent["lastAcceptedAgeSeconds"] >= 0 and first_agent["freshReports"] >= 1
        assert all(len(row["agentId"]) <= 64 for row in status_rows)
        print("PASS: loopback status exposes bounded IDs, last-accept age, freshness and rejected counters without private fields")
        metrics_text = scrape_metrics(authority_a["metrics_port"])
        accepted_line = 'gatewaycore_gslb_agent_reports_total{result="accepted"} '
        accepted_count = int(next(line[len(accepted_line):] for line in metrics_text.splitlines()
                                  if line.startswith(accepted_line)))
        # DNS admission proves the configured two-vantage quorum is present.
        # The third agent reports independently on a one-second cadence, so do
        # not make this metrics/privacy assertion depend on its scheduling.
        assert accepted_count >= 1, "authenticated mTLS report accepts were not exported"
        assert 'gatewaycore_gslb_agent_quorum_targets{state="quorum"} 1' in metrics_text
        healthy_line = 'gatewaycore_gslb_agent_evidence_reports{state="healthy"} '
        healthy_count = int(next(line[len(healthy_line):] for line in metrics_text.splitlines()
                                 if line.startswith(healthy_line)))
        assert healthy_count >= 2, "fresh healthy observer evidence was not exported"
        assert "lab.example.test" not in metrics_text and "192.0.2.17" not in metrics_text
        print("PASS: mTLS evidence, freshness and quorum metrics export without zone or backend labels")

        # Fresh positive reports cannot override a failed local application probe.
        # Keep the agents healthy and confirm their quorum is still present while
        # both independent authorities fail closed on the local readiness failure.
        local.verdict = 503
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 2,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        for authority_name, authority in (("authority A", authority_a), ("authority B", authority_b)):
            local_metrics = scrape_metrics(authority["metrics_port"])
            local_healthy_count = int(next(line[len(healthy_line):] for line in local_metrics.splitlines()
                                           if line.startswith(healthy_line)))
            assert local_healthy_count >= 2, \
                f"{authority_name} local readiness withdrawal was not tested with fresh healthy observer quorum"
            assert 'gatewaycore_gslb_agent_quorum_targets{state="quorum"} 1' in local_metrics, \
                f"{authority_name} did not retain an authenticated quorum during local readiness withdrawal"
        local.verdict = 200
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17",
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        print("PASS: fresh positive agent quorum cannot override local readiness failure on either authority")

        # A single process signs once and delivers the identical report ID to
        # two authorities. Verify each authority's own accepted counter advances.
        def accepted_reports(node):
            text = scrape_metrics(authorities[node]["metrics_port"])
            prefix = 'gatewaycore_gslb_agent_reports_total{result="accepted"} '
            return int(next(line[len(prefix):] for line in text.splitlines()
                            if line.startswith(prefix)))

        before = {node: accepted_reports(node) for node in ("a", "b")}
        fanout_process = start_agent(fanout_agent, "a", report_nodes=["a", "b"])
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and any(
                accepted_reports(node) <= before[node] for node in ("a", "b")):
            if fanout_process.poll() is not None:
                raise AssertionError(f"fan-out observer exited {fanout_process.returncode}")
            time.sleep(.2)
        assert all(accepted_reports(node) > before[node] for node in ("a", "b")), \
            "both independent authorities did not accept the single observer's report"
        print("PASS: one observer process delivered an authenticated report accepted by both authorities")

        # One independent observer reports a real failure while the DNS node's
        # local readiness endpoint stays healthy; the quorum must withdraw it.
        agents[0]["upstream"].verdict = 503
        negative_lines = [
            'gatewaycore_gslb_agent_evidence_reports{state="unhealthy"} 1',
            'gatewaycore_gslb_agent_quorum_targets{state="quorum"} 0',
            'gatewaycore_gslb_agent_quorum_targets{state="below_quorum"} 1',
        ]
        # Reports are emitted asynchronously. Wait until each independent
        # authority has accepted the 503 verdict before attributing DNS
        # withdrawal to agent evidence (SERVFAIL can also be caused by fencing).
        for authority in (authority_a, authority_b):
            wait_for_metrics(authority["metrics_port"], negative_lines)
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 2,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
            negative_metrics = scrape_metrics(authority["metrics_port"])
            assert all(line in negative_metrics.splitlines() for line in negative_lines), \
                f"negative report evidence/quorum changed before verification:\n{negative_metrics}"
        print("PASS: signed negative evidence withdraws the site without changing local probe health")
        agents[0]["upstream"].verdict = 200
        recovery_lines = [
            'gatewaycore_gslb_agent_evidence_reports{state="unhealthy"} 0',
            'gatewaycore_gslb_agent_quorum_targets{state="quorum"} 1',
            'gatewaycore_gslb_agent_quorum_targets{state="below_quorum"} 0',
        ]
        for authority in (authority_a, authority_b):
            wait_for_metrics(authority["metrics_port"], recovery_lines)
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 0, "192.0.2.17",
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])

        # Two of three independent groups remain sufficient when one reporter
        # disappears; one remaining group is below threshold and fails closed.
        processes_a = authority_a["processes"]
        processes_a[0].kill()
        processes_a[0].wait(timeout=5)
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17", timeout=12,
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        processes_a[1].kill()
        processes_a[1].wait(timeout=5)
        expect_dns(authority_a["dns"], authority_a["dns_port"], 2, timeout=12,
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        stale_metrics = scrape_metrics(authority_a["metrics_port"])
        assert 'gatewaycore_gslb_agent_evidence_reports{state="stale_or_missing"} 2' in stale_metrics
        stale_status = scrape_agent_status(authority_a["metrics_port"])
        stale_by_id = {row["agentId"]: row for row in stale_status["agents"]}
        assert stale_by_id["agent-1"]["staleOrMissingReports"] >= 1 and \
            stale_by_id["agent-2"]["staleOrMissingReports"] >= 1, \
            "per-agent stale counters did not reflect expired observer feeds"
        start_agent(agents[0], "a")
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: N-of-M tolerance, below-quorum fail-closed, durable epoch restart and recovery")

        # Simulate an observer-feed partition affecting only authority B. B's
        # local quorum failure propagates as a signed negative decision so A
        # also withdraws under the strict two-authority fence.
        processes_b = authority_b["processes"]
        for index in range(3):
            processes_b[index].kill()
            processes_b[index].wait(timeout=5)
        expect_dns(authority_b["dns"], authority_b["dns_port"], 2, timeout=12,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        expect_dns(authority_a["dns"], authority_a["dns_port"], 2,
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: loss of observer quorum at either authority fences both DNS authorities")
        start_agent(agents[0], "b")
        expect_dns(authority_b["dns"], authority_b["dns_port"], 2,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        start_agent(agents[1], "b")
        expect_dns(authority_b["dns"], authority_b["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: authority recovery waits for a fresh multi-vantage quorum")

        # Emergency leaf revocation is enforced at the TLS handshake on one
        # authority, preserves quorum fail-closed behavior, and can be rolled
        # back safely after removing the two denylisted pins.
        b_config = json.loads(authority_b["dns_config"].read_text())
        b_config["AgentReports"]["RevokedCertificateSha256"] = [
            agents[0]["pin"], agents[1]["pin"]]
        authority_b["dns_config"].write_text(json.dumps(b_config))
        restart_agents(authority_b, "b")
        revoked_dns = restart_authority(authority_b)
        restart_agents(authority_b, "b")
        expect_dns(revoked_dns, authority_b["dns_port"], 2, timeout=12,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        expect_dns(authority_a["dns"], authority_a["dns_port"], 2,
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: one authority's revoked observer quorum fails closed at both authorities")
        b_config["AgentReports"]["RevokedCertificateSha256"] = []
        authority_b["dns_config"].write_text(json.dumps(b_config))
        restart_agents(authority_b, "b")
        recovered_dns = restart_authority(authority_b)
        restart_agents(authority_b, "b")
        expect_dns(recovered_dns, authority_b["dns_port"], 0, "192.0.2.17", timeout=12,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17", timeout=12,
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: both authorities recover only after revocation is removed and fresh matching quorum returns")

        # At the actual mTLS HTTP boundary, use cryptographically valid frames
        # so duplicate-field rejection cannot pass because of a missing or bad
        # signature. The clean request must still be usable after both rejects.
        signer_agent = agents[0]
        sequence = 900_000_001
        epoch = 900_000_001
        valid = signed_report_frame(signer_agent, sequence, epoch)
        marker = f'"Sequence":{sequence}'
        assert marker in valid
        duplicate_before = valid.replace(marker,
            f'"sequence":{sequence + 1},{marker}', 1)
        duplicate_after = valid.replace(marker,
            f'{marker},"sequence":{sequence}', 1)
        assert post_agent_report_status(authority_b, signer_agent, root / "ca.pem",
                                        duplicate_before.encode()) == 400, \
            "valid signed report with conflicting case-alias before signed value was not rejected as duplicate"
        assert post_agent_report_status(authority_b, signer_agent, root / "ca.pem",
                                        duplicate_after.encode()) == 400, \
            "valid signed report with duplicate after signed value was not rejected"
        clean_status = post_agent_report_status(authority_b, signer_agent, root / "ca.pem", valid.encode())
        assert clean_status == 202, f"clean signed report returned HTTP {clean_status}, expected 202"
        assert post_agent_report_status(authority_b, signer_agent, root / "ca.pem",
                                        valid.encode()) == 400, \
            "replayed signed report was not rejected at the real mTLS HTTP boundary"
        print("PASS: mTLS report ingress rejects valid signed duplicate-field frames in both orders, accepts clean frame, rejects replay")

        # Last phase: eliminate background observer traffic and restart B with
        # a deliberately small quota so every request in the window is known.
        for authority in (authority_a, authority_b):
            for proc in authority["processes"]:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=5)
        b_config = json.loads(authority_b["dns_config"].read_text())
        b_config["AgentReports"]["MaxReportsPerMinute"] = 3
        authority_b["dns_config"].write_text(json.dumps(b_config))
        rate_dns = restart_authority(authority_b)
        deadline = time.monotonic() + 15
        while True:
            assert rate_dns.poll() is None, "rate-limit authority exited"
            try:
                with socket.create_connection(("127.0.0.1", authority_b["report_port"]), timeout=.5):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError("rate-limit authority HTTPS listener did not start")
                time.sleep(.1)
        for _ in range(3):
            assert post_agent_report_status(authority_b, agents[1], root / "ca.pem",
                                            b"{malformed-json") == 400
        assert post_agent_report_status(authority_b, agents[1], root / "ca.pem",
                                        b"{malformed-json") == 429, "malformed frames bypassed agent request budget"
        assert post_agent_report_status(authority_b, agents[2], root / "ca.pem",
                                        b"{malformed-json") == 400, "one observer exhausted another observer's budget"
        print("PASS: malformed authenticated reports consume only their own observer request budget")


if __name__ == "__main__":
    main()
