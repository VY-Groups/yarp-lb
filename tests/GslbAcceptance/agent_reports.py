"""Disposable multi-process acceptance for mTLS signed async health reports."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.request


class Ready(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(self.server.verdict)
        self.end_headers()

    def log_message(self, *_args):
        pass


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


def scrape_metrics(metrics_port):
    with urllib.request.urlopen(f"http://127.0.0.1:{metrics_port}/metrics", timeout=2) as response:
        return response.read().decode("utf-8")


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
            raise AssertionError(f"DNS process exited {process.returncode}")
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

        def openssl(*args):
            subprocess.run(["openssl", *args], cwd=root, check=True, capture_output=True)

        openssl("req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
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
                    f"observer did not reject {reason} through private-key file security"
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

            report_client_key_link = root / "observer-report-client-link.key"
            report_client_key_link.symlink_to(agents[0]["key"])
            linked_client_config = dict(observer_config)
            linked_client_config.update({
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

        local = serve(stack)
        for agent in agents:
            agent["upstream"] = serve(stack)

        authorities = {}
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
            config_document = {
                "ListenHost": "127.0.0.1", "ListenPort": dns_port,
                "MetricsListenHost": "127.0.0.1", "MetricsListenPort": metrics_port,
                "ProbeIntervalSeconds": 1, "AgentReports": report_config,
                "Zones": [{"Name": "lab.example.test", "TtlSeconds": 5,
                           "FailClosedWhenAllSitesDown": True,
                           "Sites": [{"Address": "192.0.2.17",
                                      "HealthUrl": f"http://127.0.0.1:{local.server_port}/ready",
                                      "Weight": 1, "AgentSiteId": "mumbai",
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
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 2,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
        negative_metrics = scrape_metrics(authority_a["metrics_port"])
        assert 'gatewaycore_gslb_agent_evidence_reports{state="unhealthy"} 1' in negative_metrics
        print("PASS: signed negative evidence withdraws the site without changing local probe health")
        agents[0]["upstream"].verdict = 200
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
        start_agent(agents[0], "a")
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: N-of-M tolerance, below-quorum fail-closed, durable epoch restart and recovery")

        # Simulate an observer-feed partition affecting only authority B. DNS
        # authority A keeps its fresh quorum; B withdraws when its reports age
        # out and recovers only after independent vantage evidence returns.
        processes_b = authority_b["processes"]
        for index in range(3):
            processes_b[index].kill()
            processes_b[index].wait(timeout=5)
        expect_dns(authority_b["dns"], authority_b["dns_port"], 2, timeout=12,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: observer-feed partition withdraws only the authority without fresh quorum")
        start_agent(agents[0], "b")
        expect_dns(authority_b["dns"], authority_b["dns_port"], 2,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        start_agent(agents[1], "b")
        expect_dns(authority_b["dns"], authority_b["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
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
        expect_dns(authority_a["dns"], authority_a["dns_port"], 0, "192.0.2.17",
                   log_paths=[authority_a["dns_log"], *authority_a["agent_logs"]])
        print("PASS: revoked observer client leaves cannot re-establish the isolated authority's quorum")
        b_config["AgentReports"]["RevokedCertificateSha256"] = []
        authority_b["dns_config"].write_text(json.dumps(b_config))
        restart_agents(authority_b, "b")
        recovered_dns = restart_authority(authority_b)
        restart_agents(authority_b, "b")
        expect_dns(recovered_dns, authority_b["dns_port"], 0, "192.0.2.17", timeout=12,
                   log_paths=[authority_b["dns_log"], *authority_b["agent_logs"]])
        print("PASS: authority recovers only after revocation is removed and fresh quorum returns")


if __name__ == "__main__":
    main()
