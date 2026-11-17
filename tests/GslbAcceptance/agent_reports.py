"""Disposable multi-process acceptance for mTLS signed async health reports."""
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
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

        local = serve(stack)
        for agent in agents:
            agent["upstream"] = serve(stack)

        authorities = {}
        for node in ("a", "b"):
            dns_port = port()
            report_port = port()
            metrics_port = port() if node == "a" else 0
            report_config = {
                "ListenAddress": "127.0.0.1", "ListenPort": report_port,
                "AllowNonLoopbackListener": False,
                "ServerCertificatePem": str(dns_cert), "ServerKeyPem": str(dns_key),
                "ReplayStatePath": str(root / f"dns-{node}-replay-state.json"),
                "MaxTtlSeconds": 8, "MaxAgeSeconds": 6, "MaxClockSkewSeconds": 2,
                "MaxReportsPerMinute": 120, "RevokedCertificateSha256": [],
                "Agents": [{"AgentId": a["id"], "VantageGroup": a["vantage_group"],
                            "CertificateSha256": [a["pin"]],
                            "SigningPublicKeyPems": [str(a["public"])]} for a in agents]
            }
            dns_config = root / f"zones-{node}.json"
            dns_config.write_text(json.dumps({
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
            }))
            dns_log = root / f"dns-{node}.log"
            dns_log_handle = dns_log.open("w")
            stack.callback(dns_log_handle.close)
            dns = subprocess.Popen(["dotnet", dns_dll, dns_config], stdout=dns_log_handle,
                                   stderr=subprocess.STDOUT)
            stack.callback(dns.wait)
            stack.callback(dns.kill)
            expect_dns(dns, dns_port, 2, log_paths=[dns_log])
            authorities[node] = {"dns": dns, "dns_port": dns_port, "report_port": report_port,
                                 "metrics_port": metrics_port, "dns_log": dns_log,
                                 "processes": [], "agent_logs": []}

        configs = []

        def start_agent(agent, node):
            authority = authorities[node]
            listen_port = port()
            origin = f"https://127.0.0.1:{listen_port}"
            conf = root / f"{agent['id']}-{node}.json"
            conf.write_text(json.dumps({
                "ListenAddress": "127.0.0.1", "Port": listen_port,
                "PublicUrl": origin + "/ready",
                "HealthUrl": f"http://127.0.0.1:{agent['upstream'].server_port}/ready",
                "ServerCertificatePem": str(server_cert), "ServerKeyPem": str(server_key),
                "SigningKeyPem": str(agent["signer"]), "AllowedClientSha256": [agent["pin"]],
                "ReportUrl": f"https://127.0.0.1:{authority['report_port']}/agent-health/v1/reports",
                "AgentId": agent["id"], "Zone": "lab.example.test", "SiteId": "mumbai",
                "ReportClientCertificatePem": str(agent["cert"]),
                "ReportClientKeyPem": str(agent["key"]), "ReportServerCaPem": str(root / "ca.pem"),
                "ReportServerRevocationMode": "NoCheck",
                "ReportSequenceStatePath": str(root / (agent["id"] + f"-{node}-sequence.json")),
                "ReportIntervalSeconds": 1, "ReportTtlSeconds": 8
            }))
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
        assert accepted_count >= 3, "authenticated mTLS report accepts were not exported"
        assert 'gatewaycore_gslb_agent_quorum_targets{state="quorum"} 1' in metrics_text
        assert "lab.example.test" not in metrics_text and "192.0.2.17" not in metrics_text
        print("PASS: mTLS report and quorum metrics export without zone or backend labels")

        # One independent observer reports a real failure while the DNS node's
        # local readiness endpoint stays healthy; the quorum must withdraw it.
        agents[0]["upstream"].verdict = 503
        for authority in (authority_a, authority_b):
            expect_dns(authority["dns"], authority["dns_port"], 2,
                       log_paths=[authority["dns_log"], *authority["agent_logs"]])
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


if __name__ == "__main__":
    main()
