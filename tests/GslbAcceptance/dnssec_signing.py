#!/usr/bin/env python3
"""Independent DNSSEC wire/signature acceptance using dnspython as validator."""
import json
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.query
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


ROOT = Path(__file__).resolve().parents[2]
DLL = ROOT / "engines" / "GslbDns" / "bin" / "Release" / "net10.0" / "GslbDns.dll"
ZONE = dns.name.from_text("signed.integration.test.")


def require(condition, message):
    if not condition:
        raise AssertionError(message)
    print(f"PASS: {message}", flush=True)


def query(server, port, qname, qtype, transport="udp"):
    request = dns.message.make_query(qname, qtype, want_dnssec=True)
    request.flags &= ~dns.flags.RD
    if transport == "udp":
        return dns.query.udp(request, server, port=port, timeout=3)
    return dns.query.tcp(request, server, port=port, timeout=3)


def validate_signed_sections(response, trusted_keys):
    validated = 0
    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.OPT):
                continue
            sigs = response.find_rrset(section, rrset.name, rrset.rdclass,
                                       dns.rdatatype.RRSIG, covers=rrset.rdtype,
                                       create=False)
            dns.dnssec.validate(rrset, sigs, trusted_keys, now=time.time())
            validated += 1
    return validated


def assert_nsec_cover(response, qname):
    owner = dns.name.from_text(qname).canonicalize()
    nsec_rrsets = [rrset for rrset in response.authority if rrset.rdtype == dns.rdatatype.NSEC]
    require(bool(nsec_rrsets), f"negative proof has NSEC records for {qname}")
    for rrset in nsec_rrsets:
        start = rrset.name.canonicalize()
        for record in rrset:
            end = record.next.canonicalize()
            if (start < end and start < owner < end) or (start >= end and (owner > start or owner < end)):
                return
    raise AssertionError(f"NSEC records do not cover {qname}")


def verify_cli_interop(port):
    """Check the real wire behavior with independent BIND and Knot clients."""
    for client in ("dig", "kdig"):
        if shutil.which(client) is None:
            raise RuntimeError(f"required independent DNS client is missing: {client}")
        for transport in ("udp", "tcp"):
            transport_arg = "+notcp" if transport == "udp" else "+tcp"
            # Prevent either client from silently retrying TCP after a truncated
            # UDP answer; the TC assertion below must describe the UDP datagram.
            no_fallback_arg = "+ignore" if transport == "udp" else "+noignore"
            for qname, qtype, expected_status, required_types in (
                (str(ZONE), "A", "noerror", ("A", "RRSIG")),
                ("missing.signed.integration.test.", "A", "nxdomain",
                 ("SOA", "NSEC", "RRSIG")),
            ):
                completed = subprocess.run(
                    [client, "-p", str(port), qname, qtype,
                     "+norecurse", "+dnssec", "+bufsize=1232", transport_arg, no_fallback_arg,
                     "+time=2", ("+tries=1" if client == "dig" else "+retry=1"),
                     *(["+noall", "+comments", "+answer", "+authority"] if client == "dig" else ["+all"]),
                     "@127.0.0.1"],
                    capture_output=True, text=True, timeout=6, check=False,
                )
                output = completed.stdout
                if completed.returncode != 0:
                    raise AssertionError(
                        f"{client} {transport} invocation failed ({completed.returncode}):\n"
                        f"stdout:\n{output}\nstderr:\n{completed.stderr}")
                lowered = output.lower()
                if f"status: {expected_status}" not in lowered:
                    raise AssertionError(f"{client} {transport} {qname} returned unexpected status:\n{output}")
                flags_line = next((line.lower() for line in output.splitlines()
                                   if re.search(r"\bflags:\s", line, re.IGNORECASE)), "")
                flags = set(re.split(r"[\s;]+", flags_line.split("flags:", 1)[-1].strip()))
                if "aa" not in flags or "ra" in flags or "ad" in flags:
                    raise AssertionError(f"{client} {transport} did not preserve authoritative, non-recursive flags:\n{output}")
                if transport == "udp" and "tc" in flags:
                    raise AssertionError(
                        f"{client} UDP response was truncated instead of returning the complete signed answer/proof:\n{output}")
                missing = [record_type for record_type in required_types
                           if not re.search(rf"\bIN\s+{record_type}\b", output, re.IGNORECASE)]
                if missing:
                    raise AssertionError(
                        f"{client} {transport} omitted signed {qtype} data/proof {missing}:\n{output}")
                print(f"PASS: {client} over {transport.upper()} verifies authoritative signed {expected_status} wire response",
                      flush=True)


def main():
    require(DLL.is_file(), "DNS engine was built before signed-zone acceptance")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-dnssec-") as temp:
        temp_path = Path(temp)
        key_path = temp_path / "dnssec-key.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        key_path.chmod(0o600)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        for port in range(24000, 25000):
            try:
                sock.bind(("127.0.0.1", port))
                tcp_sock.bind(("127.0.0.1", port))
                break
            except OSError:
                sock.close()
                tcp_sock.close()
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            raise RuntimeError("No free unreserved test port in 24000..24999")
        sock.close()
        tcp_sock.close()
        config_path = temp_path / "zones.json"
        config = {
            "AllowNonLoopbackListeners": False,
            "ListenHost": "127.0.0.1",
            "ListenPort": port,
            "ProbeIntervalSeconds": 2,
            "Zones": [{
                "Name": str(ZONE).rstrip("."),
                "TtlSeconds": 30,
                "SoaSerial": 2026111701,
                "SoaContact": "hostmaster.signed.integration.test",
                "DnssecPrivateKeyPath": str(key_path),
                "NameServers": [{"Host": "ns1.signed.integration.test", "Address": "127.0.0.1"}],
                "Delegations": [{"Name": "child.signed.integration.test", "NameServers": [
                    {"Host": "ns1.child.signed.integration.test", "Address": "192.0.2.53"}]}],
                "FailClosedWhenAllSitesDown": False,
                "Sites": [{"Address": "192.0.2.80", "Weight": 1,
                           "HealthCheckType": "Tcp", "TcpPort": 9}]
            }]
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        process = subprocess.Popen(["dotnet", str(DLL), str(config_path)], cwd=ROOT,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        try:
            startup = process.stdout.readline().strip()
            require(startup.startswith("GSLB_DNSSEC "), "server reports DNSSEC enablement and parent DS material")
            pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
            key_rr = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                "257 3 13 " + __import__("base64").b64encode(pub[1:]).decode("ascii"))
            keyset = dns.rrset.from_rdata(str(ZONE), 30, key_rr)
            parent_ds = dns.dnssec.make_ds(ZONE, key_rr, "SHA256")
            ds_text = f"{parent_ds.key_tag} {parent_ds.algorithm} {parent_ds.digest_type} {parent_ds.digest.hex().upper()}"
            require(ds_text in startup, "logged parent DS presentation matches independently derived DNSKEY DS")

            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("DNS server exited during startup: " + process.stdout.read())
                try:
                    response = query("127.0.0.1", port, ZONE, "DNSKEY", "udp")
                    break
                except (OSError, dns.exception.DNSException):
                    time.sleep(0.1)
            else:
                raise TimeoutError("DNS listener did not become ready")
            keys = {ZONE: keyset}
            require(response.ednsflags & dns.flags.DO, "EDNS response retains DO when zone signing is enabled")
            require(validate_signed_sections(response, keys) == 1,
                    "DNSKEY RRset self-signature validates with an independent DNSSEC verifier")
            require(any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer),
                    "DNSKEY query returns the zone key")

            for transport in ("udp", "tcp"):
                answer = query("127.0.0.1", port, ZONE, "A", transport)
                require(validate_signed_sections(answer, keys) == 1,
                        f"{transport.upper()} selected dynamic A RRset verifies cryptographically")
                require(any(rrset.rdtype == dns.rdatatype.A for rrset in answer.answer),
                        f"{transport.upper()} preserves healthy-backend GSLB answer")
                rrset = next(rrset for rrset in answer.answer if rrset.rdtype == dns.rdatatype.A)
                sigs = answer.find_rrset(answer.answer, rrset.name, rrset.rdclass,
                                         dns.rdatatype.RRSIG, covers=rrset.rdtype)
                tampered = dns.rrset.from_text(str(rrset.name), rrset.ttl, "IN", "A", "192.0.2.99")
                try:
                    dns.dnssec.validate(tampered, sigs, keys, now=time.time())
                except dns.dnssec.ValidationFailure:
                    pass
                else:
                    raise AssertionError("a modified dynamic backend address incorrectly passed signature verification")
                require(True, f"{transport.upper()} signature rejects a tampered backend address")

            nodata = query("127.0.0.1", port, ZONE, "AAAA", "tcp")
            require(nodata.rcode() == dns.rcode.NOERROR and validate_signed_sections(nodata, keys) == 2,
                    "NODATA SOA and exact-owner NSEC denial signatures validate")
            for transport in ("udp", "tcp"):
                nx = query("127.0.0.1", port,
                           "missing.signed.integration.test.", "A", transport)
                require(nx.rcode() == dns.rcode.NXDOMAIN,
                        f"{transport.upper()} preserves NXDOMAIN response code")
                if transport == "udp":
                    require(not nx.flags & dns.flags.TC,
                            "UDP NXDOMAIN denial proof is complete without TCP fallback")
                require(validate_signed_sections(nx, keys) >= 3,
                        f"{transport.upper()} NXDOMAIN SOA and NSEC proof RRsets verify cryptographically")
                assert_nsec_cover(nx, "missing.signed.integration.test.")
                assert_nsec_cover(nx, "*.signed.integration.test.")

            ds = query("127.0.0.1", port, "child.signed.integration.test.", "DS", "tcp")
            require(ds.rcode() == dns.rcode.NOERROR and validate_signed_sections(ds, keys) >= 2,
                    "unsigned child delegation DS absence is signed by the parent zone")
            require(any(rrset.rdtype == dns.rdatatype.NSEC and rrset.name == dns.name.from_text("child.signed.integration.test.")
                        for rrset in ds.authority), "DS absence proof is attached at the child cut")

            rrsig = query("127.0.0.1", port, ZONE, "RRSIG", "tcp")
            require(any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in rrsig.answer),
                    "direct RRSIG query returns available zone signatures")
            require("PRIVATE KEY" not in startup, "private key material is not written to startup logs")
            verify_cli_interop(port)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
