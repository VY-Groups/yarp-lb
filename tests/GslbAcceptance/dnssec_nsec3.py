#!/usr/bin/env python3
"""Independent NSEC3 wire and denial-proof acceptance using dnspython."""
import base64
import json
import os
import socket
import subprocess
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
ZONE = dns.name.from_text("nsec3.integration.test.")
SALT_HEX = "AABBCCDD11223344"
ITERATIONS = 12


def require(value, message):
    if not value:
        raise AssertionError(message)
    print(f"PASS: {message}", flush=True)


def query(port, name, qtype, transport="udp"):
    request = dns.message.make_query(name, qtype, want_dnssec=True)
    request.flags &= ~dns.flags.RD
    return (dns.query.udp(request, "127.0.0.1", port=port, timeout=3) if transport == "udp"
            else dns.query.tcp(request, "127.0.0.1", port=port, timeout=3))


def validate_sections(response, keys):
    count = 0
    for section in (response.answer, response.authority):
        for rrset in section:
            if rrset.rdtype in (dns.rdatatype.RRSIG, dns.rdatatype.OPT):
                continue
            sigs = response.find_rrset(section, rrset.name, rrset.rdclass,
                                       dns.rdatatype.RRSIG, covers=rrset.rdtype, create=False)
            dns.dnssec.validate(rrset, sigs, keys, now=time.time())
            count += 1
    return count


def nsec3_hash(name):
    return dns.dnssec.nsec3_hash(dns.name.from_text(name), SALT_HEX, ITERATIONS, 1).upper()


def covers(rrset, target_hash):
    for record in rrset:
        start = rrset.name.labels[0].decode("ascii").upper()
        end = base64.b32hexencode(record.next).decode("ascii").rstrip("=")
        if start < end and start < target_hash < end:
            return True
        if start >= end and (target_hash > start or target_hash < end):
            return True
    return False


def start_port():
    for port in range(25000, 26000):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            udp.bind(("127.0.0.1", port))
            tcp.bind(("127.0.0.1", port))
            return port
        except OSError:
            pass
        finally:
            udp.close()
            tcp.close()
    raise RuntimeError("No free port in 25000..25999")


def main():
    require(DLL.is_file(), "DNS engine built before NSEC3 acceptance")
    # RFC 5155 Appendix B.2 uses a four-byte vector salt; acceptance config
    # uses an eight-byte deployment salt to enforce the configured minimum.
    require(dns.dnssec.nsec3_hash("ns1.example.", "AABBCCDD", 12, 1).upper() ==
            "2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
            "RFC 5155 Appendix B.2 NSEC3 hash vector")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-nsec3-") as directory:
        root = Path(directory)
        key = ec.generate_private_key(ec.SECP256R1())
        key_path = root / "dnssec-key.pem"
        key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        key_path.chmod(0o600)
        port = start_port()
        config = {"AllowNonLoopbackListeners": False, "ListenHost": "127.0.0.1",
            "ListenPort": port, "ProbeIntervalSeconds": 2, "Zones": [{
                "Name": str(ZONE).rstrip("."), "TtlSeconds": 30, "SoaSerial": 2026111901,
                "SoaContact": "hostmaster.nsec3.integration.test",
                "DnssecPrivateKeyPath": str(key_path), "DnssecDenialMode": "Nsec3",
                "DnssecNsec3SaltHex": SALT_HEX, "DnssecNsec3Iterations": ITERATIONS,
                "NameServers": [
                    {"Host": "ns1.nsec3.integration.test", "Address": "127.0.0.1"},
                    {"Host": "ns1.branch.nsec3.integration.test", "Address": "127.0.0.2"}],
                "Delegations": [{"Name": "child.nsec3.integration.test", "NameServers": [
                    {"Host": "ns1.child.nsec3.integration.test", "Address": "192.0.2.53"}]}],
                "FailClosedWhenAllSitesDown": False,
                "Sites": [{"Address": "192.0.2.80", "Weight": 1,
                           "HealthCheckType": "Tcp", "TcpPort": 9}]}]}
        config_path = root / "zones.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        implicit_iterations = json.loads(json.dumps(config))
        del implicit_iterations["Zones"][0]["DnssecNsec3Iterations"]
        invalid_path = root / "implicit-iterations.json"
        invalid_path.write_text(json.dumps(implicit_iterations), encoding="utf-8")
        invalid = subprocess.run(["dotnet", str(DLL), str(invalid_path)], cwd=ROOT,
            capture_output=True, text=True, timeout=10, check=False)
        require(invalid.returncode != 0 and "explicit 8..32 byte hex salt and 0..50 iterations" in
                (invalid.stdout + invalid.stderr), "NSEC3 config requires a persisted explicit iteration count")
        for bad_name, label in (("ns1.ünicode.nsec3.integration.test", "Unicode owner"),
                                ("x" * 64 + ".nsec3.integration.test", "oversized label"),
                                ("ns1..nsec3.integration.test", "empty label"),
                                ("ns1.nsec3.integration.test..", "multiple terminal dots")):
            malformed = json.loads(json.dumps(config))
            malformed["Zones"][0]["NameServers"][0]["Host"] = bad_name
            invalid_path = root / ("invalid-" + label.replace(" ", "-") + ".json")
            invalid_path.write_text(json.dumps(malformed), encoding="utf-8")
            invalid = subprocess.run(["dotnet", str(DLL), str(invalid_path)], cwd=ROOT,
                capture_output=True, text=True, timeout=10, check=False)
            expected_error = ("NSEC3 names may have at most one terminal root dot" if
                              label == "multiple terminal dots" else "Invalid authoritative NS hostname")
            require(invalid.returncode != 0 and expected_error in (invalid.stdout + invalid.stderr),
                    f"NSEC3 startup rejects {label}")
        process = subprocess.Popen(["dotnet", str(DLL), str(config_path)], cwd=ROOT,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
        try:
            startup = process.stdout.readline()
            if not startup.startswith("GSLB_DNSSEC "):
                raise RuntimeError("DNS server did not announce signing: " + startup + process.stdout.read())
            require(startup.startswith("GSLB_DNSSEC "), "NSEC3 signer starts with active DNSSEC key")
            for _ in range(60):
                if process.poll() is not None:
                    raise RuntimeError("DNS process exited: " + process.stdout.read())
                try:
                    response = query(port, str(ZONE), "DNSKEY")
                    break
                except (OSError, dns.exception.DNSException):
                    time.sleep(.1)
            else:
                raise TimeoutError("NSEC3 DNS server did not become ready")
            keys_rrset = next(rr for rr in response.answer if rr.rdtype == dns.rdatatype.DNSKEY)
            keys = {ZONE: keys_rrset}
            require(validate_sections(response, keys) == 1, "NSEC3 zone DNSKEY signature validates")

            param = query(port, str(ZONE), "NSEC3PARAM", "tcp")
            param_rrset = next(rr for rr in param.answer if rr.rdtype == dns.rdatatype.NSEC3PARAM)
            param_rdata = next(iter(param_rrset))
            require(param_rdata.algorithm == 1 and param_rdata.flags == 0 and
                    param_rdata.iterations == ITERATIONS and param_rdata.salt.hex().upper() == SALT_HEX,
                    "NSEC3PARAM publishes the configured SHA-1, no-opt-out salt and iteration values")
            require(validate_sections(param, keys) == 1, "NSEC3PARAM signature validates")

            for transport in ("udp", "tcp"):
                answer = query(port, str(ZONE), "A", transport)
                require(answer.rcode() == dns.rcode.NOERROR and validate_sections(answer, keys) == 1,
                        f"{transport.upper()} dynamic A signature validates in NSEC3 mode")

            nodata = query(port, str(ZONE), "AAAA", "tcp")
            require(nodata.rcode() == dns.rcode.NOERROR and validate_sections(nodata, keys) >= 2,
                    "NSEC3 NODATA SOA and denial signatures validate")
            proofs = [rr for rr in nodata.authority if rr.rdtype == dns.rdatatype.NSEC3]
            apex_hash = nsec3_hash(str(ZONE))
            exact = [rr for rr in proofs if rr.name.labels[0].decode().upper() == apex_hash]
            require(bool(exact) and "AAAA" not in str(next(iter(exact[0]))).split(),
                    "NSEC3 exact-owner NODATA proof has a bitmap that omits AAAA")
            apex_types = str(next(iter(exact[0]))).split() if exact else []
            require("NSEC3PARAM" in apex_types and "NSEC3" not in apex_types,
                    "RFC 5155 original-owner bitmap includes NSEC3PARAM but excludes NSEC3 itself")

            # branch.nsec3... is an empty non-terminal created by ns1.branch...
            ent_name = "branch." + str(ZONE)
            ent = query(port, ent_name, "A", "udp")
            require(ent.rcode() == dns.rcode.NOERROR and validate_sections(ent, keys) >= 2,
                    "NSEC3 empty non-terminal is NODATA, not NXDOMAIN")
            ent_hash = nsec3_hash(ent_name)
            ent_exact = [rr for rr in ent.authority if rr.rdtype == dns.rdatatype.NSEC3 and
                         rr.name.labels[0].decode().upper() == ent_hash]
            require(bool(ent_exact) and "A" not in str(next(iter(ent_exact[0]))).split() and
                    "RRSIG" not in str(next(iter(ent_exact[0]))).split(),
                    "empty non-terminal exact hash uses an empty original-owner type bitmap")

            for qname in ("missing." + str(ZONE), "missing.branch." + str(ZONE)):
                nx = query(port, qname, "A", "tcp")
                validated = validate_sections(nx, keys) if nx.rcode() == dns.rcode.NXDOMAIN else -1
                # Several proof obligations may be satisfied by one ring entry;
                # require the SOA plus every distinct signed NSEC3 RRset.
                if nx.rcode() != dns.rcode.NXDOMAIN or validated < 3:
                    raise AssertionError(f"bad NSEC3 NXDOMAIN for {qname}: rcode={nx.rcode()} validated={validated} "
                        f"authority={[str(rr) for rr in nx.authority]}")
                require(True,
                        f"NSEC3 NXDOMAIN and every response signature validate for {qname}")
                records = [rr for rr in nx.authority if rr.rdtype == dns.rdatatype.NSEC3]
                require(all("NSEC3" not in str(record).split() for rr in records for record in rr),
                        "RFC 5155 NSEC3 bitmaps omit types contributed solely by NSEC3 records")
                owner_hashes = {rr.name.labels[0].decode("ascii").upper() for rr in records}
                closest = str(ZONE) if qname.startswith("missing." + str(ZONE)) else "branch." + str(ZONE)
                next_closer = qname
                wildcard = "*." + closest
                require(nsec3_hash(closest) in owner_hashes,
                        f"NSEC3 NXDOMAIN includes exact closest-encloser proof for {closest}")
                require(any(covers(rr, nsec3_hash(next_closer)) for rr in records),
                        f"NSEC3 NXDOMAIN covers the next-closer hash for {qname}")
                require(any(covers(rr, nsec3_hash(wildcard)) for rr in records),
                        f"NSEC3 NXDOMAIN covers the wildcard hash for {wildcard}")
                require(all(record.algorithm == 1 and record.flags == 0 and
                            record.iterations == ITERATIONS and record.salt.hex().upper() == SALT_HEX
                            for rr in records for record in rr),
                        "all NSEC3 proof records use matching parameters and disable opt-out")

            ds = query(port, "child." + str(ZONE), "DS", "tcp")
            ds_exact = [rr for rr in ds.authority if rr.rdtype == dns.rdatatype.NSEC3 and
                        rr.name.labels[0].decode("ascii").upper() == nsec3_hash("child." + str(ZONE))]
            require(ds.rcode() == dns.rcode.NOERROR and validate_sections(ds, keys) >= 2 and
                    bool(ds_exact) and "NS" in str(next(iter(ds_exact[0]))).split() and
                    "DS" not in str(next(iter(ds_exact[0]))).split() and
                    "RRSIG" not in str(next(iter(ds_exact[0]))).split(),
                    "unsigned delegation DS absence has exact NSEC3 bitmap with unsigned NS and no DS")
            print("PASS: NSEC3 RFC-vector, NODATA, empty non-terminal, NXDOMAIN and DS wire acceptance")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
