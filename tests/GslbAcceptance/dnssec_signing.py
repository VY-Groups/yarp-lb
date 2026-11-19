#!/usr/bin/env python3
"""Independent DNSSEC wire/signature acceptance using dnspython as validator."""
import json
import os
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


def query(server, port, qname, qtype, transport="udp", timeout=3, want_dnssec=True):
    request = dns.message.make_query(qname, qtype, want_dnssec=want_dnssec)
    request.flags &= ~dns.flags.RD
    if transport == "udp":
        return dns.query.udp(request, server, port=port, timeout=timeout)
    return dns.query.tcp(request, server, port=port, timeout=timeout)


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
        rollover_key_path = temp_path / "dnssec-rollover-key.pem"
        rollover_public_path = temp_path / "dnssec-rollover-public.pem"
        key = ec.generate_private_key(ec.SECP256R1())
        rollover_key = ec.generate_private_key(ec.SECP256R1())
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        key_path.chmod(0o600)
        rollover_key_path.write_bytes(rollover_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        rollover_key_path.chmod(0o600)
        rollover_public_path.write_bytes(rollover_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        child_key = ec.generate_private_key(ec.SECP256R1())
        child_pub = child_key.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        child_dnskey = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
            "257 3 13 " + __import__("base64").b64encode(child_pub[1:]).decode("ascii"))
        child_zone = dns.name.from_text("child.signed.integration.test.")
        child_ds = dns.dnssec.make_ds(child_zone, child_dnskey, "SHA256")
        unsigned_child_zone = dns.name.from_text("unsigned.signed.integration.test.")
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
                "DnssecPrepublishPublicKeyPaths": [str(rollover_public_path)],
                "NameServers": [{"Host": "ns1.signed.integration.test", "Address": "127.0.0.1"}],
                "Delegations": [{"Name": "child.signed.integration.test", "NameServers": [
                    {"Host": "ns1.child.signed.integration.test", "Address": "192.0.2.53"}],
                    "DsRecords": [{"KeyTag": child_ds.key_tag, "Algorithm": child_ds.algorithm,
                        "DigestType": child_ds.digest_type, "DigestHex": child_ds.digest.hex().upper()}]},
                    {"Name": "unsigned.signed.integration.test", "NameServers": [
                        {"Host": "ns.unsigned.signed.integration.test", "Address": "192.0.2.54"}]}],
                "FailClosedWhenAllSitesDown": False,
                "Sites": [{"Address": "192.0.2.80", "Weight": 1,
                           "HealthCheckType": "Tcp", "TcpPort": 9}]
            }]
        }
        config_path.write_text(json.dumps(config), encoding="utf-8")
        def reject_rollover_config(mutated, expected, label):
            invalid_path = temp_path / f"invalid-rollover-{label}.json"
            invalid_path.write_text(json.dumps(mutated), encoding="utf-8")
            denied = subprocess.run(["dotnet", str(DLL), str(invalid_path)], cwd=ROOT,
                                    capture_output=True, text=True, timeout=10, check=False)
            output = denied.stdout + denied.stderr
            require(denied.returncode != 0 and expected.lower() in output.lower(),
                    f"DNSSEC startup rejects invalid {label} rollover configuration")

        reject_rollover_config({**config, "Zones": [dict(config["Zones"][0],
            DnssecPrivateKeyPath=None)]}, "DNSSEC rollover keys require", "orphaned public key")
        reject_rollover_config({**config, "Zones": [dict(config["Zones"][0],
            DnssecAdditionalSigningKeyPaths=[str(key_path)])]}, "must be unique", "duplicate active signer")
        malformed_ds = dict(config["Zones"][0])
        malformed_ds["Delegations"] = [dict(malformed_ds["Delegations"][0], DsRecords=[{
            "KeyTag": child_ds.key_tag, "Algorithm": 13, "DigestType": 1,
            "DigestHex": child_ds.digest.hex().upper()}])]
        reject_rollover_config({**config, "Zones": [malformed_ds]}, "SHA-256 or SHA-384",
                               "unsupported child DS digest type")
        malformed_ds_length = dict(config["Zones"][0])
        malformed_ds_length["Delegations"] = [dict(malformed_ds_length["Delegations"][0], DsRecords=[{
            "KeyTag": child_ds.key_tag, "Algorithm": 13, "DigestType": 2,
            "DigestHex": "AB" * 31}])]
        reject_rollover_config({**config, "Zones": [malformed_ds_length]}, "exact length",
                               "truncated child DS digest")
        malformed_ds_algorithm = dict(config["Zones"][0])
        malformed_ds_algorithm["Delegations"] = [dict(malformed_ds_algorithm["Delegations"][0], DsRecords=[{
            "KeyTag": child_ds.key_tag, "Algorithm": 0, "DigestType": 2,
            "DigestHex": child_ds.digest.hex().upper()}])]
        reject_rollover_config({**config, "Zones": [malformed_ds_algorithm]}, "recognized DNSKEY algorithm",
                               "unsupported child DS DNSKEY algorithm")
        duplicate_ds = dict(config["Zones"][0])
        duplicate_ds["Delegations"] = [dict(duplicate_ds["Delegations"][0], DsRecords=[
            {"KeyTag": child_ds.key_tag, "Algorithm": child_ds.algorithm,
             "DigestType": child_ds.digest_type, "DigestHex": child_ds.digest.hex().upper()}] * 2)]
        reject_rollover_config({**config, "Zones": [duplicate_ds]}, "Duplicate delegation DS record",
                               "duplicate child DS record")
        unsigned_ds_parent = dict(config["Zones"][0])
        unsigned_ds_parent.pop("DnssecPrivateKeyPath", None)
        unsigned_ds_parent.pop("DnssecPrepublishPublicKeyPaths", None)
        reject_rollover_config({**config, "Zones": [unsigned_ds_parent]}, "signed parent zone",
                               "DS records on unsigned parent")
        misplaced_private_path = temp_path / "misplaced-private-key.pem"
        shutil.copyfile(key_path, misplaced_private_path)
        misplaced_private_path.chmod(0o600)
        reject_rollover_config({**config, "Zones": [dict(config["Zones"][0],
            DnssecPrepublishPublicKeyPaths=[str(misplaced_private_path)])]},
            "bounded public subjectpublickeyinfo", "private key in prepublish role")
        reject_rollover_config({**config, "Zones": [dict(config["Zones"][0],
            DnssecPrepublishPublicKeyPaths=["relative-public-key.pem"])]}, "absolute", "relative public key path")
        unsupported_curve_path = temp_path / "unsupported-curve-key.pem"
        unsupported_curve_key = ec.generate_private_key(ec.SECP384R1())
        unsupported_curve_path.write_bytes(unsupported_curve_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        unsupported_curve_path.chmod(0o600)
        reject_rollover_config({**config, "Zones": [dict(config["Zones"][0],
            DnssecAdditionalSigningKeyPaths=[str(unsupported_curve_path)])]},
            "P-256/SHA-256", "unsupported signing-key curve")
        if os.name != "nt":
            def reject_key_path(candidate, expected, label):
                invalid = dict(config)
                invalid["Zones"] = [dict(config["Zones"][0], DnssecPrivateKeyPath=str(candidate))]
                invalid_path = temp_path / f"invalid-{label}.json"
                invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
                denied = subprocess.run(["dotnet", str(DLL), str(invalid_path)], cwd=ROOT,
                                        capture_output=True, text=True, timeout=10, check=False)
                output = denied.stdout + denied.stderr
                require(denied.returncode != 0 and expected.lower() in output.lower(),
                        f"DNSSEC startup rejects {label} key path")
                require("PRIVATE KEY" not in output,
                        f"DNSSEC startup does not print key material for {label} key path")

            broad_key_path = temp_path / "broad-dnssec-key.pem"
            shutil.copyfile(key_path, broad_key_path)
            broad_key_path.chmod(0o644)
            reject_key_path(broad_key_path, "group/other access", "group-readable")

            linked_key_path = temp_path / "linked-dnssec-key.pem"
            linked_key_path.symlink_to(key_path)
            reject_key_path(linked_key_path, "without following links", "symlinked")

        process = subprocess.Popen(["dotnet", str(DLL), str(config_path)], cwd=ROOT,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, encoding="utf-8", errors="replace")
        try:
            startup = process.stdout.readline().strip()
            require(startup.startswith("GSLB_DNSSEC "), "server reports DNSSEC enablement and parent DS material")
            prepublish_startup = process.stdout.readline().strip()
            require("phase=prepublish" in prepublish_startup,
                    "rollover startup labels a public-only new key as prepublish material")
            pub = key.public_key().public_bytes(serialization.Encoding.X962,
                                                serialization.PublicFormat.UncompressedPoint)
            key_rr = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                "257 3 13 " + __import__("base64").b64encode(pub[1:]).decode("ascii"))
            rollover_pub = rollover_key.public_key().public_bytes(
                serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            rollover_key_rr = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DNSKEY,
                "257 3 13 " + __import__("base64").b64encode(rollover_pub[1:]).decode("ascii"))
            keyset = dns.rrset.from_rdata(str(ZONE), 30, key_rr, rollover_key_rr)
            old_keyset = dns.rrset.from_rdata(str(ZONE), 30, key_rr)
            new_keyset = dns.rrset.from_rdata(str(ZONE), 30, rollover_key_rr)
            parent_ds = dns.dnssec.make_ds(ZONE, key_rr, "SHA256")
            ds_text = f"{parent_ds.key_tag} {parent_ds.algorithm} {parent_ds.digest_type} {parent_ds.digest.hex().upper()}"
            require(ds_text in startup, "logged parent DS presentation matches independently derived DNSKEY DS")
            rollover_ds = dns.dnssec.make_ds(ZONE, rollover_key_rr, "SHA256")
            rollover_ds_text = f"{rollover_ds.key_tag} {rollover_ds.algorithm} {rollover_ds.digest_type} {rollover_ds.digest.hex().upper()}"
            require(rollover_ds_text in prepublish_startup,
                    "prepublish DS presentation matches independently derived next-key DS")

            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("DNS server exited during startup: " + process.stdout.read())
                try:
                    response = query("127.0.0.1", port, ZONE, "DNSKEY", "udp", timeout=0.2)
                    break
                except (OSError, dns.exception.DNSException):
                    time.sleep(0.1)
            else:
                diagnostics = []
                for client in ("dig", "kdig"):
                    if shutil.which(client):
                        command = ([client, "@127.0.0.1", "-p", str(port), str(ZONE), "DNSKEY",
                                    "+dnssec", "+time=1", "+tries=1"] if client == "dig" else
                                   [client, "@127.0.0.1", "-p", str(port), str(ZONE), "DNSKEY",
                                    "+dnssec", "+timeout=1", "+retry=0"])
                        result = subprocess.run(command, capture_output=True, text=True, timeout=4, check=False)
                        diagnostics.append(f"{client} rc={result.returncode}: {result.stdout[:1000]} {result.stderr[:500]}")
                try:
                    tcp_debug = query("127.0.0.1", port, ZONE, "DNSKEY", "tcp", timeout=1)
                    diagnostics.append(f"TCP response id={tcp_debug.id} rcode={tcp_debug.rcode()}")
                except Exception as error:
                    diagnostics.append(f"TCP error: {type(error).__name__}: {error}")
                process.terminate()
                process.wait(timeout=5)
                raise TimeoutError("DNS listener did not become ready; " + " | ".join(diagnostics) +
                                   " | server: " + process.stdout.read())
            keys = {ZONE: keyset}
            old_trust = {ZONE: old_keyset}
            new_trust = {ZONE: new_keyset}
            require(response.ednsflags & dns.flags.DO, "EDNS response retains DO when zone signing is enabled")
            published_keys = next(rrset for rrset in response.answer if rrset.rdtype == dns.rdatatype.DNSKEY)
            require(len(published_keys) == 2 and set(published_keys) == {key_rr, rollover_key_rr},
                    "prepublication DNSKEY RRset contains the old and new keys")
            require(validate_signed_sections(response, old_trust) == 1,
                    "prepublished DNSKEY RRset remains signed by the current trusted key")
            dnskey_sigs = response.find_rrset(response.answer, published_keys.name,
                published_keys.rdclass, dns.rdatatype.RRSIG, covers=dns.rdatatype.DNSKEY)
            require({signature.key_tag for signature in dnskey_sigs} == {parent_ds.key_tag},
                    "prepublication phase does not use the untrusted next key to sign the DNSKEY RRset")
            require(any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer),
                    "DNSKEY query returns the zone key")

            for transport in ("udp", "tcp"):
                answer = query("127.0.0.1", port, ZONE, "A", transport)
                require(validate_signed_sections(answer, old_trust) == 1,
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

            for transport in ("udp", "tcp"):
                ds = query("127.0.0.1", port, child_zone, "DS", transport)
                ds_rrset = next(rrset for rrset in ds.answer if rrset.rdtype == dns.rdatatype.DS)
                ds_sigs = ds.find_rrset(ds.answer, ds_rrset.name, ds_rrset.rdclass,
                    dns.rdatatype.RRSIG, covers=dns.rdatatype.DS)
                require(ds.rcode() == dns.rcode.NOERROR and len(ds_rrset) == 1 and
                        next(iter(ds_rrset)) == child_ds and
                        validate_signed_sections(ds, keys) == 1,
                        f"{transport.upper()} parent DS answer matches child DNSKEY and verifies cryptographically")
                require(len(ds_sigs) == 1,
                        f"{transport.upper()} child DS answer contains parent signature")
                unsigned_response = query("127.0.0.1", port, child_zone, "DS", transport,
                                          want_dnssec=False)
                require(any(rrset.rdtype == dns.rdatatype.DS for rrset in unsigned_response.answer) and
                        not any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in
                                unsigned_response.answer + unsigned_response.authority),
                        f"{transport.upper()} non-DO DS answer omits signatures without omitting DS data")

                referral = query("127.0.0.1", port, "www.child.signed.integration.test.", "A", transport)
                require(not referral.flags & dns.flags.AA and not referral.answer and
                        any(rrset.rdtype == dns.rdatatype.NS and rrset.name == child_zone
                            for rrset in referral.authority),
                        f"{transport.upper()} signed-child lookup returns a non-authoritative parent referral")
                referral_ds = next(rrset for rrset in referral.authority
                                   if rrset.rdtype == dns.rdatatype.DS)
                referral_sig = referral.find_rrset(referral.authority, referral_ds.name,
                    referral_ds.rdclass, dns.rdatatype.RRSIG, covers=dns.rdatatype.DS)
                dns.dnssec.validate(referral_ds, referral_sig, keys, now=time.time())
                require(next(iter(referral_ds)) == child_ds,
                        f"{transport.upper()} DO referral carries the validating child DS RRset")
                non_do_referral = query("127.0.0.1", port,
                    "www.child.signed.integration.test.", "A", transport, want_dnssec=False)
                require(not any(rrset.rdtype in (dns.rdatatype.DS, dns.rdatatype.RRSIG)
                                for rrset in non_do_referral.authority),
                        f"{transport.upper()} non-DO referral omits DNSSEC-only DS/signature data")

                insecure_referral = query("127.0.0.1", port,
                    "www.unsigned.signed.integration.test.", "A", transport)
                insecure_nsec = next(rrset for rrset in insecure_referral.authority
                    if rrset.rdtype == dns.rdatatype.NSEC and rrset.name == unsigned_child_zone)
                insecure_sig = insecure_referral.find_rrset(insecure_referral.authority,
                    insecure_nsec.name, insecure_nsec.rdclass, dns.rdatatype.RRSIG,
                    covers=dns.rdatatype.NSEC)
                dns.dnssec.validate(insecure_nsec, insecure_sig, keys, now=time.time())
                require(not insecure_referral.flags & dns.flags.AA and
                        any(rrset.rdtype == dns.rdatatype.NS for rrset in insecure_referral.authority),
                        f"{transport.upper()} DO referral proves an unsigned cut with parent-signed NSEC")

            unsigned_ds = query("127.0.0.1", port, unsigned_child_zone, "DS", "tcp")
            require(unsigned_ds.rcode() == dns.rcode.NOERROR and
                    validate_signed_sections(unsigned_ds, keys) >= 2 and
                    any(rrset.rdtype == dns.rdatatype.NSEC and rrset.name == unsigned_child_zone
                        for rrset in unsigned_ds.authority),
                    "unsigned child delegation DS absence remains signed by the parent zone")

            rrsig = query("127.0.0.1", port, ZONE, "RRSIG", "tcp")
            require(any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in rrsig.answer),
                    "direct RRSIG query returns available zone signatures")
            require("PRIVATE KEY" not in startup, "private key material is not written to startup logs")
            if os.name != "nt":
                verify_cli_interop(port)

            process.terminate()
            process.wait(timeout=5)
            dual_zone = dict(config["Zones"][0])
            dual_zone.pop("DnssecPrepublishPublicKeyPaths", None)
            dual_zone["DnssecAdditionalSigningKeyPaths"] = [str(rollover_key_path)]
            config["Zones"] = [dual_zone]
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process = subprocess.Popen(["dotnet", str(DLL), str(config_path)], cwd=ROOT,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace")
            dual_active_startup = process.stdout.readline().strip()
            dual_next_startup = process.stdout.readline().strip()
            require("phase=active" in dual_active_startup and ds_text in dual_active_startup,
                    "dual-sign phase preserves the active key's deterministic parent DS")
            require("phase=dual-sign" in dual_next_startup and rollover_ds_text in dual_next_startup,
                    "dual-sign phase reports the next key's deterministic parent DS")
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("DNS server exited during dual-sign startup: " + process.stdout.read())
                try:
                    dual_dnskey = query("127.0.0.1", port, ZONE, "DNSKEY", "udp")
                    break
                except (OSError, dns.exception.DNSException):
                    time.sleep(0.1)
            else:
                raise TimeoutError("dual-sign DNS listener did not become ready")
            dual_keyset = next(rrset for rrset in dual_dnskey.answer
                               if rrset.rdtype == dns.rdatatype.DNSKEY)
            dual_key_sigs = dual_dnskey.find_rrset(dual_dnskey.answer, dual_keyset.name,
                dual_keyset.rdclass, dns.rdatatype.RRSIG, covers=dns.rdatatype.DNSKEY)
            expected_tags = {parent_ds.key_tag, rollover_ds.key_tag}
            require(set(dual_keyset) == {key_rr, rollover_key_rr} and
                    {signature.key_tag for signature in dual_key_sigs} == expected_tags,
                    "dual-sign DNSKEY RRset publishes and signs with both keys")
            require(validate_signed_sections(dual_dnskey, old_trust) == 1 and
                    validate_signed_sections(dual_dnskey, new_trust) == 1,
                    "dual-signed DNSKEY RRset validates against either old or new independent trust anchor")
            for transport in ("udp", "tcp"):
                dual_answer = query("127.0.0.1", port, ZONE, "A", transport)
                dual_rrset = next(rrset for rrset in dual_answer.answer
                                  if rrset.rdtype == dns.rdatatype.A)
                dual_sigs = dual_answer.find_rrset(dual_answer.answer, dual_rrset.name,
                    dual_rrset.rdclass, dns.rdatatype.RRSIG, covers=dns.rdatatype.A)
                require({signature.key_tag for signature in dual_sigs} == expected_tags and
                        validate_signed_sections(dual_answer, old_trust) == 1 and
                        validate_signed_sections(dual_answer, new_trust) == 1,
                        f"{transport.upper()} dynamic A RRset dual-sign validates with either trust anchor")
            if os.name != "nt":
                verify_cli_interop(port)
            print("PASS: DNSSEC prepublish and dual-sign key rollover wire behavior", flush=True)

            process.terminate()
            process.wait(timeout=5)
            retired_zone = dict(config["Zones"][0])
            retired_zone["DnssecPrivateKeyPath"] = str(rollover_key_path)
            retired_zone.pop("DnssecAdditionalSigningKeyPaths", None)
            config["Zones"] = [retired_zone]
            config_path.write_text(json.dumps(config), encoding="utf-8")
            process = subprocess.Popen(["dotnet", str(DLL), str(config_path)], cwd=ROOT,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       text=True, encoding="utf-8", errors="replace")
            retired_startup = process.stdout.readline().strip()
            require("phase=active" in retired_startup and rollover_ds_text in retired_startup and
                    ds_text not in retired_startup,
                    "retired phase advertises only the new active parent DS")
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("DNS server exited during retire startup: " + process.stdout.read())
                try:
                    retired_dnskey = query("127.0.0.1", port, ZONE, "DNSKEY", "udp", timeout=0.2)
                    break
                except (OSError, dns.exception.DNSException):
                    time.sleep(0.1)
            else:
                process.terminate()
                process.wait(timeout=5)
                raise TimeoutError("retired DNS listener did not become ready: " + process.stdout.read())
            retired_keyset = next(rrset for rrset in retired_dnskey.answer
                                  if rrset.rdtype == dns.rdatatype.DNSKEY)
            retired_key_sigs = retired_dnskey.find_rrset(retired_dnskey.answer, retired_keyset.name,
                retired_keyset.rdclass, dns.rdatatype.RRSIG, covers=dns.rdatatype.DNSKEY)
            require(set(retired_keyset) == {rollover_key_rr} and
                    {signature.key_tag for signature in retired_key_sigs} == {rollover_ds.key_tag} and
                    validate_signed_sections(retired_dnskey, new_trust) == 1,
                    "retired DNSKEY RRset contains and verifies only the new active key")
            retired_answer = query("127.0.0.1", port, ZONE, "A", "udp")
            require(validate_signed_sections(retired_answer, new_trust) == 1,
                    "retired dynamic A RRset validates with the new independent trust anchor")
            try:
                validate_signed_sections(retired_answer, old_trust)
            except dns.dnssec.ValidationFailure:
                require(True, "retired dynamic A RRset no longer validates under the removed old trust anchor")
            else:
                raise AssertionError("retired dynamic A RRset unexpectedly validated under old trust anchor")
            if os.name != "nt":
                verify_cli_interop(port)
            print("PASS: DNSSEC old-key retirement wire behavior", flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    main()
    subprocess.run([sys.executable, str(Path(__file__).with_name("dnssec_nsec3.py"))], check=True)
