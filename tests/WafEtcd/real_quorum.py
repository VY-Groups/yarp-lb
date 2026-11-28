#!/usr/bin/env python3
"""Real disposable 3-member etcd v3 TLS lease/partition CI (not physical HA).

No external customer records, no production keys, no inbound public ports.
Three distinct etcd processes form a private Raft cluster with a read-only
mTLS verifier and a separately provisioned synthetic writer certificate.
The actual cluster acceptance test may NOT be replaced with fake JSON.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "waf"))
import etcd_quorum_fence as quorum
import etcd_cas_writer as writer
import real_dp_runtime
sys.path.insert(0, str(ROOT))
from ops.fleet import linux_dp_quorum_authority as dp_recovery

IMAGE = os.getenv("ETCD_IMAGE", "")
P = "A" * 64
NODES = ("node-a", "node-b")
STAGE = "startup"  # Only source-owned safe classification; never raw TLS/logs.


def checked(args, timeout=30):
    result = subprocess.run(args, shell=False, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False, timeout=timeout)
    if result.returncode:
        raise RuntimeError("disposable external etcd acceptance command failed")
    return result.stdout.decode("utf-8", "strict").strip()


def certs(folder, extra_client_subjects=()):
    folder.mkdir(mode=0o700)
    ca = folder / "ca.pem"
    ca_key = folder / "ca.key"
    checked(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
             "-sha256", "-days", "1", "-subj", "/CN=Disposable WAF etcd CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(ca_key), "-out", str(ca)])
    identities = {}
    for subject in ("ci1", "ci2", "ci3", "writer", "reader", *extra_client_subjects):
        key = folder / (subject + ".key")
        csr = folder / (subject + ".csr")
        crt = folder / (subject + ".pem")
        ext = folder / (subject + ".ext")
        server = subject.startswith("ci")
        ext.write_text(
            # etcd's embedded HTTP-to-gRPC gateway establishes its own
            # outbound TLS client connection to the server. The disposable
            # etcd server identity therefore requires BOTH X.509 usages;
            # reader/writer identities remain clientAuth-only, and
            # client certificate validation stays explicitly enabled.
            "extendedKeyUsage=" +
            ("serverAuth,clientAuth" if server else "clientAuth") +
            "\nkeyUsage=digitalSignature,keyEncipherment\n" +
            ("subjectAltName=IP:127.0.0.1,DNS:" + subject + "\n" if server else ""),
            encoding="ascii")
        checked(["openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
                 "-subj", "/CN=" + subject, "-keyout", str(key),
                 "-out", str(csr)])
        checked(["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca),
                 "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt),
                 "-days", "1", "-sha256", "-extfile", str(ext)])
        key.chmod(0o600)
        der = subprocess.run(["openssl", "x509", "-in", str(crt),
                              "-outform", "DER"], check=True,
                             capture_output=True, timeout=10).stdout
        identities[subject] = (str(crt), str(key),
                               hashlib.sha256(der).hexdigest().upper())
    ca_key.chmod(0o600)
    return str(ca), identities


def post(url, body, ca, certificate, key):
    host, port = url
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certificate, key)
    conn = http.client.HTTPSConnection(host, port, timeout=3, context=ctx)
    try:
        resource, payload = body
        conn.request("POST", resource, json.dumps(payload).encode("ascii"),
                     {"Content-Type": "application/json",
                      "Accept": "application/json", "Connection": "close"})
        response = conn.getresponse()
        raw = response.read(65537)
        if response.status != 200:
            # HTTP status is synthetic runner-only metadata; never print the
            # response body, certificate, headers or private etcd values.
            code = response.status if response.status in (
                400, 401, 403, 404, 408, 429, 500, 502, 503, 504) else 999
            raise RuntimeError("etcd-http-" + str(code))
        if len(raw) > 65536:
            raise RuntimeError("etcd-http-oversized")
        return json.loads(raw)
    finally:
        conn.close()


def open_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def docker(*args, timeout=30):
    return checked(["docker", *args], timeout=timeout)


def main():
    global STAGE
    STAGE = "immutable-image-identity"
    if (os.getenv("GITHUB_ACTIONS") != "true" or
            os.getenv("RUNNER_OS") != "Linux" or
            not IMAGE.startswith("quay.io/coreos/etcd@sha256:") or
            not quorum.HEX64.fullmatch(IMAGE.split(":")[-1].upper())):
        raise RuntimeError("fixed disposable GitHub CI and immutable etcd OCI required")
    label = secrets.token_hex(8)
    network = "waf-etcd-acceptance-" + label
    created = []
    net_created = False
    with tempfile.TemporaryDirectory(prefix="waf-etcd-real-ci-") as folder:
        root = Path(folder)
        root.chmod(0o700)
        STAGE = "disposable-ca"
        ca, ids = certs(root / "certs", ("vip-node-a", "vip-node-b", "ci4", "ci5", "ci6", "ci7", "ci8"))
        ports = [open_port() for _ in range(3)]
        while len(set(ports)) != 3:
            ports = [open_port() for _ in range(3)]
        try:
            STAGE = "private-etcd-network"
            # The three Raft peers use their own disposable bridge.
            # Host-only 127.0.0.1 published TLS ports must remain reachable
            # by the independent Python verifier; Docker --internal can
            # block its host-port DNAT path on some hosted runners.
            docker("network", "create", network)
            net_created = True
            peers = ",".join(f"ci{i}=http://ci{i}:2380" for i in (1, 2, 3))
            STAGE = "three-etcd-processes"
            for idx in (1, 2, 3):
                name = "ci" + str(idx)
                container = "waf-etcd-" + label + "-" + name
                data = root / "data" / name
                data.mkdir(mode=0o700, parents=True)
                args = [
                    "run", "-d", "--rm", "--name", container,
                    "--network", network, "--network-alias", name,
                    "--user", f"{os.geteuid()}:{os.getegid()}",
                    "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                    "--pids-limit", "128", "--memory", "512m",
                    "-v", str(root / "certs") + ":/certs:ro",
                    "-v", str(data) + ":/data",
                    "-p", f"127.0.0.1:{ports[idx-1]}:2379",
                    IMAGE,
                    "/usr/local/bin/etcd", "--name=" + name,
                    "--data-dir=/data",
                    "--listen-client-urls=https://0.0.0.0:2379",
                    "--advertise-client-urls=https://" + name + ":2379",
                    "--listen-peer-urls=http://0.0.0.0:2380",
                    "--initial-advertise-peer-urls=http://" + name + ":2380",
                    "--initial-cluster=" + peers,
                    "--initial-cluster-state=new",
                    "--initial-cluster-token=waf-ci-" + label,
                    "--cert-file=/certs/" + name + ".pem",
                    "--key-file=/certs/" + name + ".key",
                    "--trusted-ca-file=/certs/ca.pem",
                    "--client-cert-auth=true"
                ]
                docker(*args)
                created.append(container)
            writer_cert, writer_key, _ = ids["writer"]
            reader_cert, reader_key, _ = ids["reader"]
            addr = ("127.0.0.1", ports[0])
            keyname = "/gatewaycore/waf/fence/fleet-ci"
            keybase = base64.b64encode(keyname.encode("ascii")).decode("ascii")
            start = time.monotonic()
            cluster = None
            STAGE = "cluster-linearizable-readiness"
            last_class = "unclassified"
            while time.monotonic() - start < 45:
                try:
                    response = post(addr, ("/v3/kv/range",
                                {"key":keybase,"serializable":False}),
                                ca,writer_cert,writer_key)
                    cluster = response["header"]["cluster_id"]
                    break
                except (OSError, RuntimeError, KeyError, ValueError,
                        http.client.HTTPException, ssl.SSLError) as exc:
                    if isinstance(exc, RuntimeError) and str(exc) in {
                        "etcd-http-400", "etcd-http-401", "etcd-http-403",
                        "etcd-http-404", "etcd-http-408", "etcd-http-429",
                        "etcd-http-500", "etcd-http-502", "etcd-http-503",
                        "etcd-http-504", "etcd-http-999", "etcd-http-oversized"
                    }:
                        last_class = str(exc)
                    else:
                        last_class = type(exc).__name__
                    time.sleep(.5)
            if cluster is None:
                # CI uses only disposable synthetic certificates and a
                # random disposable cluster. Examine bounded Docker logs
                # privately; output ONLY allowlisted error *categories*,
                # never raw etcd logs, IPs, certificate paths or content.
                categories = {
                    "dial": ("failed to dial", "dial tcp", "connection refused"),
                    "raft": ("raft", "leader", "election"),
                    "dns": ("no such host", "lookup", "resolve"),
                    "peer": ("rafthttp", "peer became active", "peer became inactive"),
                    "tls": ("tls:", "certificate", "x509"),
                    "cluster": ("cluster id mismatch", "member id mismatch"),
                    "network": ("network is unreachable", "no route to host"),
                    "bind": ("bind: address already in use",),
                    "auth": ("authentication", "permission denied"),
                }
                for idx, item in enumerate(created):
                    report = subprocess.run(
                        ["docker","logs","--tail","200",item],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        stdin=subprocess.DEVNULL, timeout=8, check=False)
                    raw = (report.stdout + report.stderr)[:16384].decode(
                        "utf-8", "replace").lower()
                    labels = sorted(name for name, needles in categories.items()
                                    if any(token in raw for token in needles))
                    # Real etcd logs never leave the runner. Report only
                    # fixed known diagnostic event categories for debugging.
                    probes = {
                        "remote-peer-active": "peer became active",
                        "remote-peer-inactive": "peer became inactive",
                        "peer-connect-fail": "failed to connect to peer",
                        "peer-dial-error": "failed dialing",
                        "elected-leader": "elected leader",
                        "leader-changed": "leader changed",
                        "raft-proposal-timeout": "timed out",
                        "raft-no-leader": "no leader",
                        "peer-unauthorized": "unmatched member while checking peer urls",
                        "published-local": "published local member",
                        "serving-client": "serving client traffic securely",
                        "peer-stream-established": "established tcp streaming connection",
                        "peer-stream-rejected": "rejected connection",
                        "cluster-identity-mismatch": "cluster id mismatch",
                        "peer-remotes-missing": "no route to host",
                        "peer-unresolved": "no such host",
                        "quorum-unavailable": "not capable",
                    }
                    observed = sorted(name for name, needle in probes.items()
                                      if needle in raw)
                    print("ETCD_DISPOSABLE_MEMBER_DIAG_" + str(idx+1) + "=" +
                          (",".join(labels) if labels else "none") +
                          " EVENTS=" +
                          (",".join(observed) if observed else "none"), flush=True)
                states=[]
                for item in created:
                    try:
                        states.append(docker("inspect", "--format",
                            "{{.State.Running}}", item, timeout=5))
                    except (RuntimeError, subprocess.SubprocessError):
                        states.append("gone")
                if states != ["true", "true", "true"]:
                    STAGE = "etcd-container-not-running"
                else:
                    STAGE = "cluster-readiness-" + (last_class if last_class in {
                        "ConnectionRefusedError", "SSLCertVerificationError",
                        "SSLError", "TimeoutError", "RuntimeError", "KeyError",
                        "ValueError", "ConnectionResetError", "OSError",
                        "etcd-http-400", "etcd-http-401", "etcd-http-403",
                        "etcd-http-404", "etcd-http-408", "etcd-http-429",
                        "etcd-http-500", "etcd-http-502", "etcd-http-503",
                        "etcd-http-504", "etcd-http-999", "etcd-http-oversized"
                    } else "unknown")
                raise RuntimeError("three-member etcd leader never became ready")
            # In the disposable CI cluster, discover the real identities
            # independently using linearizable TLS requests. Production
            # endpoints must instead be supplied with preapproved member IDs
            # from the independently operated etcd inventory.
            endpoints = []
            for i, port in enumerate(ports, 1):
                observed = post(("127.0.0.1", port),
                                ("/v3/kv/range",
                                 {"key": keybase, "serializable": False}),
                                ca, writer_cert, writer_key)
                header = observed.get("header", {})
                if str(header.get("cluster_id")) != str(cluster):
                    raise RuntimeError("etcd endpoint changed approved cluster")
                member_id = quorum.integer(header.get("member_id"))
                endpoints.append({
                    "url": f"https://127.0.0.1:{port}",
                    "leafSha256": ids["ci" + str(i)][2],
                    "memberId": member_id
                })
            if len({item["memberId"] for item in endpoints}) != 3:
                raise RuntimeError("duplicate live Raft identity across TLS endpoints")
            verifier = quorum.EtcdQuorumFence(
                "fleet-ci", endpoints, cluster, ca, reader_cert, reader_key)
            value = {"schemaVersion":1,"kind":"waf",
                     "nodeIds":list(NODES),"revision":7,
                     "policySha256":P,"holder":secrets.token_hex(16)}
            encoded = base64.b64encode(json.dumps(
                value,sort_keys=True).encode("ascii")).decode("ascii")

            def grant_and_put():
                authority = writer.EtcdCasWriter(
                    "fleet-ci", endpoints, cluster, ca, writer_cert,
                    writer_key, NODES, 7, P, ttl=120)
                minted = authority.issue_once()
                if (minted["nodeIds"] != list(NODES) or
                        minted["policySha256"] != P or
                        minted["revision"] != 7):
                    raise RuntimeError("independent CAS writer issued wrong identity")
                return str(minted["leaseId"])

            STAGE = "lease-cas-grant"
            lease = grant_and_put()
            STAGE = "live-three-member-fence"
            if not verifier.assert_current(NODES,7,P,"preflight") or \
                    not verifier.assert_current(NODES,7,P,"before-apply-node-a"):
                raise RuntimeError("real three-member live etcd quorum did not grant fence")
            print("PASS: three actual etcd raft members with pinned mTLS and "
                  "fresh linearizable 2-of-3 WAF fencing")

            # A second controller cannot silently replace a live leased key.
            # Compare the actual pre/post linearizable key contents and Raft
            # revisions, not just a proto3 JSON boolean that etcd's gateway
            # may omit for false-valued responses.
            STAGE = "live-conflicting-writer-cas"
            before_cas = post(addr, ("/v3/kv/range", {
                "key":keybase, "serializable":False
            }), ca,writer_cert,writer_key)
            before_members=before_cas.get("kvs")
            if type(before_members) is not list or len(before_members)!=1:
                raise RuntimeError("active lease key unreadable before CAS")
            before_key=before_members[0]
            fields=("create_revision","mod_revision","version","lease","value")
            if any(field not in before_key for field in fields):
                raise RuntimeError("active lease metadata incomplete before CAS")
            try:
                duplicate = post(addr, ("/v3/kv/txn",{
                    "compare":[{"result":"EQUAL","target":"CREATE",
                                "key":keybase,"createRevision":"0"}],
                    "success":[{"requestPut":{"key":keybase,
                                              "value":encoded,"lease":lease}}],
                    "failure":[]
                }), ca,writer_cert,writer_key)
            except RuntimeError as error:
                # Only source-owned enum from the disposable HTTP client.
                candidate = str(error)
                STAGE = "competing-writer-" + (candidate if
                    candidate in {"etcd-http-400", "etcd-http-403",
                        "etcd-http-503", "etcd-http-999",
                        "etcd-http-oversized"} else "request")
                raise
            header = duplicate.get("header")
            # grpc-gateway/Proto3 may omit the zero/false-valued succeeded
            # field. Only an authenticated exact-cluster response with
            # a missing or literal-false field is eligible for verification.
            if (type(header) is not dict or
                    str(header.get("cluster_id")) != str(cluster) or
                    duplicate.get("succeeded") not in (None,False) or
                    duplicate.get("succeeded") is True or
                    type(duplicate.get("responses",[])) is not list or
                    duplicate.get("responses",[])):
                STAGE = "competing-writer-invalid-result"
                raise RuntimeError("second etcd WAF CAS response not a safe rejection")
            after_cas=post(addr, ("/v3/kv/range",{
                "key":keybase,"serializable":False
            }),ca,writer_cert,writer_key)
            actual=after_cas.get("kvs")
            if (type(actual) is not list or len(actual)!=1 or
                    any(before_key[field]!=actual[0].get(field) for field in fields)):
                STAGE = "competing-writer-mutated-signed-lease"
                raise RuntimeError("second etcd WAF writer changed existing Raft lease")

            # Independent revocation is a real quorum event, not a fake local
            # flag. The previously authorized controller must be refused.
            STAGE = "live-lease-revoke"
            post(addr, ("/v3/lease/revoke",{"ID":lease}),
                 ca,writer_cert,writer_key)
            if verifier.assert_current(NODES,7,P,"before-apply-node-b"):
                raise RuntimeError("revoked etcd lease authorized stale controller")
            renewed = grant_and_put()
            if verifier.assert_current(NODES,7,P,"before-apply-node-b"):
                raise RuntimeError("changed etcd Raft lease epoch reauthorized old controller")
            print("PASS: real etcd CAS rejects competing writer and revocation/"
                  "epoch rollover fences old transaction")

            # A completely separate signed Data Protection recovery epoch
            # must coexist with (and never impersonate) the WAF lease. The
            # exact same REAL three-member Raft quorum and TLS endpoints are
            # used; CI alone does not prove independently housed hosts.
            STAGE = "real-dp-recovery-issuer-construct"
            dp_issuer = dp_recovery.RecoveryLeaseIssuer(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 43, P, ttl=120)
            STAGE = "real-dp-recovery-cas-issue"
            try:
                dp_receipt = dp_issuer.issue_once()
            except Exception:
                # Only hardcoded source phase names leave the disposable
                # runner. Never echo etcd responses, tokens, private trust
                # paths or dynamic exception strings.
                stages = {"preflight", "read-absent-quorum",
                          "grant-new-lease", "validate-lease-grant",
                          "compare-and-swap", "validate-cas-header",
                          "verify-live-quorum"}
                STAGE = "real-dp-cas-" + (
                    dp_issuer.phase if dp_issuer.phase in stages else "unclassified")
                raise
            STAGE = "real-dp-cas-issued-receipt"
            if (dp_receipt["checkpointSha256"] != P or
                    dp_receipt["leaseId"] <= 0 or
                    dp_receipt["senderNodeId"] != "gateway-a" or
                    dp_receipt["receiverNodeId"] != "gateway-b"):
                raise RuntimeError("real Raft DP CAS did not pin signed recovery")
            STAGE = "real-dp-reader-construction"
            dp_verifier = dp_recovery.RecoveryFence(
                "fleet-ci", endpoints, cluster, ca, reader_cert, reader_key,
                "gateway-a", "gateway-b", 43, P)
            STAGE = "real-dp-read-only-majority"
            if not dp_verifier.current("preflight") or \
                    not dp_verifier.current("before-signed-restore"):
                raise RuntimeError("real 2/3 Raft quorum denied signed DP recovery")
            # The ORIGINAL WAF verifier is correctly fenced after the WAF
            # test's intentional revocation and epoch rollover. Instantiate
            # a new verifier for the newly issued WAF epoch; no unrelated DP
            # grant is allowed to mutate that independent namespace.
            STAGE = "real-dp-isolated-waf-namespace"
            fresh_waf = quorum.EtcdQuorumFence(
                "fleet-ci", endpoints, cluster, ca, reader_cert, reader_key)
            if (not fresh_waf.assert_current(NODES, 7, P, "preflight") or
                    not fresh_waf.assert_current(NODES, 7, P, "before-receipt") or
                    verifier.assert_current(NODES, 7, P, "before-receipt")):
                raise RuntimeError("independent DP lease changed existing WAF epoch")
            STAGE = "real-dp-durable-checkpoint-publication"
            publisher = dp_recovery.RecoveryRevisionPublisher(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 43, P)
            published = publisher.publish_once()
            if published["revision"] != 43 or published["checkpointSha256"] != P:
                raise RuntimeError("real DP durable publication mismatch")
            try:
                publisher.publish_once()
            except ValueError:
                pass
            else:
                raise RuntimeError("duplicate DP publication was accepted")
            STAGE = "real-dp-recovery-contested-cas"
            try:
                dp_issuer.issue_once()
            except ValueError:
                pass
            else:
                raise RuntimeError("second DP recovery CAS stole active lease")
            STAGE = "real-dp-recovery-revocation"
            post(addr, ("/v3/lease/revoke",
                        {"ID":str(dp_receipt["leaseId"])}),
                 ca, writer_cert, writer_key)
            if dp_verifier.current("after-signed-restore"):
                raise RuntimeError("revoked DP lease authorized a stale restore")
            # A NEW independent operator instance must acquire a new
            # epoch. The old issuer/verifier is pinned to the old holder and
            # must not silently self-renew after a revocation.
            dp_new_issuer = dp_recovery.RecoveryLeaseIssuer(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 43, P, ttl=120)
            dp_new_epoch = dp_new_issuer.issue_once()
            # The durable pointer survives revocation and cannot be replayed
            # even by a newly issued recovery epoch at the same revision.
            STAGE = "real-dp-durable-pointer-survives-revocation"
            fresh_publisher = dp_recovery.RecoveryRevisionPublisher(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 43, P)
            try:
                fresh_publisher.publish_once()
            except ValueError:
                pass
            else:
                raise RuntimeError("new lease permitted replay of durable revision")
            if dp_new_epoch["holder"] == dp_receipt["holder"] or \
                    dp_verifier.current("after-signed-restore"):
                raise RuntimeError("DP recovery old epoch survived Raft lease rollover")
            print("PASS: real three-member Raft signed-DP recovery CAS, "
                  "read-only mTLS verifier, namespace isolation and revocation")

            STAGE = "runtime-encrypted-ring-atomic-append"
            runtime_issuer = dp_recovery.RuntimeWriterLeaseIssuer(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 44, P, ttl=120)
            runtime_receipt = runtime_issuer.issue_once()
            runtime_writer = dp_recovery.RuntimeEncryptedRingWriter(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-a", "gateway-b", 44, P, node_id="gateway-a")
            name = "key-11111111-2222-3333-4444-555555555555.xml"
            ciphertext_fixture = (
                '<key id="11111111-2222-3333-4444-555555555555">'
                '<encryptedSecret xmlns="http://schemas.asp.net/2015/03/dataProtection" '
                'decryptorType="Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor, Microsoft.AspNetCore.DataProtection">'
                '<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#">'
                '<CipherData><CipherValue>fixture-only</CipherValue></CipherData>'
                '</EncryptedData></encryptedSecret></key>').encode()
            if runtime_writer.append_once(name,ciphertext_fixture) <= 0:
                raise RuntimeError("runtime append did not commit")
            try:
                runtime_writer.append_once(name,ciphertext_fixture)
            except ValueError:
                pass
            else:
                raise RuntimeError("runtime writer overwrote existing key")
            STAGE = "runtime-atomic-writer-handoff"
            successor = dp_recovery.RuntimeWriterLeaseIssuer(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-b", "gateway-a", 45, P, ttl=120)
            new_receipt = dp_recovery.RuntimeWriterHandoff(
                runtime_issuer,successor,runtime_receipt).replace_once()
            if new_receipt["senderNodeId"] != "gateway-b" or \
                    new_receipt["leaseId"] == runtime_receipt["leaseId"]:
                raise RuntimeError("atomic writer handoff failed")
            new_writer = dp_recovery.RuntimeEncryptedRingWriter(
                "fleet-ci", endpoints, cluster, ca, writer_cert, writer_key,
                "gateway-b", "gateway-a", 45, P, node_id="gateway-b")
            replacement_name = "key-99999999-8888-7777-6666-555555555555.xml"
            replacement_bytes = ciphertext_fixture.replace(
                b"11111111-2222-3333-4444-555555555555",
                b"99999999-8888-7777-6666-555555555555")
            try:
                runtime_writer.append_once(replacement_name,replacement_bytes)
            except ValueError:
                pass
            else:
                raise RuntimeError("old runtime writer survived atomic handoff")
            if new_writer.append_once(replacement_name,replacement_bytes)<=0:
                raise RuntimeError("successor runtime writer could not append")
            post(addr, ("/v3/lease/revoke",
                        {"ID":str(new_receipt["leaseId"])}),
                 ca, writer_cert, writer_key)
            replacement = "key-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.xml"
            replacement_xml = ciphertext_fixture.replace(
                b"11111111-2222-3333-4444-555555555555",
                b"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
            try:
                runtime_writer.append_once(replacement,replacement_xml)
            except ValueError:
                pass
            else:
                raise RuntimeError("revoked runtime writer appended a key")
            print("PASS: real etcd runtime encrypted XML append, duplicate and revoked writer refusal")

            STAGE = "real-dotnet-distributed-key-ring"
            dp_runtime = real_dp_runtime.run(root, endpoints, cluster, ca, ids,
                                             addr, post, checked)

            STAGE = "installed-vip-live-raft-recovery"
            vip_input = root / "vip-runtime-input.json"
            vip_input.write_text(json.dumps({
                "ca":ca,"endpoints":endpoints,"cluster":str(cluster),"writer":ids["writer"],
                "reader":ids["reader"],"nodeA":ids["vip-node-a"],"nodeB":ids["vip-node-b"],
                "providerServer":ids["ci4"],"bmc0":ids["ci5"],"bmc1":ids["ci6"],
                "agent0":ids["ci7"],"agent1":ids["ci8"],"containers":created
            }),encoding="ascii")
            vip_input.chmod(0o600)
            subprocess.run(["sudo","-n","env","GITHUB_ACTIONS=true","RUNNER_ENVIRONMENT=github-hosted",
                "DOTNET_ROOT="+os.environ["DOTNET_ROOT"],
                "PLAYWRIGHT_BROWSERS_PATH="+os.environ["PLAYWRIGHT_BROWSERS_PATH"],
                "VIP_BROWSER_NODE="+os.environ["VIP_BROWSER_NODE"],sys.executable,
                str(ROOT/"tests/WafEtcd/real_vip_recovery.py"),str(vip_input),
                os.environ["DP_RUNTIME_PRODUCT_DLL"]],check=True,timeout=1050)
            STAGE = "two-shipping-vip-nodes-live-raft-recovery"
            subprocess.run(["sudo","-n","env","GITHUB_ACTIONS=true","RUNNER_ENVIRONMENT=github-hosted",
                "DOTNET_ROOT="+os.environ["DOTNET_ROOT"],
                "PLAYWRIGHT_BROWSERS_PATH="+os.environ["PLAYWRIGHT_BROWSERS_PATH"],
                "VIP_BROWSER_NODE="+os.environ["VIP_BROWSER_NODE"],sys.executable,
                str(ROOT/"tests/WafEtcd/real_vip_recovery.py"),str(vip_input),
                os.environ["DP_RUNTIME_PRODUCT_DLL"],"--real-nodes"],check=True,timeout=1050)

            # Lose 2/3 independent members: the surviving member cannot
            # authorize mutation. No automatic rescue via a local JSON lease.
            STAGE = "loss-of-real-etcd-majority"
            for container in created[1:]:
                docker("stop", "--time", "1", container)
            if verifier.assert_current(NODES,7,P,"before-receipt"):
                raise RuntimeError("minority etcd partition authorized WAF mutation")
            STAGE = "real-dotnet-minority-denies-fresh-start"
            dp_runtime()
            print("PASS: actual two-member etcd outage denies transaction "
                  "and leaves recovery for independent reconciliation")
        finally:
            for container in reversed(created):
                try:
                    docker("rm", "-f", container, timeout=15)
                except (RuntimeError, subprocess.SubprocessError):
                    pass
            if net_created:
                try:
                    docker("network", "rm", network, timeout=15)
                except (RuntimeError, subprocess.SubprocessError):
                    pass


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError,
            subprocess.SubprocessError, ssl.SSLError, http.client.HTTPException) as error:
        print("FAIL: real isolated three-member etcd quorum test at "+STAGE,
              file=sys.stderr)
        # Never print exception messages, command arguments, response bodies,
        # child output or local variables: they may contain credentials.
        # Repository-relative source locations and exception type are enough
        # to distinguish failed assertions from subprocess/transport failures.
        print("Failure type: "+type(error).__name__, file=sys.stderr)
        for frame in traceback.extract_tb(error.__traceback__):
            source = Path(frame.filename).resolve()
            if source.is_relative_to(ROOT):
                print("Failure location: "+source.relative_to(ROOT).as_posix()
                      +":"+str(frame.lineno), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print("Child exit status: "+str(error.returncode), file=sys.stderr)
        raise SystemExit(1) from None
