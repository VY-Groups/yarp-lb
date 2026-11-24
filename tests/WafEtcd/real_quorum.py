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

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ops" / "waf"))
import etcd_quorum_fence as quorum

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


def certs(folder):
    folder.mkdir(mode=0o700)
    ca = folder / "ca.pem"
    ca_key = folder / "ca.key"
    checked(["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
             "-sha256", "-days", "1", "-subj", "/CN=Disposable WAF etcd CA",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(ca_key), "-out", str(ca)])
    identities = {}
    for subject in ("ci1", "ci2", "ci3", "writer", "reader"):
        key = folder / (subject + ".key")
        csr = folder / (subject + ".csr")
        crt = folder / (subject + ".pem")
        ext = folder / (subject + ".ext")
        server = subject.startswith("ci")
        ext.write_text(
            "extendedKeyUsage=" + ("serverAuth" if server else "clientAuth") +
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
        if response.status != 200 or len(raw) > 65536:
            raise RuntimeError("disposable etcd API refused request")
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
        ca, ids = certs(root / "certs")
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
                    last_class = type(exc).__name__
                    time.sleep(.5)
            if cluster is None:
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
                        "ValueError", "ConnectionResetError", "OSError"} else "unknown")
                raise RuntimeError("three-member etcd leader never became ready")
            endpoints = [
                {"url":f"https://127.0.0.1:{port}",
                 "leafSha256":ids["ci"+str(i)][2]}
                for i, port in enumerate(ports, 1)
            ]
            verifier = quorum.EtcdQuorumFence(
                "fleet-ci", endpoints, cluster, ca, reader_cert, reader_key)
            value = {"schemaVersion":1,"kind":"waf",
                     "nodeIds":list(NODES),"revision":7,
                     "policySha256":P,"holder":secrets.token_hex(16)}
            encoded = base64.b64encode(json.dumps(
                value,sort_keys=True).encode("ascii")).decode("ascii")

            def grant_and_put():
                granted = post(addr, ("/v3/lease/grant",{"TTL":"30"}),
                               ca,writer_cert,writer_key)
                lease = str(granted["ID"])
                txn = post(addr, ("/v3/kv/txn",{
                    "compare":[{"result":"EQUAL","target":"CREATE",
                                "key":keybase,"createRevision":"0"}],
                    "success":[{"requestPut":{"key":keybase,
                                              "value":encoded,"lease":lease}}],
                    "failure":[]
                }), ca,writer_cert,writer_key)
                if txn.get("succeeded") is not True:
                    raise RuntimeError("etcd atomic lease key reservation failed")
                return lease

            STAGE = "lease-cas-grant"
            lease = grant_and_put()
            STAGE = "live-three-member-fence"
            if not verifier.assert_current(NODES,7,P,"preflight") or \
                    not verifier.assert_current(NODES,7,P,"before-apply-node-a"):
                raise RuntimeError("real three-member live etcd quorum did not grant fence")
            print("PASS: three actual etcd raft members with pinned mTLS and "
                  "fresh linearizable 2-of-3 WAF fencing")

            # A second controller cannot silently replace a live leased key.
            STAGE = "live-conflicting-writer-cas"
            duplicate = post(addr, ("/v3/kv/txn",{
                "compare":[{"result":"EQUAL","target":"CREATE",
                            "key":keybase,"createRevision":"0"}],
                "success":[{"requestPut":{"key":keybase,
                                          "value":encoded,"lease":lease}}],
                "failure":[]
            }), ca,writer_cert,writer_key)
            if duplicate.get("succeeded") is not False:
                raise RuntimeError("second etcd WAF writer bypassed active lease")

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

            # Lose 2/3 independent members: the surviving member cannot
            # authorize mutation. No automatic rescue via a local JSON lease.
            STAGE = "loss-of-real-etcd-majority"
            for container in created[1:]:
                docker("stop", "--time", "1", container)
            if verifier.assert_current(NODES,7,P,"before-receipt"):
                raise RuntimeError("minority etcd partition authorized WAF mutation")
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
            subprocess.SubprocessError, ssl.SSLError, http.client.HTTPException):
        print("FAIL: real isolated three-member etcd quorum test at "+STAGE,
              file=sys.stderr)
        raise SystemExit(1)
