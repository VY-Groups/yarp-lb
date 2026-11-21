#!/usr/bin/env python3
"""Real disposable HTTPS collector acceptance with an independent client."""
import base64
import datetime
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import uuid
from unittest.mock import patch
from contextlib import contextmanager

# These Linux-only CI fixtures must exercise the shipping file-based secret
# readers. Use an owner-only RAM-backed directory, never ordinary disk or
# uploaded artifacts, and create each secret file with permissions atomically.
def fixture_secret_directory():
    with open("/proc/mounts", encoding="utf-8") as mounts:
        if not any(line.split()[1:3] == ["/dev/shm", "tmpfs"] for line in mounts):
            raise RuntimeError("CI requires /dev/shm tmpfs for disposable credentials")
    return tempfile.TemporaryDirectory(prefix="gatewaycore-ci-secrets-", dir="/dev/shm")

def write_private_fixture_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    if path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("Fixture secret file permissions are not owner-only")

def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS: " + message, flush=True)

def safe_receipt_response(status, response_body, receipt):
    """Reject malformed signed receipts instead of forwarding a modified value."""
    # Collector signatures use standard base64. Restrict the value to a small,
    # bounded ASCII alphabet before placing it in an HTTP response header.
    # Keep the value unchanged: the gateway verifies the exact signed bytes.
    if receipt is not None and (
        len(receipt) > 1024 or re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", receipt) is None
    ):
        return 503, b"", None
    return status, response_body, receipt

def run(*args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)

class ReceiptProxy:
    """Disposable TLS forwarder with a one-shot receipt barrier for race acceptance."""
    def __init__(self, collector_port, cert, tlskey, client_context):
        self.collector_port = collector_port
        self.client_context = client_context
        self.hold_operation = None
        self.hold_lock = threading.Lock()
        self.hold_entered = threading.Event()
        self.release_held = threading.Event()
        self.inventory_response_forwarded = threading.Event()
        owner = self
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def do_POST(self):
                if self.path != "/audit/v1/intents":
                    self.send_error(404)
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                operation = json.loads(body).get("operation")
                headers = {"Content-Type": self.headers.get("Content-Type", "application/json"),
                    "X-GC-Audit-Event-Id": self.headers.get("X-GC-Audit-Event-Id", ""),
                    "X-GC-Audit-Signature": self.headers.get("X-GC-Audit-Signature", "")}
                connection = http.client.HTTPSConnection("127.0.0.1", owner.collector_port,
                    context=owner.client_context, timeout=10)
                try:
                    connection.request("POST", self.path, body, headers)
                    upstream = connection.getresponse()
                    status = upstream.status
                    response_body = upstream.read()
                    receipt = upstream.getheader("X-GC-Audit-Receipt")
                except Exception:
                    status, response_body, receipt = 503, b"", None
                finally:
                    connection.close()
                with owner.hold_lock:
                    hold = status == 201 and operation == owner.hold_operation
                    if hold:
                        owner.hold_operation = None
                if hold:
                    owner.hold_entered.set()
                    if not owner.release_held.wait(20):
                        status, response_body, receipt = 503, b"", None
                # A malformed signed receipt must fail closed; stripping its
                # bytes would produce a different value from the one signed.
                status, response_body, receipt = safe_receipt_response(
                    status, response_body, receipt)
                self.send_response(status)
                if receipt:
                    # Belt-and-suspenders CR/LF encoding at the actual header
                    # sink for static analysis. The strict base64 guard above
                    # rejects these bytes first, so valid signatures are unchanged.
                    self.send_header("X-GC-Audit-Receipt",
                                     receipt.replace("\r", "").replace("\n", ""))
                self.send_header("Content-Length", str(len(response_body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if response_body:
                    self.wfile.write(response_body)
                self.wfile.flush()
                self.close_connection = True
                if operation == "INVENTORY_ADD_INTENT" and status == 201:
                    owner.inventory_response_forwarded.set()
            def log_message(self, *_):
                pass
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.minimum_version = ssl.TLSVersion.TLSv1_2
        server_context.load_cert_chain(str(cert), str(tlskey))
        self.server.socket = server_context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.url = f"https://127.0.0.1:{self.server.server_address[1]}/audit/v1/intents"
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self, *_):
        self.release_held.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
    def hold_once(self, operation):
        with self.hold_lock:
            self.hold_operation = operation
        self.hold_entered.clear()
        self.release_held.clear()
        self.inventory_response_forwarded.clear()

@contextmanager
def fixture_smtp_trust(ca):
    # Disposable Ubuntu Actions runner only; match the existing SMTP fixture's
    # trust setup and remove the temporary CA even on assertion failure.
    trust=Path("/usr/local/share/ca-certificates/gatewaycore-audit-smtp-fixture.crt")
    run("sudo","install","-m","0644",str(ca),str(trust))
    try:
        run("sudo","update-ca-certificates")
        yield
    finally:
        run("sudo","rm","-f",str(trust))
        run("sudo","update-ca-certificates")

def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable CI only")
    check(safe_receipt_response(201, b"ok", "signed") ==
          (201, b"ok", "signed"), "valid signed receipt is forwarded unchanged")
    for malformed in ("signed\rInjected: true", "signed\nInjected: true", "signed\x00", "signed\x09", "signed\u2028", "x" * 1025):
        check(safe_receipt_response(201, b"ok", malformed) ==
              (503, b"", None), "invalid or oversized signed receipt fails closed")
    dll = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="audit-fixture-") as tmp, fixture_secret_directory() as sd:
        root = Path(tmp)
        private = Path(sd)
        keys = private / "keys"
        keys.mkdir(mode=0o700)
        secret = secrets.token_bytes(32)
        write_private_fixture_file(keys / "node-a.key", secret)
        ledger = root / "ledger.jsonl"
        ledger.touch()
        signing = private / "signing.pem"
        public = root / "public.pem"
        cert = root / "tls.crt"
        tlskey = private / "tls.key"
        pfx = private / "tls.pfx"
        password = secrets.token_hex(16)
        pwd = private / "pfx-password"
        write_private_fixture_file(pwd, password)
        run("openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",str(signing))
        run("openssl","pkey","-in",str(signing),"-pubout","-out",str(public))
        run("openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","2",
            "-subj","/CN=127.0.0.1","-addext","subjectAltName=IP:127.0.0.1",
            "-keyout",str(tlskey),"-out",str(cert))
        run("openssl","pkcs12","-export","-inkey",str(tlskey),"-in",str(cert),
            "-out",str(pfx),"-passout","file:"+str(pwd))
        for f in [keys/"node-a.key",ledger,signing,pfx,pwd]:
            f.chmod(0o600)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1",0))
            port = sock.getsockname()[1]
        env = dict(os.environ, AUDIT_LISTEN_ADDRESS="127.0.0.1", AUDIT_LISTEN_PORT=str(port),
            AUDIT_LEDGER_FILE=str(ledger), AUDIT_NODE_KEYS_DIR=str(keys), AUDIT_SIGNING_PEM=str(signing),
            AUDIT_TLS_PFX=str(pfx), AUDIT_TLS_PASSWORD_FILE=str(pwd))
        ctx = ssl.create_default_context(cafile=str(cert))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        def request(body, event, key=secret, recorded=False):
            digest=hashlib.sha256(body).hexdigest().upper()
            purpose="GatewayCore-Audit-Event-v2" if recorded else "GatewayCore-Audit-Intent-v1"
            mac=hmac.digest(key, (purpose+"\n"+event+"\n"+digest).encode(), "sha256")
            conn=http.client.HTTPSConnection("127.0.0.1",port,context=ctx,timeout=5)
            try:
                conn.request("POST","/audit/v1/intents",body,{"Content-Type":"application/json",
                    "X-GC-Audit-Event-Id":event,"X-GC-Audit-Signature":base64.b64encode(mac).decode()})
                res=conn.getresponse()
                receipt=res.getheader("X-GC-Audit-Receipt")
                res.read()
                return res.status,receipt
            finally: conn.close()
        def intent(node="node-a", utc=None):
            event=uuid.uuid4().hex
            body=json.dumps(dict(schema=1,eventId=event,node=node,
                utc=(utc or datetime.datetime.now(datetime.timezone.utc)).isoformat(),
                actor="lab-operator",operation="CONFIG_APPLY_INTENT",revision="A"*64,targetDigest="B"*64),
                separators=(",",":")).encode()
            return body,event
        def start():
            log=(root/"collector.log").open("ab")
            try: proc=subprocess.Popen(["dotnet",str(dll)],env=env,stdout=log,stderr=log)
            finally: log.close()
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if proc.poll() is not None: break
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.2): return proc
                except OSError: time.sleep(.1)
            if proc.poll() is None: proc.kill(); proc.wait()
            raise AssertionError((root/"collector.log").read_text())
        def stop(proc):
            proc.terminate()
            try: proc.wait(timeout=10)
            except subprocess.TimeoutExpired: proc.kill();proc.wait()
        def verify_receipt(body,event,signature,recorded=False):
            msg=root/"receipt-input"
            sig=root/"receipt-signature"
            purpose="GatewayCore-Audit-Event-Receipt-v2" if recorded else "GatewayCore-Audit-Receipt-v1"
            msg.write_bytes((purpose+"\n"+event+"\n"+hashlib.sha256(body).hexdigest().upper()).encode())
            sig.write_bytes(base64.b64decode(signature,validate=True))
            run("openssl","dgst","-sha256","-verify",str(public),"-signature",str(sig),
                "-sigopt","rsa_padding_mode:pss","-sigopt","rsa_pss_saltlen:auto",str(msg))
        proc=start()
        try:
            body,event=intent()
            status,receipt=request(body,event)
            check(status==201 and receipt and len(ledger.read_bytes())>0,"HTTPS receipt after durable ledger record")
            verify_receipt(body,event,receipt)
            check(True,"independent RSA-PSS receipt verification")
            check(request(body,event)==(409,None),"duplicate event rejected")
            x,y=intent()
            check(request(x,y,b"X"*32)==(403,None),"incorrect node HMAC rejected")
            x,y=intent("unknown-node")
            check(request(x,y)==(403,None),"unknown node rejected")
            x,y=intent(utc=datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(minutes=5))
            check(request(x,y)==(409,None),"stale signed intent rejected")
            x,y=intent()
            duplicate=x[:-1]+b',"schema":1}'
            check(request(duplicate,y)==(403,None),"duplicate JSON field rejected")
            check(len(ledger.read_text().splitlines())==1,"invalid requests do not append")
        finally: stop(proc)
        proc=start()
        try:
            check(request(body,event)==(409,None),"restart retains replay protection")
            x,y=intent()
            status,receipt=request(x,y)
            check(status==201 and receipt,"new valid intent after restart")
            verify_receipt(x,y,receipt)
        finally: stop(proc)
        original=ledger.read_bytes()
        records=original.splitlines(keepends=True)
        head=json.loads(records[-1])["Hash"]
        verify=["dotnet",str(dll),"--verify-ledger","2",head]
        run(*verify,env=env)
        check(True,"restart chain and independent checkpoint verified")
        ledger.write_bytes(records[0])
        failed=subprocess.run(verify,env=env,capture_output=True)
        check(failed.returncode!=0,"independent checkpoint detects valid-prefix truncation")
        entry=json.loads(records[0])
        entry["Hash"]="0"*64
        ledger.write_bytes(json.dumps(entry).encode()+b"\n"+records[1])
        failed=subprocess.run(["dotnet",str(dll),"--verify-ledger"],env=env,capture_output=True)
        check(failed.returncode!=0,"edited signed chain rejected")
        ledger.write_bytes(original[:-1])
        failed=subprocess.run(["dotnet",str(dll),"--verify-ledger"],env=env,capture_output=True)
        check(failed.returncode!=0,"partial record rejected without auto-repair")
        ledger.write_bytes(original)
        run(*verify,env=env)
        print("AUDIT_COLLECTOR_HTTPS_SUCCESS",flush=True)

        # Use the shipping gateway and the shipping collector, not a fake
        # HttpMessageHandler. Check the exact serialized mutation digest and
        # prove outage denial leaves the persisted credentials/stamps unchanged.
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"E2E"))
        from real_control_center import backend, gateway, openssl_state, port as free_port, Client
        from real_smtp_otp import local_smtp, MAIL_USER, MAIL_PASSWORD
        cwd=Path(__file__).resolve().parents[2]/"control-center"
        gateway_dll=cwd/"bin/Release/net10.0/GatewayCoreYarp.dll"
        gateway_root=root/"gateway-fixture"
        operations=[("USER_CREATE_INTENT","/admin/api/users",
                        {"username":"operator","password":"Operator-fixture-pass-123!","email":"operator@example.invalid","role":"Operator"}),
                    ("USER_PASSWORD_RESET_INTENT","/admin/api/users/operator/password",{"password":"Reset-fixture-password-123!"}),
                    ("USER_DISABLE_INTENT","/admin/api/users/operator/disable",{}),
                    ("USER_ENABLE_INTENT","/admin/api/users/operator/enable",{})]
        gateway_env={"GATEWAY_AUDIT_INTENT_URL":f"https://127.0.0.1:{port}/audit/v1/intents",
            "GATEWAY_AUDIT_NODE_ID":"node-a","GATEWAY_AUDIT_SENDER_KEY_FILE":str(keys/"node-a.key"),
            "GATEWAY_AUDIT_COLLECTOR_PUBLIC_KEY_FILE":str(public),"SSL_CERT_FILE":str(cert)}
        smtp_port=free_port()
        with backend() as upstream, ReceiptProxy(port, cert, tlskey, ctx) as receipt_proxy:
            openssl_state(gateway_root,upstream)
            gateway_env['GATEWAY_AUDIT_INTENT_URL']=receipt_proxy.url
            with local_smtp(gateway_root,smtp_port) as (mailbox, smtp_ca), fixture_smtp_trust(smtp_ca):
                trust_bundle=root/"gateway-trusted.pem"
                trust_bundle.write_bytes(cert.read_bytes()+smtp_ca.read_bytes())
                gateway_env["SSL_CERT_FILE"]=str(trust_bundle)
                with patch.dict(os.environ,gateway_env), gateway(cwd,gateway_dll,gateway_root,free_port()) as base:
                    admin=Client(base)
                    admin.bootstrap("reviewer","Reviewer-fixture-pass-123!","reviewer@example.invalid")
                    state=gateway_root/"state"/"admin-users.json"
                    for index,(operation,route,body) in enumerate(operations):
                        before=state.read_bytes()
                        admin.request("POST",route,body,expect=503)
                        check(state.read_bytes()==before,"collector outage denies "+operation+" without account mutation")
                        proc=start()
                        try:
                            admin.request("POST",route,body)
                            after=state.read_bytes()
                            check(after!=before,"verified receipt authorizes "+operation)
                        finally: stop(proc)
                        rows=ledger.read_text().splitlines()
                        check(len(rows)==3+index,"one retained intent for "+operation)
                        retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                        check(retained["operation"]==operation and retained["actor"]=="reviewer" and
                            retained["revision"]==hashlib.sha256(before).hexdigest().upper() and
                            retained["targetDigest"]==hashlib.sha256(after).hexdigest().upper(),
                            "retained receipt binds exact before/after bytes for "+operation)
                        check("password" not in retained and "email" not in retained,
                            "no plaintext credentials or email fields exported")
                    operator=Client(base)
                    operator.login("operator","Reset-fixture-password-123!")
                    check(operator.session()["role"]=="Operator","account recovery retains correct role")
                    inventory=gateway_root/"state"/"inventory.json"
                    fleet=gateway_root/"state"/"fleet-gateways.json"
                    fleet_body={"id":"lab-node","url":"https://127.0.0.1:19443/",
                        "clientCertificateThumbprint":"A"*64}
                    # Fleet mutations require a confirmed multi-gateway design.
                    # First prove that the real onboarding gate still denies the
                    # request; then satisfy it through the public management API.
                    admin.request("POST","/admin/api/fleet",fleet_body,expect=409)
                    check(not fleet.exists(),"unconfirmed topology cannot register fleet node")
                    topology=admin.request("GET","/admin/api/onboarding")
                    plan={"mode":"ha-pair","controlPlane":"single-controller","dataStore":"local-file",
                          "accessPattern":"segmented","publicVip":"fixture-vip.example.invalid",
                          "upstreamHealthAware":True,"requireIndependentApproval":True,
                          "gateways":[{"id":"lab-node","hostname":"gateway-a.example.invalid","agentUrl":fleet_body["url"]},
                                      {"id":"lab-node-b","hostname":"gateway-b.example.invalid","agentUrl":"https://127.0.0.1:19444/"}],
                          "workloads":[{"id":"origin-a","application":"fixture","zone":"restricted","hostingEngine":"http","url":f"http://127.0.0.1:{upstream}/"},
                                       {"id":"origin-b","application":"fixture","zone":"restricted","hostingEngine":"http","url":f"http://127.0.0.1:{upstream}/"}]}
                    validation=admin.request("POST","/admin/api/onboarding/validate",{"plan":plan})
                    check(validation["issues"]==[],"valid HA design before fleet registration audit acceptance")
                    topology_file=gateway_root/"state"/"onboarding-topology.json"
                    for confirmed,operation in [(False,"TOPOLOGY_DRAFT_INTENT"),(True,"TOPOLOGY_CONFIRM_INTENT")]:
                        before=topology_file.read_bytes() if topology_file.exists() else b""
                        count=len(ledger.read_text().splitlines())
                        request_body={"plan":plan,"confirmDesign":confirmed,"expectedRevision":topology["revision"]}
                        admin.request("POST","/admin/api/onboarding",request_body,expect=503)
                        check((topology_file.read_bytes() if topology_file.exists() else b"")==before,
                              "outage leaves topology unchanged: "+operation)
                        proc=start()
                        try:
                            topology=admin.request("POST","/admin/api/onboarding",request_body)
                        finally: stop(proc)
                        rows=ledger.read_text().splitlines()
                        retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                        check(len(rows)==count+1 and retained["operation"]==operation and
                              retained["revision"]==hashlib.sha256(before).hexdigest().upper() and
                              retained["targetDigest"]==hashlib.sha256(topology_file.read_bytes()).hexdigest().upper(),
                              "signed receipt binds persisted topology: "+operation)
                    check(topology["status"]=="design-confirmed","real onboarding API confirms HA design")
                    change={"reason":"Disposable audit regression review","payload":{"routes":{},"clusters":{},"revision":"fixture-stale"}}
                    before_requests=admin.request("GET","/admin/api/change-requests")
                    operator.request("POST","/admin/api/change-requests",change,expect=503)
                    check(admin.request("GET","/admin/api/change-requests")==before_requests,
                          "collector outage prevents change submission")
                    count=len(ledger.read_text().splitlines())
                    proc=start()
                    try:
                        pending=operator.request("POST","/admin/api/change-requests",change)
                    finally: stop(proc)
                    request_file=gateway_root/"state"/"change-requests"/(pending["id"]+".json")
                    before=request_file.read_bytes()
                    rows=ledger.read_text().splitlines()
                    retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                    check(len(rows)==count+1 and retained["operation"]=="CHANGE_REQUEST_INTENT" and
                          retained["actor"]=="operator" and retained["targetDigest"]==hashlib.sha256(before).hexdigest().upper(),
                          "submission receipt binds exact pending request")
                    decision="/admin/api/change-requests/"+pending["id"]+"/decision"
                    reject={"decision":"reject","reason":"Disposable independent rejection"}
                    operator.request("POST",decision,reject,expect=403)
                    admin.request("POST",decision,reject,expect=503)
                    check(request_file.read_bytes()==before,"outage leaves review status pending")
                    count=len(ledger.read_text().splitlines())
                    proc=start()
                    try:
                        reviewed=admin.request("POST",decision,reject)
                    finally: stop(proc)
                    rows=ledger.read_text().splitlines()
                    retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                    check(reviewed["status"]=="Rejected" and len(rows)==count+1 and
                          retained["operation"]=="CHANGE_REJECT_INTENT" and retained["actor"]=="reviewer" and
                          retained["revision"]==hashlib.sha256(before).hexdigest().upper() and
                          retained["targetDigest"]==hashlib.sha256(request_file.read_bytes()).hexdigest().upper(),
                          "independent rejection receipt binds exact reviewed request")
                    # An operator must not be able to register a fleet node even
                    # if the collector is available. Preserve the existing RBAC.
                    operator.request("POST","/admin/api/fleet",fleet_body,expect=403)
                    check(not fleet.exists(),"operator cannot register fleet node")
                    resources=[
                        (operator,"operator",inventory,"INVENTORY_ADD_INTENT","POST","/admin/api/inventory",
                         {"id":"lab-service","name":"Lab service","type":"Service",
                          "address":"fixture.example.invalid","notes":"not exported"}),
                        (operator,"operator",inventory,"INVENTORY_DELETE_INTENT","DELETE","/admin/api/inventory/lab-service",{}),
                        (admin,"reviewer",fleet,"FLEET_REGISTER_INTENT","POST","/admin/api/fleet",fleet_body),
                        (admin,"reviewer",fleet,"FLEET_UNREGISTER_INTENT","DELETE","/admin/api/fleet/lab-node",{}),
                    ]
                    for client,actor,state,operation,method,route,payload in resources:
                        existed=state.exists()
                        before=state.read_bytes() if existed else b""
                        count=len(ledger.read_text().splitlines())
                        client.request(method,route,payload,expect=503)
                        check(state.exists()==existed and (not existed or state.read_bytes()==before),
                              "collector outage leaves resource unchanged: "+operation)
                        proc=start()
                        try:
                            client.request(method,route,payload)
                            after=state.read_bytes()
                        finally: stop(proc)
                        check(after!=before,"signed receipt permits "+operation)
                        rows=ledger.read_text().splitlines()
                        check(len(rows)==count+1,"exactly one retained intent: "+operation)
                        retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                        check(retained["operation"]==operation and retained["actor"]==actor and
                              retained["revision"]==hashlib.sha256(before).hexdigest().upper() and
                              retained["targetDigest"]==hashlib.sha256(after).hexdigest().upper(),
                              "retained before/after digests match exact resource bytes: "+operation)
                        check(set(retained)=={"schema","eventId","node","utc","actor","operation","revision","targetDigest"},
                              "no internal address, certificate or inventory notes exported")
                    check(json.loads(inventory.read_bytes())==[] and json.loads(fleet.read_bytes())==[],
                          "resource deletion persisted after valid receipts")
                    # Deterministically hold the account-state lock while a
                    # separate, valid resource receipt is returned. The resource
                    # write must wait until the account reset has committed.
                    proc=start()
                    try:
                        admin.request("POST","/admin/api/users",
                            {"username":"reviewer2","password":"Reviewer-two-fixture-pass-123!",
                             "email":"reviewer2@example.invalid","role":"Administrator"})
                        admin2=Client(base)
                        admin2.login("reviewer2","Reviewer-two-fixture-pass-123!")
                        receipt_proxy.hold_once("USER_PASSWORD_RESET_INTENT")
                        reset_done=threading.Event()
                        inventory_done=threading.Event()
                        results={}
                        errors={}
                        def reset_operator():
                            try:
                                results["reset"]=admin.request("POST","/admin/api/users/operator/password",
                                    {"password":"Concurrent-reset-fixture-password-456!"})
                            except Exception as ex: errors["reset"]=repr(ex)
                            finally: reset_done.set()
                        def add_during_reset():
                            try:
                                results["inventory"]=admin2.request("POST","/admin/api/inventory",
                                    {"id":"race-service","name":"Race service","type":"Service",
                                     "address":"fixture.example.invalid","notes":"race fixture"})
                            except Exception as ex: errors["inventory"]=repr(ex)
                            finally: inventory_done.set()
                        reset_thread=threading.Thread(target=reset_operator,daemon=True)
                        inventory_thread=threading.Thread(target=add_during_reset,daemon=True)
                        reset_thread.start()
                        check(receipt_proxy.hold_entered.wait(10),
                            "collector accepted reset receipt while account lock remains held")
                        inventory_thread.start()
                        check(receipt_proxy.inventory_response_forwarded.wait(10),
                            "collector accepted resource receipt while account mutation is pending")
                        check(not inventory_done.wait(1.0),
                            "resource mutation cannot commit while account mutation lock is held")
                        receipt_proxy.release_held.set()
                        reset_thread.join(timeout=15)
                        inventory_thread.join(timeout=15)
                        check(reset_done.is_set() and inventory_done.is_set() and not errors,
                            "serialized account reset and resource mutation complete")
                        check(json.loads(inventory.read_bytes())[0]["Id"]=="race-service",
                            "resource mutation commits after account lock release")
                        admin2.request("DELETE","/admin/api/inventory/race-service",{})
                        check(json.loads(inventory.read_bytes())==[],
                            "race fixture resource removed through the signed receipt gate")
                        # Same actor must be revalidated after a signed receipt
                        # returns: hold reviewer2's inventory receipt, reset that
                        # account as administrator, then release the stale receipt.
                        revocation_before_exists=inventory.exists()
                        revocation_before=inventory.read_bytes() if revocation_before_exists else b""
                        receipt_proxy.hold_once("INVENTORY_ADD_INTENT")
                        revoked_done=threading.Event()
                        revoked_errors={}
                        def add_after_revocation():
                            try:
                                admin2.request("POST","/admin/api/inventory",
                                    {"id":"revoked-service","name":"Revoked service","type":"Service",
                                     "address":"fixture.example.invalid","notes":"must not persist"},expect=403)
                            except Exception as ex: revoked_errors["revoked"]=repr(ex)
                            finally: revoked_done.set()
                        revoked_thread=threading.Thread(target=add_after_revocation,daemon=True)
                        revoked_thread.start()
                        check(receipt_proxy.hold_entered.wait(10),
                            "collector accepted reviewer2 inventory receipt before revocation")
                        admin.request("POST","/admin/api/users/reviewer2/password",
                            {"password":"Reviewer-two-reset-fixture-789!"})
                        receipt_proxy.release_held.set()
                        revoked_thread.join(timeout=15)
                        check(revoked_done.is_set() and not revoked_errors,
                            "same-actor password reset revokes pending inventory mutation with HTTP 403")
                        check(inventory.exists()==revocation_before_exists and
                              (not inventory.exists() or inventory.read_bytes()==revocation_before),
                            "revoked receipt leaves inventory byte-for-byte unchanged")
                        check(not admin2.session()["authenticated"],
                            "password reset invalidates reviewer2's previously authenticated session")
                        # Real two-person routing approval while a genuine
                        # collector receipt is held and its actor revoked.
                        admin2=Client(base)
                        admin2.login("reviewer2","Reviewer-two-reset-fixture-789!")
                        config_path=gateway_root/"state"/"config"/"appsettings.json"
                        config_before=config_path.read_bytes()
                        proxy=json.loads(config_before)["ReverseProxy"]
                        draft=admin.request("POST","/admin/api/change-requests",{
                            "reason":"Disposable routing authorization race",
                            "payload":{"routes":proxy["Routes"],"clusters":proxy["Clusters"],
                                "disabled":proxy.get("AdminDisabledDestinations",{}),
                                "revision":hashlib.sha256(config_before).hexdigest().upper()}})
                        draft_path=gateway_root/"state"/"change-requests"/(draft["id"]+".json")
                        draft_before=draft_path.read_bytes()
                        receipt_proxy.hold_once("CONFIG_APPLY_INTENT")
                        approval_errors=[]
                        def approve_revoked():
                            try:
                                admin2.request("POST","/admin/api/change-requests/"+draft["id"]+"/decision",
                                    {"decision":"approve","reason":"Disposable independent review"},expect=403)
                            except Exception as ex: approval_errors.append(repr(ex))
                        approval=threading.Thread(target=approve_revoked,daemon=True)
                        approval.start()
                        check(receipt_proxy.hold_entered.wait(10),"valid routing approval receipt held before actor revocation")
                        admin.request("POST","/admin/api/users/reviewer2/password",
                            {"password":"Reviewer-two-final-fixture-456!"})
                        receipt_proxy.release_held.set()
                        approval.join(timeout=15)
                        check(not approval.is_alive() and not approval_errors and
                              config_path.read_bytes()==config_before and draft_path.read_bytes()==draft_before,
                            "revoked reviewer cannot publish routing config or mark draft approved")
                    finally:
                        receipt_proxy.release_held.set()
                        stop(proc)
                    # The race fixture reset the operator password and rotated its
                    # security stamp. Verify the old session is invalid, then use
                    # a newly authenticated Operator for the subsequent RBAC checks.
                    check(not operator.session()["authenticated"],
                          "concurrent reset invalidates the original operator session")
                    operator=Client(base)
                    operator.login("operator","Concurrent-reset-fixture-password-456!")
                    check(operator.session()["role"]=="Operator",
                          "fresh operator session retains its role after reset")
                    # The real local STARTTLS server permits testing the proof
                    # mutation as well as encrypted SMTP settings, without an
                    # external provider or a certificate-validation bypass.
                    mail=gateway_root/"state"/"mail-settings.json"
                    proof=gateway_root/"state"/"mail-test-proof.sha256"
                    directory=gateway_root/"state"/"active-directory.json"
                    mail_payload={"enabled":False,"host":"127.0.0.1","port":smtp_port,
                                  "from":"reviewer@example.invalid","username":MAIL_USER,
                                  "password":MAIL_PASSWORD,"startTls":True}
                    directory_payload={"enabled":False,"host":"directory.example.invalid","port":636,
                                       "searchBaseDn":"DC=example,DC=invalid","bindUsername":"fixture-bind",
                                       "password":"CI-only-directory-secret","adminGroupDn":"CN=Admins,DC=example,DC=invalid",
                                       "operatorGroupDn":"","viewerGroupDn":""}
                    for operation,route,payload,state in [
                        ("MAIL_SETTINGS_INTENT","/admin/api/mail",mail_payload,mail),
                        ("MAIL_PROOF_INTENT","/admin/api/mail/test",{},proof),
                        ("DIRECTORY_SETTINGS_INTENT","/admin/api/directory",directory_payload,directory)]:
                        check(not state.exists(),"new settings/proof starts absent")
                        operator.request("POST",route,payload,expect=403)
                        count=len(ledger.read_text().splitlines())
                        admin.request("POST",route,payload,expect=503)
                        check(not state.exists(),"outage denied persistent "+operation)
                        if operation=="MAIL_PROOF_INTENT":
                            check(len(mailbox.messages)==1,"real STARTTLS delivered but proof is not saved without receipt")
                        proc=start()
                        try:
                            admin.request("POST",route,payload)
                            after=state.read_bytes()
                        finally: stop(proc)
                        rows=ledger.read_text().splitlines()
                        retained=json.loads(base64.b64decode(json.loads(rows[-1])["Body"]))
                        check(len(rows)==count+1 and retained["operation"]==operation and retained["actor"]=="reviewer" and
                              retained["revision"]==hashlib.sha256(b"").hexdigest().upper() and
                              retained["targetDigest"]==hashlib.sha256(after).hexdigest().upper(),
                              "signed receipt binds exact persisted "+operation)
                    check(len(mailbox.messages)==2 and mailbox.auth_calls>0,"authenticated SMTP proof succeeds only with external receipt")
                    check(MAIL_PASSWORD.encode() not in mail.read_bytes() and b"CI-only-directory-secret" not in directory.read_bytes(),
                          "SMTP and LDAPS bind credentials remain encrypted")
                    check(admin.request("GET","/admin/api/mail")["deliveryVerified"],
                          "SMTP delivery proof remains valid for the exact saved configuration")
        print("MAIL_DIRECTORY_EXTERNAL_AUDIT_SUCCESS",flush=True)
        print("INVENTORY_FLEET_EXTERNAL_AUDIT_SUCCESS",flush=True)
        print("ACCOUNT_MUTATION_EXTERNAL_AUDIT_SUCCESS",flush=True)

        # First fixture uses a disposable receipt proxy; it has stopped.
        # The independent outbox fixture connects directly to the collector.
        gateway_env["GATEWAY_AUDIT_INTENT_URL"]=f"https://127.0.0.1:{port}/audit/v1/intents"
        gateway_env["SSL_CERT_FILE"]=str(cert)
        spool=root/"private-spool"
        spool.mkdir(mode=0o700)
        gateway_env["GATEWAY_AUDIT_OUTBOX_DIR"]=str(spool)
        queued_root=root/"queued-gateway"
        with backend() as upstream:
            openssl_state(queued_root,upstream)
            with patch.dict(os.environ,gateway_env):
                with gateway(cwd,gateway_dll,queued_root,free_port()) as base:
                    admin=Client(base)
                    admin.bootstrap("reviewer","Reviewer-fixture-pass-123!","reviewer@example.invalid")
                    admin.request("POST","/admin/api/setup/freeze",{
                        "frozen":True,"reason":"Disposable outage freeze regression"})
                    admin.request("POST","/admin/api/setup/freeze",{
                        "frozen":False,"reason":"Disposable outage unfreeze regression"})
                    profile=admin.request("GET","/admin/api/organization")
                    admin.request("PUT","/admin/api/organization",{
                        "organizationName":"Disposable Audit Fixture","sector":"technology",
                        "region":"Lab","notes":"","expectedRevision":profile["revision"]})
                    files=list(spool.glob("*.event"))
                    check(bool(files),"collector outage leaves durable gateway audit records")
                    entries=[json.loads(p.read_bytes()) for p in files]
                    actions=[json.loads(base64.b64decode(e["Payload"]))["operation"] for e in entries]
                    for action in ("ROUTING_CHANGE_FREEZE_ENABLED","ROUTING_CHANGE_FREEZE_DISABLED",
                                   "ORGANIZATION_PROFILE_UPDATED"):
                        check(actions.count(action)==1,"shared audit writer queued "+action+" exactly once")
                    local_lines=(queued_root/"state"/"admin-audit.jsonl").read_bytes().splitlines()
                    hashes={hashlib.sha256(line).hexdigest().upper() for line in local_lines}
                    check(all(json.loads(base64.b64decode(e["Payload"]))["targetDigest"] in hashes for e in entries),
                          "queued event binds exact local audit record bytes")
                    check(admin.request("GET","/admin/api/audit/delivery")["pending"]>=len(entries),
                          "administrator sees pending delivery without exported details")
                # Restart the shipping gateway before the collector is restored.
                with gateway(cwd,gateway_dll,queued_root,free_port()) as base:
                    check(all((spool/(e["Id"]+".event")).exists() for e in entries),
                          "gateway restart preserves every original queued event")
                    admin=Client(base)
                    admin.login("reviewer","Reviewer-fixture-pass-123!")
                    proc=start()
                    try:
                        deadline=time.monotonic()+30
                        while time.monotonic()<deadline and list(spool.glob("*.event")):
                            time.sleep(.2)
                        check(not list(spool.glob("*.event")),"real HTTPS collector drains persistent gateway queue")
                        check(admin.request("GET","/admin/api/audit/delivery")["pending"]==0,
                              "delivery status reports drained queue")
                        retained=[json.loads(base64.b64decode(json.loads(line)["Body"])) for line in ledger.read_text().splitlines()]
                        for entry in entries:
                            event_id=entry["Id"]
                            body=base64.b64decode(entry["Payload"])
                            record=json.loads(body)
                            check(sum(e["eventId"]==event_id for e in retained)==1 and record in retained,
                                  "original event retained once with exact digest")
                            count=len(ledger.read_text().splitlines())
                            status,receipt=request(body,event_id,recorded=True)
                            check(status==201 and receipt,"lost recorded-event receipt can be recovered")
                            verify_receipt(body,event_id,receipt,recorded=True)
                            check(len(ledger.read_text().splitlines())==count,"exact event retry does not append twice")
                            check(request(body,event_id)==(403,None),"intent MAC cannot authenticate historical event")
                            changed=dict(record,operation="CHANGED_EVENT")
                            changed_bytes=json.dumps(changed,separators=(",",":")).encode()
                            check(request(changed_bytes,event_id,recorded=True)==(409,None),
                                  "same event ID with changed bytes cannot obtain receipt")
                    finally: stop(proc)
                # Correlation must work with the real shipping gateway and
                # collector. A distinct intent receipt never authorizes replay.
                with gateway(cwd,gateway_dll,queued_root,free_port()) as base:
                    admin=Client(base)
                    admin.login("reviewer","Reviewer-fixture-pass-123!")
                    state=queued_root/"state"/"admin-users.json"
                    proc=start()
                    try:
                        actions_by_intent={"USER_CREATE_INTENT":"USER_CREATED",
                            "USER_PASSWORD_RESET_INTENT":"PASSWORD_RESET",
                            "USER_DISABLE_INTENT":"USER_OFFBOARDED",
                            "USER_ENABLE_INTENT":"USER_REENABLED"}
                        for operation,route,body in operations:
                            before=state.read_bytes()
                            admin.request("POST",route,body)
                            after=state.read_bytes()
                            deadline=time.monotonic()+30
                            while time.monotonic()<deadline and list(spool.glob("*.event")):
                                time.sleep(.1)
                            check(not list(spool.glob("*.event")),"correlated events delivered")
                            ledger_rows=[json.loads(base64.b64decode(json.loads(line)["Body"]))
                                         for line in ledger.read_text().splitlines()]
                            intents=[v for v in ledger_rows if v["schema"]==1 and v["operation"]==operation]
                            intent=intents[-1]
                            check(intent["revision"]==hashlib.sha256(before).hexdigest().upper() and
                                  intent["targetDigest"]==hashlib.sha256(after).hexdigest().upper(),
                                  "correlated intent binds exact mutation bytes")
                            correlation=hashlib.sha256(intent["eventId"].encode("ascii")).hexdigest().upper()
                            linked=[v for v in ledger_rows if v["schema"]==2 and v["revision"]==correlation]
                            check(sorted(v["operation"] for v in linked)==sorted(
                                ["ACCOUNT_MUTATION_PREPARED",actions_by_intent[operation]]),
                                "one prepared and one successful outcome correlate to "+operation)
                            lines=(queued_root/"state"/"admin-audit.jsonl").read_bytes().splitlines()
                            exact={hashlib.sha256(line).hexdigest().upper() for line in lines
                                   if json.loads(line).get("intentId")==intent["eventId"]}
                            check(len(exact)==2 and all(v["targetDigest"] in exact for v in linked),
                                  "correlated envelopes bind both exact local rows")
                        # Inject a queue storage fault after startup. The collector
                        # still authorizes the intent, but precommit storage must deny.
                        before=state.read_bytes()
                        (spool/"incomplete.tmp").write_text("fixture fault")
                        admin.request("POST","/admin/api/users",{
                            "username":"must-not-exist","password":"Blocked-fixture-password-123!",
                            "email":"blocked@example.invalid","role":"Viewer"},expect=503)
                        check(state.read_bytes()==before,"preparation storage fault denies account mutation")
                        check(admin.request("GET","/admin/api/audit/delivery")["storageFault"],
                              "outbox storage fault remains visible")
                    finally: stop(proc)
        print("DURABLE_GATEWAY_AUDIT_HTTPS_SUCCESS",flush=True)
        print("ACCOUNT_INTENT_OUTCOME_CORRELATION_SUCCESS",flush=True)

if __name__=="__main__": main()
