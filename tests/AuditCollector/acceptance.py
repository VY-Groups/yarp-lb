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
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from unittest.mock import patch

def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("PASS: " + message, flush=True)

def run(*args, **kw):
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)

def main():
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise SystemExit("Disposable CI only")
    dll = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="audit-fixture-") as tmp:
        root = Path(tmp)
        keys = root / "keys"
        keys.mkdir(mode=0o700)
        secret = secrets.token_bytes(32)
        (keys / "node-a.key").write_bytes(secret)
        ledger = root / "ledger.jsonl"
        ledger.touch()
        signing = root / "signing.pem"
        public = root / "public.pem"
        cert = root / "tls.crt"
        tlskey = root / "tls.key"
        pfx = root / "tls.pfx"
        password = secrets.token_hex(16)
        pwd = root / "pfx-password"
        pwd.write_text(password)
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
        def request(body, event, key=secret):
            digest=hashlib.sha256(body).hexdigest().upper()
            mac=hmac.digest(key, ("GatewayCore-Audit-Intent-v1\n"+event+"\n"+digest).encode(), "sha256")
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
        def verify_receipt(body,event,signature):
            msg=root/"receipt-input"
            sig=root/"receipt-signature"
            msg.write_bytes(("GatewayCore-Audit-Receipt-v1\n"+event+"\n"+hashlib.sha256(body).hexdigest().upper()).encode())
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
        with backend() as upstream:
            openssl_state(gateway_root,upstream)
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
                saved=admin.request("POST","/admin/api/onboarding",{"plan":plan,"confirmDesign":True,
                      "expectedRevision":topology["revision"]})
                check(saved["status"]=="design-confirmed","real onboarding API confirms HA design")
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
        print("INVENTORY_FLEET_EXTERNAL_AUDIT_SUCCESS",flush=True)
        print("ACCOUNT_MUTATION_EXTERNAL_AUDIT_SUCCESS",flush=True)

if __name__=="__main__": main()
