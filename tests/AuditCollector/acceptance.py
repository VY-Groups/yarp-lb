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

if __name__=="__main__": main()
