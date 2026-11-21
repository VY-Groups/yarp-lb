#!/usr/bin/env python3
"""Disposable real GatewayCore peer-v4 HTTPS acceptance, with controlled delivery loss."""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
import hashlib
import hmac
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
from unittest.mock import patch

from real_control_center import backend, gateway, openssl_state, port, Client, check

EPOCH_HEADER="X-GC-Peer-Receiver-Epoch"
PATH="/gateway/internal/peer-sync"

def until(label, fn, timeout=12):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        found=fn()
        if found:
            return found
        time.sleep(.05)
    raise AssertionError(label)

def certificate(root, name):
    key=root/(name+".key")
    cert=root/(name+".crt")
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-days","7",
        "-subj","/CN=127.0.0.1","-addext","subjectAltName=IP:127.0.0.1",
        "-addext","basicConstraints=critical,CA:TRUE",
        "-keyout",str(key),"-out",str(cert)],check=True,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    key.chmod(0o600)
    return key,cert

def state_with_tls(root, origin):
    openssl_state(root,origin)
    # Keep the CA TLS identity separate from the compliant key-encipherment
    # leaf that openssl_state created for Linux Data Protection.
    key,cert=certificate(root/"secrets","peer-tls")
    pfx=root/"secrets"/"tls.pfx"
    subprocess.run(["openssl","pkcs12","-export","-out",str(pfx),"-inkey",str(key),
        "-in",str(cert),"-passout","pass:temporary-e2e-only-password"],check=True,
        stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    pfx.chmod(0o600)
    return cert

def https_post(port_number, context, payload, headers):
    conn=http.client.HTTPSConnection("127.0.0.1",port_number,context=context,timeout=3)
    try:
        conn.request("POST",PATH,payload,headers)
        response=conn.getresponse()
        result=(response.status,dict(response.getheaders()))
        response.read()
        return result
    finally:
        conn.close()

def signed(secret, sender, frame):
    payload=json.dumps(frame,separators=(",",":")).encode()
    ts=str(int(time.time()))
    nonce=secrets.token_hex(16).upper()
    mac=hmac.new(secret, (sender+"\n"+ts+"\n"+nonce+"\n").encode()+
        hashlib.sha256(payload).digest(), hashlib.sha256).digest()
    return payload,{"X-GC-Peer-Id":sender,"X-GC-Peer-Ts":ts,"X-GC-Peer-Nonce":nonce,
        "X-GC-Peer-Sig":base64.b64encode(mac).decode(),"Content-Type":"application/json"}

class Relay:
    """Record actual publisher frames; discard exactly one delta with a false
    successful acknowledgment to simulate an acknowledged baseline gap."""
    def __init__(self, receiver_port, receiver_cert, key, cert):
        self.events=[]
        self.lock=threading.Lock()
        self.drop_next=False
        ctx=ssl.create_default_context(cafile=str(receiver_cert))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path!=PATH:
                    self.send_error(404)
                    return
                n=int(self.headers.get("Content-Length","0"))
                if not 0<n<=262144:
                    self.send_error(400)
                    return
                payload=self.rfile.read(n)
                frame=json.loads(payload)
                with owner.lock:
                    dropped=owner.drop_next and frame["BaseSequence"]>0
                    if dropped: owner.drop_next=False
                if dropped:
                    status,headers=204,{}
                else:
                    try:
                        forwarded={k:self.headers[k] for k in
                            ("X-GC-Peer-Id","X-GC-Peer-Ts","X-GC-Peer-Nonce","X-GC-Peer-Sig","Content-Type")}
                        status,headers=https_post(receiver_port,ctx,payload,forwarded)
                    except (OSError,http.client.HTTPException):
                        status,headers=503,{}
                challenge=next((v for k,v in headers.items() if k.lower()==EPOCH_HEADER.lower()),None)
                with owner.lock:
                    owner.events.append((frame,status,challenge,dropped))
                self.send_response(status)
                if challenge: self.send_header(EPOCH_HEADER,challenge)
                self.send_header("Content-Length","0")
                self.end_headers()
            def log_message(self,*_): pass
        self.server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(str(cert),str(key))
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self,*_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
    def find(self,start,predicate):
        with self.lock:
            return next(((i,e) for i,e in enumerate(self.events[start:],start) if predicate(*e)),None)
    def count(self):
        with self.lock: return len(self.events)

def config(node,remote,url,secret,trust=None):
    result={"GATEWAY_PEER_SYNC_NODE_ID":node,"GATEWAY_PEER_SYNC_REMOTE_ID":remote,
        "GATEWAY_PEER_SYNC_REMOTE_URL":url,"GATEWAY_PEER_SYNC_SECRET":secret.decode(),
        "GATEWAY_PEER_SYNC_INTERVAL_SECONDS":"1","GATEWAY_PEER_SYNC_CAPACITY":"8"}
    if trust: result["SSL_CERT_FILE"]=str(trust)
    return result

@contextmanager
def peer_gateway(cwd,dll,root,listen,tls,settings):
    with patch.dict(os.environ,settings), gateway(cwd,dll,root,listen,tls) as base:
        yield base

def observe(port_number, source):
    conn=http.client.HTTPConnection("127.0.0.1",port_number,timeout=3,source_address=(source,0))
    try:
        conn.request("GET","/fixture/peer-observation")
        r=conn.getresponse()
        check(r.status==200 and b"e2e-origin" in r.read(),"real sender observes proxied request")
    finally: conn.close()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("control-center"))
    args=parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("CI")!="true":
        raise SystemExit("REJECTED: disposable GitHub Actions CI only")
    cwd=args.root.resolve()
    dll=cwd/"bin/Release/net10.0/GatewayCoreYarp.dll"
    if not dll.is_file(): raise SystemExit("build shipping application before acceptance")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-peer-v4-") as td, backend() as origin:
        root=Path(td)
        sender_root=root/"sender"
        receiver_root=root/"receiver"
        sender_root.mkdir()
        receiver_root.mkdir()
        state_with_tls(sender_root,origin)
        receiver_cert=state_with_tls(receiver_root,origin)
        relay_key,relay_cert=certificate(root,"relay")
        ports=set()
        while len(ports)<5: ports.add(port())
        sender_http,sender_tls,receiver_http,receiver_tls,unused=ports
        secret=secrets.token_hex(32).encode()
        receiver_cfg=config("receiver","sender",f"https://127.0.0.1:{unused}{PATH}",secret)
        active_signing=secrets.token_hex(32).encode()
        receiver_cfg.update({"GATEWAY_PEER_SYNC_SIGNING_SECRET":active_signing.decode(),
                             "GATEWAY_PEER_SYNC_PREVIOUS_SIGNING_SECRET":secret.decode()})
        receiver_context=ssl.create_default_context(cafile=str(receiver_cert))
        receiver_context.minimum_version = ssl.TLSVersion.TLSv1_2
        with Relay(receiver_tls,receiver_cert,relay_key,relay_cert) as relay:
            sender_cfg=config("sender","receiver",
                f"https://127.0.0.1:{relay.server.server_address[1]}{PATH}",secret,relay_cert)
            # Keep deliberate gap and restart within a real current-minute window.
            remain=60-int(time.time())%60
            if remain<40: time.sleep(remain+.2)
            with peer_gateway(cwd,dll,sender_root,sender_http,sender_tls,sender_cfg):
                with peer_gateway(cwd,dll,receiver_root,receiver_http,receiver_tls,receiver_cfg) as base:
                    admin=Client(base)
                    admin.bootstrap("peer_e2e","Peer-e2e-long-password!","peer@example.invalid")
                    start=relay.count()
                    idx,challenge_event=until("signed publisher never learned receiver challenge",
                        lambda:relay.find(0,lambda f,s,c,d:s==409 and c and not d))
                    epoch=challenge_event[2]
                    check(len(epoch)==64,"actual HTTPS receiver returns boot challenge")
                    observe(sender_http,"127.0.0.1")
                    observe(sender_http,"127.0.0.2")
                    # Force complete baseline if both identities change together.
                    idx,full=until("publisher did not establish full baseline",
                        lambda:relay.find(idx+1,lambda f,s,c,d:
                            s==204 and not d and f["BaseSequence"]==0 and
                            f["ReceiverEpoch"]==epoch))
                    def remote_counts():
                        state=admin.request("GET","/admin/api/peer-sync/status")
                        return state if state["remoteIdentities"]==2 and state["remoteRequests"]>=2 else None
                    until("receiver never observed both hashed identities",remote_counts)
                    observe(sender_http,"127.0.0.1")
                    idx,delta=until("publisher never sent a changed delta",
                        lambda:relay.find(idx+1,lambda f,s,c,d:s==204 and not d and
                            f["BaseSequence"]>0 and len(f["Counters"])==1))
                    check(delta[0]["ReceiverEpoch"]==epoch,"real publisher delta uses signed receiver epoch")
                    until("delta did not preserve both identities and increment count",
                        lambda:(lambda x:x["remoteIdentities"]==2 and x["remoteRequests"]==3)(
                            admin.request("GET","/admin/api/peer-sync/status")))
                    with relay.lock: relay.drop_next=True
                    idx,missing=until("relay did not drop one acknowledged delta",
                        lambda:relay.find(idx+1,lambda f,s,c,d:d))
                    idx,rejected=until("actual receiver did not reject missing base",
                        lambda:relay.find(idx+1,lambda f,s,c,d:s==409 and c is None and
                            f["BaseSequence"]==missing[0]["Sequence"]))
                    idx,repaired=until("actual publisher failed to send full backfill",
                        lambda:relay.find(idx+1,lambda f,s,c,d:s==204 and not d and f["BaseSequence"]==0))
                    check(repaired[0]["ReceiverEpoch"]==epoch,"gap forces complete real HTTPS backfill")
                    until("backfill did not restore receiver counters",
                        lambda:(lambda x:x["remoteIdentities"]==2 and x["remoteRequests"]==3)(
                            admin.request("GET","/admin/api/peer-sync/status")))
                    old_frame=repaired[0]
                    payload,headers=signed(secret,"sender",old_frame)
                    headers["X-GC-Peer-Sig"]=base64.b64encode(bytes(32)).decode()
                    check(https_post(receiver_tls,receiver_context,payload,headers)[0]==403,
                        "receiver rejects tampered HMAC at the actual HTTPS endpoint")
                # Actual receiver process replaced, sender publisher stays alive.
                with peer_gateway(cwd,dll,receiver_root,receiver_http,receiver_tls,receiver_cfg) as base:
                    payload,headers=signed(secret,"sender",old_frame)
                    status,hdrs=https_post(receiver_tls,receiver_context,payload,headers)
                    new_epoch=next((v for k,v in hdrs.items() if k.lower()==EPOCH_HEADER.lower()),None)
                    check(status==409 and new_epoch and new_epoch!=epoch,
                        "replacement receiver rejects obsolete boot-bound signed frame")
                    idx,restart=until("publisher did not fully resynchronize after real receiver restart",
                        lambda:relay.find(idx+1,lambda f,s,c,d:s==204 and not d and
                            f["BaseSequence"]==0 and f["ReceiverEpoch"]==new_epoch))
                    admin=Client(base)
                    admin.login("peer_e2e","Peer-e2e-long-password!")
                    until("restarted receiver did not recover both counters",
                        lambda:(lambda x:x["remoteIdentities"]==2 and x["remoteRequests"]==3)(
                            admin.request("GET","/admin/api/peer-sync/status")))
                    check(True,"real receiver restart teaches new challenge and full backfill using previous signing key")
                    payload,headers=signed(active_signing,"sender",old_frame)
                    status,_=https_post(receiver_tls,receiver_context,payload,headers)
                    check(status==409,"active signing key authenticates obsolete boot frame but cannot bypass epoch fence")
                # Restart receiving side without overlap. The old publisher
                # stays running; it must receive 403, not a challenge or ACK.
                retired_cfg=dict(receiver_cfg)
                retired_cfg.pop("GATEWAY_PEER_SYNC_PREVIOUS_SIGNING_SECRET")
                with peer_gateway(cwd,dll,receiver_root,receiver_http,receiver_tls,retired_cfg):
                    payload,headers=signed(secret,"sender",old_frame)
                    check(https_post(receiver_tls,receiver_context,payload,headers)[0]==403,
                          "real replacement receiver refuses retired signing key")
                    payload,headers=signed(active_signing,"sender",old_frame)
                    status,hdrs=https_post(receiver_tls,receiver_context,payload,headers)
                    check(status==409 and any(k.lower()==EPOCH_HEADER.lower() for k in hdrs),
                          "still accepts active key and preserves receiver-boot fence")
        print("PEER_V4_HTTPS_SUCCESS",flush=True)

if __name__=="__main__": main()
