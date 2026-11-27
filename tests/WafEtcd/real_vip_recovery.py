#!/usr/bin/env python3
"""Installed Linux provider and writer against actual disposable etcd Raft.
Only Redfish hardware and the two node-management endpoints are simulated.
No production hardware, credentials, addresses or customer state."""
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

HERE = Path(__file__).resolve().parents[2]
if os.geteuid()!=0 or os.getenv("GITHUB_ACTIONS")!="true" or os.getenv("RUNNER_ENVIRONMENT")!="github-hosted":
    raise SystemExit("Disposable elevated hosted CI only")
manifest=json.loads(Path(sys.argv[1]).read_text())
product=Path(sys.argv[2]).resolve(strict=True)
provider="gatewaycore-vip-fence-provider"
controller="gatewaycore-vip-controller"
root=Path(tempfile.mkdtemp(prefix="gc-vip-live-"))
root.chmod(0o755)
users=[]; services=[]; servers=[]; paused=[]
lock=threading.RLock()
stage="preflight"
def run(*args,check=True,timeout=120):
    return subprocess.run([str(a) for a in args],capture_output=True,text=True,check=check,timeout=timeout)
def installed(name):
    return run("systemctl","cat",name+".service",check=False).returncode==0
def active(name):
    return run("systemctl","is-active","--quiet",name+".service",check=False).returncode==0
def stop(name):
    run("systemctl","stop",name+".service")
    if active(name): raise AssertionError("Service stop unconfirmed")
def wait(predicate,label,seconds=90):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            if predicate(): return
        except (OSError,http.client.HTTPException): pass
        time.sleep(.3)
    raise AssertionError(label)
def private_dir(name):
    d=root/name;d.mkdir(mode=0o700);return d
def put(d,name,value):
    p=d/name
    p.write_text(value if isinstance(value,str) else json.dumps(value),encoding="ascii")
    p.chmod(0o600);return p
def copy(d,name,source):
    p=d/name;shutil.copyfile(source,p);p.chmod(0o600);return p
def identity(name):
    user="gcvip"+name+str(os.getpid())
    if run("id",user,check=False).returncode==0: raise AssertionError("Existing service identity")
    run("useradd","--system","--no-create-home","--shell","/usr/sbin/nologin",user)
    users.append(user);return user
def own(d,user):
    run("chown","-R",user,d)
    d.chmod(0o700)
    for p in d.iterdir(): p.chmod(0o600)
def b64(s):return base64.b64encode(s.encode("ascii")).decode("ascii")
def rpc(path,body):
    endpoint=manifest["endpoints"][0]["url"]
    port=int(endpoint.rsplit(":",1)[1])
    ctx=ssl.create_default_context(cafile=manifest["ca"])
    ctx.load_cert_chain(*manifest["writer"][:2])
    conn=http.client.HTTPSConnection("127.0.0.1",port,context=ctx,timeout=5)
    try:
        conn.request("POST",path,json.dumps(body),{"Content-Type":"application/json"})
        r=conn.getresponse();data=r.read(65536)
        if r.status!=200:raise RuntimeError("Disposable quorum request denied")
        return json.loads(data)
    finally:conn.close()
scope=hashlib.sha256(("live-vip-"+uuid.uuid4().hex).encode()).hexdigest().upper()
key=b64("/gatewaycore/adc-vip/v1/"+scope)
def owner_state():
    rows=rpc("/v3/kv/range",{"key":key,"serializable":False}).get("kvs",[])
    if len(rows)!=1:raise AssertionError("Exact owner missing")
    return base64.b64decode(rows[0]["value"]).decode("ascii"),int(rows[0]["mod_revision"])
def journal_rows(path):
    if not path.exists():return []
    data=path.read_text()
    if data and not data.endswith("\n"):return []
    return [json.loads(x) for x in data.splitlines()]
def field(row,key):
    return row.get(key,row.get(key[0].upper()+key[1:]))
def pin(cert):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(cert).read_text())).hexdigest().upper()
def openssl(*args):run("openssl",*args)
def free_port():
    with socket.socket() as s:s.bind(("127.0.0.1",0));return s.getsockname()[1]
def tls_server(handler,cert,key,ca=None):
    server=http.server.ThreadingHTTPServer(("127.0.0.1",0),handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert,key)
    if ca:
        ctx.verify_mode=ssl.CERT_REQUIRED;ctx.load_verify_locations(cafile=ca)
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True)
    thread.start();servers.append(server)
    return "https://127.0.0.1:"+str(server.server_port)
class JsonHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def response(self,status,obj=None):
        data=json.dumps(obj or {}).encode()
        self.send_response(status);self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(data)));self.end_headers();self.wfile.write(data)
    def body(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>4096:raise ValueError("Oversize")
        return json.loads(self.rfile.read(n))
try:
    if installed(provider) or installed(controller):raise AssertionError("Existing service; refuse mutation")
    if not all(c.startswith("waf-etcd-") for c in manifest["containers"]) or len(manifest["containers"])!=3:
        raise AssertionError("Unexpected disposable quorum members")
    pdir=private_dir("provider"); cdir=private_dir("controller")
    fixture=private_dir("hardware-fixture"); bindir=root/"bin"
    shutil.copytree(product.parent,bindir)
    executable=bindir/"GatewayCoreYarp"
    for p in bindir.rglob("*"):
        p.chmod(0o755 if p.is_dir() or p==executable else 0o644)
    bindir.chmod(0o755)
    pa=identity("p");wa=identity("w")
    ca=manifest["ca"];writer_cert,writer_key,writer_pin=manifest["writer"]
    reader_cert,reader_key,reader_pin=manifest["reader"]
    node_pins=[manifest["nodeA"][2],manifest["nodeB"][2]]
    first,second=node_pins
    pca=copy(pdir,"quorum-ca.pem",ca);cca=copy(cdir,"quorum-ca.pem",ca)
    pcert=copy(pdir,"reader.pem",reader_cert);pkey=copy(pdir,"reader.key",reader_key)
    ccert=copy(cdir,"writer.pem",writer_cert);ckey=copy(cdir,"writer.key",writer_key)
    endpoints=[dict(e,memberId=str(e["memberId"])) for e in manifest["endpoints"]]
    def quorum(ca,cert,key):
        return {"scope":scope,"clusterId":str(manifest["cluster"]),"caFile":str(ca),"certFile":str(cert),
                "keyFile":str(key),"endpoints":endpoints}
    preader=put(pdir,"reader.json",quorum(pca,pcert,pkey))
    signer=pdir/"signer.pem";pub=cdir/"fence-public.pem";der=fixture/"public.der"
    openssl("ecparam","-name","prime256v1","-genkey","-noout","-out",signer)
    openssl("pkey","-in",signer,"-pubout","-out",pub)
    openssl("pkey","-pubin","-in",pub,"-outform","DER","-out",der)
    wc=quorum(cca,ccert,ckey)
    wc.update(vipFencePublicKeyFile=str(pub),vipFencePublicKeySha256=hashlib.sha256(der.read_bytes()).hexdigest().upper())
    writer_path=put(cdir,"writer.json",wc)
    server_cert,server_key,server_pin=manifest["providerServer"]
    password=put(pdir,"password",uuid.uuid4().hex)
    pfx=pdir/"server.pfx"
    openssl("pkcs12","-export","-in",server_cert,"-inkey",server_key,"-out",pfx,"-passout","file:"+str(password))
    bmc_credential=put(pdir,"bmc.json",{"username":"fixture","password":"disposable-only"})
    expected_basic="Basic "+b64("fixture:disposable-only")
    power={first:True,second:True}
    serving={first:True,second:False}
    draining={first:False,second:False}
    inflight={first:0,second:0}
    systemids={p:str(uuid.uuid4()) for p in node_pins}
    events=[]; failure={"activate":True}
    def bmc_handler(node):
        path="/redfish/v1/Systems/fixture"
        class Bmc(JsonHandler):
            def do_GET(self):
                if self.headers.get("Authorization")!=expected_basic or self.path!=path:return self.response(403)
                with lock:
                    obj={"@odata.id":path,"UUID":systemids[node],"PowerRestorePolicy":"AlwaysOff",
                         "PowerState":"On" if power[node] else "Off",
                         "Actions":{"#ComputerSystem.Reset":{"target":path+"/Actions/ComputerSystem.Reset",
                         "ResetType@Redfish.AllowableValues":["ForceOff","On"]}}}
                self.response(200,obj)
            def do_POST(self):
                if self.headers.get("Authorization")!=expected_basic or self.path!=path+"/Actions/ComputerSystem.Reset":return self.response(403)
                action=self.body().get("ResetType")
                with lock:
                    if action=="ForceOff":
                        power[node]=False;serving[node]=False
                    elif action=="On":
                        power[node]=True;serving[node]=False;draining[node]=False
                    else:return self.response(400)
                    events.append((action,node))
                self.response(200)
        return Bmc
    def agent_handler(node):
        class Agent(JsonHandler):
            def do_POST(self):
                peer=self.connection.getpeercert(binary_form=True)
                if not peer or hashlib.sha256(peer).hexdigest().upper()!=reader_pin:return self.response(403)
                r=self.body()
                if r.get("scope")!=scope:return self.response(403)
                try:owner,epoch=owner_state()
                except Exception:return self.response(503)
                if r.get("epoch")!=epoch:return self.response(409)
                current=owner[4:] if owner.startswith("vip_") else ""
                with lock:
                    if not power[node]:return self.response(503)
                    if self.path=="/admin/vip-machine/drain":
                        if current!=node:return self.response(403)
                        if r["drain"]:
                            draining[node]=True;serving[node]=False;inflight[node]=2
                            events.append(("drain",node))
                        elif inflight[node]>0:inflight[node]-=1
                        return self.response(200,dict(scope=scope,epoch=epoch,nonce=r["nonce"],
                            draining=draining[node],manualDrain=False,active=inflight[node]))
                    if r.get("ownerPin")!=current:return self.response(409)
                    if self.path=="/v1/vip-node/activate":
                        if current!=node or any(power[p] for p in node_pins if p!=node):return self.response(409)
                        if failure["activate"]:
                            events.append(("activation-refused",node));return self.response(503)
                        serving[node]=True;draining[node]=False
                        events.append(("activated",node))
                    elif self.path!="/v1/vip-node/status":return self.response(404)
                    return self.response(200,dict(r,nodePin=node,serving=current==node and serving[node],
                        eligible=current!=node and not serving[node]))
        return Agent
    nodes=[]
    for i,node in enumerate(node_pins):
        bc,bk,bp=manifest["bmc"+str(i)]
        ac,ak,ap=manifest["agent"+str(i)]
        bmc=tls_server(bmc_handler(node),bc,bk)
        agent=tls_server(agent_handler(node),ac,ak,ca)
        machine={"origin":agent,"leafSha256":ap,"caFile":str(pca),"certFile":str(pcert),"keyFile":str(pkey)}
        nodes.append({"pin":node,"bmc":{"origin":bmc,"leafSha256":bp,"caFile":str(pca),
            "systemPath":"/redfish/v1/Systems/fixture","systemUuid":systemids[node],"credentialFile":str(bmc_credential)},
            "agent":machine,"drain":machine})
    port=free_port(); rearm=pdir/"rearm.journal"
    provider_cfg=put(pdir,"provider.json",{"listenIp":"127.0.0.1","port":port,"scope":scope,"readerConfig":str(preader),
        "serverPfx":str(pfx),"serverPasswordFile":str(password),"writerCaFile":str(pca),"writerPin":writer_pin,
        "signingKeyFile":str(signer),"nodes":nodes,"standbyBootIsolationApproved":True,"rearmJournalFile":str(rearm)})
    client=put(cdir,"provider-client.json",{"origin":"https://127.0.0.1:"+str(port),"leafSha256":server_pin,
        "caFile":str(cca),"certFile":str(ccert),"keyFile":str(ckey),"scope":scope,"ownerPins":node_pins})
    policy=put(cdir,"policy.json",{"version":1,"scope":scope,"preferredPin":first,"otherPin":second,
        "failbackEnabled":True,"rearmEnabled":True,"pollSeconds":5,"failureSamples":3,"failureSeconds":10,
        "failbackEligibleSeconds":120,"minimumOwnerSeconds":300})
    journal=cdir/"controller.journal"
    expires=int(time.time())+120
    message=put(fixture,"bootstrap.txt","\n".join(("GatewayCore.VIP.HardFence.v1",scope,"-","0",first,str(expires))))
    sig=cdir/"bootstrap.der"
    openssl("dgst","-sha256","-sign",signer,"-out",sig,message)
    own(pdir,pa);own(cdir,wa)
    def writer(*args,check=True):
        return run("runuser","-u",wa,"--",executable,"--vip-owner",writer_path,scope,*args,check=check,timeout=270)
    stage="signed-bootstrap"
    writer("activate","-","0",first,str(expires),sig)
    initial=owner_state()
    if initial[0]!="vip_"+first:raise AssertionError("Initial signed owner missing")
    sig.unlink()
    stage="install-roles"
    services.append(provider)
    run("bash",HERE/"ops/ha/install-vip-service.sh","provider",executable,provider_cfg,pa,"--apply")
    services.append(controller)
    run("bash",HERE/"ops/ha/install-vip-service.sh","controller",executable,writer_path,wa,scope,policy,client,journal,"--apply")
    run("systemctl","start",provider+".service")
    def provider_ready():
        if not active(provider):return False
        ctx=ssl.create_default_context(cafile=ca);ctx.load_cert_chain(writer_cert,writer_key)
        conn=http.client.HTTPSConnection("127.0.0.1",port,context=ctx,timeout=3)
        try:
            conn.request("POST","/v1/vip/hard-fence",'{"unexpected":true}',{"Content-Type":"application/json"})
            r=conn.getresponse();r.read(4096);return r.status==503
        finally:conn.close()
    wait(provider_ready,"Installed provider did not serve pinned mTLS")
    run("systemctl","start",controller+".service")
    wait(lambda:active(controller) and journal.exists(),"Installed controller did not open journal")
    stage="real-majority-partition"
    for name in manifest["containers"][1:]:
        run("docker","pause",name);paused.append(name)
    with lock:serving[first]=False
    time.sleep(22)
    if journal_rows(journal) or events:raise AssertionError("HA mutation without real quorum majority")
    for name in reversed(paused):run("docker","unpause",name)
    paused.clear()
    stage="automatic-failover-injected-activation-failure"
    def failed_successor():
        state=owner_state()
        return state[0]=="vip_"+second and not active(controller) and any(e==("activation-refused",second) for e in events)
    wait(failed_successor,"Controller did not preserve failed successor transition",150)
    successor=owner_state()
    rows=journal_rows(journal)
    if len(rows)!=1 or field(rows[0],"finalEpoch")!=0 or events.count(("ForceOff",first))!=1:
        raise AssertionError("Failed activation did not preserve exact durable recovery intent")
    if power[first] or serving[first] or serving[second]:raise AssertionError("Failed transition did not fail closed")
    stage="explicit-recovery-real-quorum"
    with lock:failure["activate"]=False
    writer("recover-policy",policy,client,journal)
    if owner_state()!=successor or not serving[second] or power[first]:
        raise AssertionError("Recovery changed owner epoch or admitted predecessor")
    rows=journal_rows(journal)
    if len(rows)!=2 or field(rows[-1],"finalEpoch")!=successor[1]:
        raise AssertionError("Exact recovery completion was not durable")
    if events.count(("ForceOff",first))!=1:raise AssertionError("Recovery repeated physical fence")
    print("PASS: installed writer/provider with real Raft: majority loss denies mutation; exact failover, failed activation and explicit durable recovery",flush=True)
    stage="provider-and-controller-restart-rearm"
    stop(provider);run("systemctl","start",provider+".service");wait(provider_ready,"Provider restart failed")
    run("systemctl","start",controller+".service")
    wait(lambda:events.count(("On",first))==1 and power[first] and not serving[first],"Standby rearm did not complete",150)
    stage="automatic-drained-failback"
    def completed_failback():
        current=owner_state()
        rows=journal_rows(journal)
        return current[0]=="vip_"+first and current[1]>successor[1] and serving[first] and bool(rows) and field(rows[-1],"finalEpoch")==current[1] and field(rows[-1],"kind")=="failback"
    # Real production policy minimum owner interval is deliberately unchanged.
    wait(completed_failback,"Full policy-timed failback failed",420)
    stop(controller)
    if serving[second] or events.count(("ForceOff",second))!=1 or events.count(("drain",second))!=1:
        raise AssertionError("Failback did not drain and hard-fence former owner exactly once")
    print("PASS: installed provider restart, durable standby rearm, policy-timed drained failback and exact real Raft epoch convergence",flush=True)
except Exception:
    print("FAIL: live installed VIP recovery stage="+stage,flush=True)
    for name in services:
        if installed(name):
            print(run("systemctl","show",name+".service","-p","ActiveState","-p","ExecMainStatus",check=False).stdout,flush=True)
            print(run("journalctl","-u",name+".service","--no-pager","-n","20",check=False).stdout,flush=True)
    raise
finally:
    for name in reversed(paused):run("docker","unpause",name,check=False)
    for name in reversed(services):
        if installed(name):
            stop(name)
            (Path("/etc/systemd/system")/(name+".service")).unlink(missing_ok=True)
    run("systemctl","daemon-reload")
    for s in servers:s.shutdown();s.server_close()
    for u in reversed(users):run("userdel",u)
    shutil.rmtree(root)
