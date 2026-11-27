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
from vip_http_body import read_json_body

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
        except RuntimeError as error:
            if str(error)!="Disposable quorum request denied":raise
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
fleet="live-vip-"+uuid.uuid4().hex
vip="192.0.2.137"
scope=hashlib.sha256(("gatewaycore-adc-vip-v1\n"+fleet+"\n"+vip).encode()).hexdigest().upper()
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
        self.connection.settimeout(5)
        return read_json_body(self.headers,self.rfile)
def accept_live_policy(executable,scope,fleet,vip,reader,policy,expected_owner):
    # Real shipping gateway on an ephemeral dedicated kernel interface.
    # This fixture is intentionally separate from simulated BMC/node endpoints.
    from http.cookiejar import CookieJar
    from urllib.request import build_opener,ProxyHandler,HTTPSHandler,HTTPCookieProcessor,Request
    from urllib.error import HTTPError,URLError
    d=private_dir("live-policy");state=d/"state";state.mkdir(mode=0o700)
    journal_dir=d/"vip-journal";journal_dir.mkdir(mode=0o700)
    certdir=d/"certs";certdir.mkdir(mode=0o700)
    ca_key=certdir/"ca.key";ca_crt=certdir/"ca.crt"
    openssl("req","-new","-x509","-nodes","-newkey","rsa:3072","-sha256","-days","3",
        "-subj","/CN=Disposable VIP policy CA","-addext","basicConstraints=critical,CA:TRUE",
        "-addext","keyUsage=keyCertSign,cRLSign","-keyout",ca_key,"-out",ca_crt)
    # Hosted role inspection deliberately requires owner-private mode even
    # for referenced CA files. Never weaken the production ACL contract.
    ca_key.chmod(0o600);ca_crt.chmod(0o600)
    def leaf(label,san,usage):
        k=certdir/(label+".key");csr=certdir/(label+".csr");crt=certdir/(label+".crt")
        openssl("req","-new","-nodes","-newkey","rsa:2048","-subj","/CN="+label,"-keyout",k,"-out",csr)
        ext=put(certdir,label+".ext","subjectAltName="+san+"\nextendedKeyUsage="+usage+"\n")
        openssl("x509","-req","-in",csr,"-CA",ca_crt,"-CAkey",ca_key,"-CAcreateserial",
                "-days","2","-sha256","-extfile",ext,"-out",crt)
        k.chmod(0o600);crt.chmod(0o600);return k,crt
    sk,sc=leaf("management","IP:127.0.0.1","serverAuth")
    tk,tc=leaf("traffic","IP:"+vip,"serverAuth")
    ck,cc=leaf("operator","DNS:vip-ci-operator","clientAuth")
    dpkey=certdir/"dp.key";dpcrt=certdir/"dp.crt"
    openssl("req","-new","-x509","-nodes","-newkey","rsa:3072","-sha256","-days","7",
            "-subj","/CN=Disposable VIP DP","-addext","basicConstraints=critical,CA:FALSE",
            "-addext","keyUsage=critical,keyEncipherment","-keyout",dpkey,"-out",dpcrt)
    def make_pfx(name,key,crt):
        password=put(certdir,name+".password",uuid.uuid4().hex)
        output=certdir/(name+".pfx")
        openssl("pkcs12","-export","-in",crt,"-inkey",key,"-out",output,"-passout","file:"+str(password))
        output.chmod(0o600);return str(output),str(password)
    server_pfx,server_pass=make_pfx("server",sk,sc)
    traffic_pfx,traffic_pass=make_pfx("traffic",tk,tc)
    dp_pfx,dp_pass=make_pfx("dp",dpkey,dpcrt)
    thumb=hashlib.sha1(ssl.PEM_cert_to_DER_cert(cc.read_text())).hexdigest().upper()
    # Hold every port reservation concurrently until the configuration is built.
    reservations=[]
    try:
        for ip in ("127.0.0.2","127.0.0.2","127.0.0.1","127.0.0.1","127.0.0.1"):
            sock=socket.socket();reservations.append(sock);sock.bind((ip,0))
        ports=[sock.getsockname()[1] for sock in reservations]
        if len(set(ports))!=len(ports):raise AssertionError("Disposable port collision")
    finally:
        for sock in reservations:sock.close()
    suffix=uuid.uuid4().hex[:8];nic="gcv"+suffix;peer="gcp"+suffix
    if any(run("ip","link","show","dev",n,check=False).returncode==0 for n in (nic,peer)):
        raise AssertionError("Existing interface; refuse mutation")
    current=json.loads(run("ip","-j","address","show").stdout)
    if any(x.get("local")==vip for item in current for x in item.get("addr_info",[])):
        raise AssertionError("Existing VIP; refuse mutation")
    config=put(d,"listeners.json",{"trafficIp":"127.0.0.2","trafficHttpPort":ports[0],
        "trafficHttpsPort":ports[1],"managementIp":"127.0.0.1","adminPort":ports[2],
        "metricsPort":ports[3],"trafficPfxPath":traffic_pfx,"trafficPfxPasswordFile":traffic_pass,
        "managementPfxPath":server_pfx,"managementPfxPasswordFile":server_pass,
        "clientCaPemPath":str(ca_crt),"clientThumbprints":[thumb],
        "allowedAdminCidrs":["127.0.0.1/32"],"maxConcurrentConnections":32,"httpVersion":"1.1",
        "virtualServices":[{"id":"policy-vip","ip":vip,"port":ports[4],"protocol":"HTTPS",
            "requireLocalAddressPresence":True,"vipFleetId":fleet,"vipQuorumConfigPath":str(reader),
            "vipJournalDirectory":str(journal_dir),"vipInterfaceId":nic}]})
    cfg=state/"config";cfg.mkdir(mode=0o700)
    # Readiness intentionally requires an actively healthy real destination.
    # Exercise the shipping YARP route instead of bypassing that contract.
    class PolicyBackend(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            body=b"fixture" if self.path=="/api/identity" else b"ready"
            status=200 if self.path in ("/api/identity","/health/ready") else 404
            self.send_response(status);self.send_header("Content-Length",str(len(body)))
            self.end_headers();self.wfile.write(body)
    backend=http.server.ThreadingHTTPServer(("127.0.0.1",0),PolicyBackend)
    backend_port=backend.server_port
    runtime=put(cfg,"appsettings.json",{"Logging":{"LogLevel":{"Default":"Warning"}},
        "ReverseProxy":{"Routes":{
            "policy-vip":{"ClusterId":"policy-backend","Match":{"Path":"/api/identity"},
                "Metadata":{"ADC.VirtualServer.Id":"policy-vip"}}},
            "Clusters":{"policy-backend":{"HealthCheck":{"AvailableDestinationsPolicy":"HealthyAndUnknown",
                "Active":{"Enabled":True,"Interval":"00:00:01","Timeout":"00:00:01",
                    "Policy":"ConsecutiveFailures","Path":"/health/ready"}},
                "Destinations":{"fixture":{"Address":"http://127.0.0.1:"+str(backend_port)+"/"}}}}}})
    env={k:v for k,v in os.environ.items() if not k.startswith(("YARP_","GATEWAY_","ASPNETCORE_","GATEWAYCORE_"))}
    env.update(ASPNETCORE_ENVIRONMENT="Production",YARP_CONTROL_PLANE_DIR=str(state),
        YARP_RUNTIME_CONFIG_PATH=str(runtime),YARP_LISTENERS_CONFIG_FILE=str(config),
        YARP_LINUX_DP_CERT_PFX_PATH=dp_pfx,YARP_LINUX_DP_CERT_PASSWORD_FILE=dp_pass)
    proc=None;created=False;assigned=False
    def address(action):
        result=subprocess.run([str(executable),"--vip-address",str(journal_dir),"policy-vip",nic,action],
            env=env,capture_output=True,text=True,timeout=60,check=True)
        return json.loads(result.stdout.strip().splitlines()[-1])
    backend_thread=threading.Thread(target=backend.serve_forever,daemon=True)
    backend_thread.start()
    try:
        run("ip","link","add",nic,"type","veth","peer","name",peer);created=True
        run("ip","link","set",nic,"up");run("ip","link","set",peer,"up")
        supervisor=put(d,"supervisor.json",{"scope":scope,"serviceId":"policy-vip",
            "serviceName":"gatewaycore-vip-ci-gateway.service","listenerConfig":str(config),
            "probePath":"/api/identity","probeCaFile":str(ca_crt),"probeLeafSha256":pin(tc),
            "probeBodySha256":hashlib.sha256(b"fixture").hexdigest().upper()})
        agent=put(d,"agent.json",{"scope":scope,"nodePin":policy["preferredPin"],"otherPin":policy["otherPin"],
            "readerConfig":str(reader),"supervisorConfig":str(supervisor),"server":{"listenIp":"127.0.0.1",
            "port":free_port(),"pfx":server_pfx,"passwordFile":server_pass,"clientCaFile":str(ca_crt),"clientPin":pin(cc)}})
        inspected=subprocess.run([str(executable),"--vip-node-agent",str(agent),"inspect"],
            env=env,capture_output=True,text=True,timeout=60)
        if inspected.returncode:
            # Only shipping fixed-stage/type diagnostics; never print config,
            # exception messages, certificate data or arbitrary child output.
            import re
            for line in inspected.stderr.splitlines():
                if re.fullmatch(r"VIP node agent refused at [a-z ]+: [A-Za-z0-9_]+",line):
                    print(line,flush=True)
            raise AssertionError("Node offline preflight exit "+str(inspected.returncode))
        preflight=json.loads(inspected.stdout)
        if (not preflight["validated"] or preflight["mutated"] or preflight["networkVerified"] or
            preflight["serviceVerified"] or list(journal_dir.iterdir()) or Path(str(supervisor)+".lock").exists()):
            raise AssertionError("Node offline preflight mutated state or overclaimed readiness")
        bad=json.loads(supervisor.read_text());bad["scope"]="0"*64
        put(d,"supervisor.json",bad)
        rejected=subprocess.run([str(executable),"--vip-node-agent",str(agent),"inspect"],
            env=env,capture_output=True,text=True,timeout=60)
        if rejected.returncode!=78 or list(journal_dir.iterdir()) or Path(str(supervisor)+".lock").exists():
            raise AssertionError("Mismatched supervisor scope was accepted or mutated state")
        bad["scope"]=scope;put(d,"supervisor.json",bad)
        result=address("reconcile");assigned=True
        if not result.get("eligibleToStart") or result.get("epoch")!=expected_owner[1]:
            raise AssertionError("Real journal-bound address not ready at signed epoch")
        journal_files=list(journal_dir.glob("*.journal"))
        if len(journal_files)!=1:raise AssertionError("Exact address journal missing")
        original_journal=journal_files[0].read_bytes()
        with (d/"gateway.log").open("w") as log:
            proc=subprocess.Popen([str(executable)],env=env,cwd=executable.parent,stdout=log,stderr=log)
            def ready():
                if proc.poll() is not None:raise AssertionError("Real policy gateway exited")
                conn=http.client.HTTPConnection("127.0.0.2",ports[0],timeout=2)
                try:
                    conn.request("GET","/gateway/health/ready")
                    res=conn.getresponse();res.read();return res.status==200
                finally:conn.close()
            wait(ready,"Real journal-bound gateway readiness",40)
            def vip_serving():
                conn=http.client.HTTPSConnection(vip,ports[4],timeout=4,
                    context=ssl.create_default_context(cafile=str(ca_crt)))
                try:
                    conn.request("GET","/api/identity")
                    res=conn.getresponse();body=res.read()
                    return res.status==200 and body==b"fixture"
                finally:conn.close()
            wait(vip_serving,"Real journal-bound TLS VIP forwards healthy backend traffic",30)
            print("PASS: live journal-bound VIP forwards actual YARP traffic to actively healthy origin",flush=True)
            context=ssl.create_default_context(cafile=str(ca_crt));context.load_cert_chain(str(cc),str(ck))
            opener=build_opener(ProxyHandler({}),HTTPSHandler(context=context),HTTPCookieProcessor(CookieJar()))
            # Check the physical HTTP assets with independent CA-validated
            # mTLS before starting the real Chromium flow.
            for route,name in (("/dashboard","index.html"),("/dashboard/app.js","app.js"),
                ("/dashboard/first-run.js","first-run.js"),("/dashboard/style.css","style.css")):
                with opener.open("https://127.0.0.1:"+str(ports[2])+route,timeout=8) as response:
                    if response.status!=200 or response.read()!=(executable.parent/"wwwroot"/name).read_bytes():
                        raise AssertionError("Shipping UI asset response mismatch "+name)
            print("PASS: actual mTLS dashboard HTML and scripts match exact staged shipping assets",flush=True)
            csrf=None
            def api(method,path,payload=None,expected=200,with_csrf=True):
                headers={"Accept":"application/json"}
                if payload is not None:headers["Content-Type"]="application/json"
                if csrf and with_csrf:headers["X-CSRF-Token"]=csrf
                data=None if payload is None else json.dumps(payload).encode()
                try:
                    with opener.open(Request("https://127.0.0.1:"+str(ports[2])+path,data=data,method=method,headers=headers),timeout=8) as reply:
                        status,raw,cache=reply.status,reply.read(65536),reply.headers.get("Cache-Control")
                except HTTPError as err:status,raw,cache=err.code,err.read(65536),err.headers.get("Cache-Control")
                if status!=expected:raise AssertionError("Real policy API "+method+" "+path+" status "+str(status))
                return (json.loads(raw),cache) if status==200 else (None,cache)
            admin_password=uuid.uuid4().hex
            api("POST","/admin/api/bootstrap",{"username":"vip-policy-admin",
                "password":admin_password,"email":"vip-policy@example.invalid"})
            session,_=api("GET","/admin/api/session");csrf=session["csrf"]
            if not session["privacyAccepted"]:
                api("POST","/admin/api/privacy/accept",{"version":session["privacyVersion"]})
            if session["role"]!="Administrator" or not csrf:raise AssertionError("Missing authenticated administrator")
            inventory,_=api("GET","/admin/api/network/interfaces")
            rows=[r for r in inventory["virtualAddresses"] if r["id"]=="policy-vip"]
            if len(rows)!=1 or rows[0]["haPolicyScope"]!=scope or rows[0]["ownershipEpoch"]!=expected_owner[1]:
                raise AssertionError("Inventory did not expose actual journal-bound scope and epoch")
            path="/admin/api/network/virtual-services/ha-policy"
            api("POST",path,policy,expected=403,with_csrf=False)
            api("POST",path,dict(policy,scope="0"*64),expected=400)
            api("POST",path,dict(policy,pollSeconds=1),expected=400)
            reply,cache=api("POST",path,policy)
            if (reply["applied"] is not False or json.loads(reply["json"])!=policy or
                reply["sha256"]!=hashlib.sha256(reply["json"].encode("utf-8")).hexdigest().upper() or
                cache!="no-store"):
                raise AssertionError("Real exported policy bytes, digest or cache contract mismatch")
            # Use a separate real browser session: no page.route(), mocked
            # API, injected authentication cookie or direct download helper.
            browser_input=put(d,"browser-input.json",{
                "origin":"https://127.0.0.1:"+str(ports[2]),
                "certificate":str(cc),"key":str(ck),"password":admin_password,
                "policy":policy,"expectedJson":reply["json"],"expectedSha256":reply["sha256"]})
            try:
                subprocess.run([os.environ["VIP_BROWSER_NODE"],str(HERE/"tests/E2E/vip-policy-live.mjs"),
                    str(browser_input)],check=True,timeout=120)
            finally:browser_input.unlink(missing_ok=True)
            if owner_state()!=expected_owner or journal_files[0].read_bytes()!=original_journal:
                raise AssertionError("Policy export changed live ownership or address journal")
            print("PASS: real journal-bound gateway + actual Raft + kernel VIP + mTLS administrator: positive audited policy export, digest and negative scope/CSRF/timing checks",flush=True)
    finally:
        if proc is not None:
            proc.terminate()
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        try:
            if assigned:
                result=address("withdraw")
                if result.get("present") or result.get("phase")!="withdrawn":
                    raise AssertionError("Disposable address withdrawal unconfirmed")
        finally:
            try:
                if created:run("ip","link","delete",nic)
            finally:
                backend.shutdown();backend.server_close();backend_thread.join(timeout=5)

try:
    if installed(provider) or installed(controller):raise AssertionError("Existing service; refuse mutation")
    if not all(c.startswith("waf-etcd-") for c in manifest["containers"]) or len(manifest["containers"])!=3:
        raise AssertionError("Unexpected disposable quorum members")
    pdir=private_dir("provider"); cdir=private_dir("controller")
    fixture=private_dir("hardware-fixture"); bindir=root/"bin"
    shutil.copytree(product.parent,bindir)
    # dotnet build does not guarantee physical wwwroot files beside the
    # apphost. The shipping dashboard serves those files from content root.
    # Stage the exact checked-out assets into this disposable runtime.
    webroot=bindir/"wwwroot";webroot.mkdir(exist_ok=True)
    for name in ("index.html","app.js","first-run.js","style.css","license.html","license.js"):
        source=HERE/"control-center"/"wwwroot"/name
        target=webroot/name
        if not source.is_file() or source.is_symlink() or target.is_symlink():
            raise AssertionError("Missing or linked shipping UI asset "+name)
        if target.exists():
            if target.read_bytes()!=source.read_bytes():
                raise AssertionError("Built UI asset differs from exact source "+name)
        else:shutil.copyfile(source,target)
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
                try:action=self.body().get("ResetType")
                except (ValueError,OSError):return self.response(400)
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
                try:r=self.body()
                except (ValueError,OSError):return self.response(400)
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
    stage="offline-provider-preflight"
    result=run("runuser","-u",pa,"--",executable,"--vip-redfish-provider",provider_cfg,"inspect")
    provider_inspection=json.loads(result.stdout)
    if (not provider_inspection["validated"] or provider_inspection["mutated"] or
        provider_inspection["networkVerified"] or not provider_inspection["remoteLifecycleConfigured"] or
        provider_inspection["rearmJournalExists"] or rearm.exists() or
        provider_inspection["signingPublicKeySha256"]!=wc["vipFencePublicKeySha256"]):
        raise AssertionError("Offline provider preflight mutated state or trust mismatch")
    stage="offline-controller-preflight"
    inspection=json.loads(writer("inspect-policy",policy,client,journal).stdout)
    if not inspection["validated"] or inspection["networkVerified"] or inspection["mutated"] or inspection["journalExists"] or journal.exists():
        raise AssertionError("Offline preflight created state or falsely claimed network readiness")
    invalid_policy=put(cdir,"invalid-policy.json",dict(json.loads(policy.read_text()),pollSeconds=1))
    own(cdir,wa)
    if writer("inspect-policy",invalid_policy,client,journal,check=False).returncode!=78 or journal.exists():
        raise AssertionError("Offline preflight accepted unsafe policy")
    invalid_policy.unlink()
    stage="signed-bootstrap"
    writer("activate","-","0",first,str(expires),sig)
    initial=owner_state()
    if initial[0]!="vip_"+first:raise AssertionError("Initial signed owner missing")
    sig.unlink()
    stage="real-journal-bound-policy-export"
    policy_dir=private_dir("policy-reader")
    node_cert=copy(policy_dir,"node.pem",manifest["nodeA"][0]);node_key=copy(policy_dir,"node.key",manifest["nodeA"][1])
    node_ca=copy(policy_dir,"ca.pem",ca)
    node_reader=put(policy_dir,"reader.json",quorum(node_ca,node_cert,node_key))
    accept_live_policy(executable,scope,fleet,vip,node_reader,json.loads(policy.read_text()),initial)
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
    before_inspection=journal.read_bytes()
    inspection=json.loads(writer("inspect-policy",policy,client,journal).stdout)
    if (not inspection["recoveryRequired"] or inspection["pending"]["OldEpoch"]!=initial[1] or
        inspection["mutated"] or journal.read_bytes()!=before_inspection or owner_state()!=successor):
        raise AssertionError("Offline recovery inspection failed or changed ownership/journal")
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
