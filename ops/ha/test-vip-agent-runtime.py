"""Disposable hosted-runner acceptance of shipping agent service startup/restart."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

WIN = os.name == "nt"
if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("Hosted CI only")
if not WIN and os.geteuid() != 0:
    raise SystemExit("Elevated disposable CI only")
HERE = Path(__file__).resolve().parent
# Exercise the extracted offline package, not a build output or source installer.
if len(sys.argv) != 2:
    raise SystemExit("Usage: acceptance.py <extracted-offline-package-root>")
PACKAGE = Path(sys.argv[1]).resolve(strict=True)
EXE = (PACKAGE / "app" / ("GatewayCoreYarp.exe" if WIN else "GatewayCoreYarp")).resolve(strict=True)
INSTALLER = (PACKAGE / "ops" / "ha" / ("Install-VipService.ps1" if WIN else "install-vip-service.sh")).resolve(strict=True)
if not EXE.is_relative_to(PACKAGE) or not INSTALLER.is_relative_to(PACKAGE):
    raise SystemExit("Package payload escaped the extracted root")
if not EXE.is_file() or not INSTALLER.is_file():
    raise SystemExit("Missing offline service payload")
GATEWAY = "GatewayCoreYarp" if WIN else "gatewaycore-vip-ci-gateway"
AGENT = "GatewayCoreVipNodeAgent" if WIN else "gatewaycore-vip-node-agent"
OPENSSL = shutil.which("openssl") or (r"C:\Program Files\Git\usr\bin\openssl.exe" if WIN else "/usr/bin/openssl")
root = Path(tempfile.mkdtemp(prefix="gc-vip-runtime-", dir=os.environ["ProgramData"] if WIN else "/tmp"))
created = []
def run(*args, check=True, timeout=100):
    return subprocess.run([str(x) for x in args], check=check, timeout=timeout, capture_output=True, text=True)
def private(path):
    if not WIN: path.chmod(0o600)
def write(name, data):
    p = root/name
    p.write_text(data, encoding="ascii")
    private(p)
    return p
def openssl(*args):
    run(OPENSSL,*args)
def pin(cert):
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest().upper()
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]
def installed(name):
    if WIN: return run("sc.exe","query",name,check=False).returncode == 0
    return run("systemctl","cat",name+".service",check=False).returncode == 0
def active(name):
    if WIN:
        r=run("sc.exe","query",name,check=False)
        return r.returncode == 0 and "RUNNING" in r.stdout
    return run("systemctl","is-active","--quiet",name+".service",check=False).returncode == 0
def start(name,check=True):
    return run(*(("sc.exe","start",name) if WIN else ("systemctl","start",name+".service")),check=check)
def stop(name):
    run(*(("sc.exe","stop",name) if WIN else ("systemctl","stop",name+".service")),check=False)
    deadline=time.monotonic()+35
    while not stopped(name) and time.monotonic()<deadline: time.sleep(.25)
    if not stopped(name): raise AssertionError("Service did not stop")
def call(port, ca, cert=None, key=None, route="/v1/vip-node/status", body='{"unexpected":true}'):
    context=ssl.create_default_context(cafile=str(ca))
    if cert is not None: context.load_cert_chain(str(cert),str(key))
    with_connection=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=3)
    try:
        with_connection.request("POST",route,body=body,headers={"Content-Type":"application/json"})
        response=with_connection.getresponse()
        response.read(4096)
        return response.status
    finally: with_connection.close()
def wait_ready(port,ca,cert,key):
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        try:
            if active(AGENT) and call(port,ca,cert,key)==503: return
        except (OSError,http.client.HTTPException): pass
        time.sleep(.25)
    diagnostics(AGENT)
    raise AssertionError("Shipping agent did not become an authenticated HTTPS service")
def diagnostics(name):
    if WIN:
        result=run("sc.exe","queryex",name,check=False)
    else:
        result=run("journalctl","-u",name+".service","--no-pager","-n","30",check=False)
    print(result.stdout,flush=True)
def refusal_event():
    command="$e=Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='GatewayCoreVipSecurity';Id=7803} -MaxEvents 1 -ErrorAction SilentlyContinue; if($e){$e.RecordId}else{0}"
    return int(run("pwsh","-NoProfile","-Command",command).stdout.strip())
def stopped(name):
    if WIN:
        r=run("sc.exe","query",name,check=False)
        return r.returncode==0 and "STOPPED" in r.stdout
    state=run("systemctl","show","-p","ActiveState","--value",name+".service").stdout.strip()
    return state in ("inactive","failed")
def wait_closed(port):
    deadline=time.monotonic()+45
    while time.monotonic()<deadline:
        if stopped(AGENT):
            try:
                with socket.create_connection(("127.0.0.1",port),timeout=.5): pass
            except OSError: return
        time.sleep(.25)
    raise AssertionError("Unsafe credentials or stop did not close service")
try:
    if installed(GATEWAY) or installed(AGENT): raise AssertionError("Existing service; refuse mutation")
    if WIN:
        run("pwsh","-NoProfile","-File",HERE/"Set-VipFixtureAcl.ps1","-Directory",root,"-Identity","NT AUTHORITY\\SYSTEM")
    else: root.chmod(0o700)
    ca=root/"ca.pem"; cak=root/"ca.key"
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=Disposable VIP CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",cak,"-out",ca)
    private(cak);private(ca)
    def issue(name, server=False):
        key=root/(name+".key"); cert=root/(name+".pem"); csr=root/(name+".csr")
        ext=write(name+".ext","basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+("serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n"))
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+name,"-keyout",key,"-out",csr)
        openssl("x509","-req","-in",csr,"-CA",ca,"-CAkey",cak,"-set_serial",str(int.from_bytes(os.urandom(12),"big")+1),"-days","1","-extfile",ext,"-out",cert)
        for p in (key,cert,csr): private(p)
        return cert,key
    server,serverkey=issue("server",True)
    node,nodekey=issue("node")
    peer,_=issue("peer")
    provider,providerkey=issue("provider")
    wrong,wrongkey=issue("wrong")
    pfx=root/"server.pfx"; password=write("password","disposable-fixture-only")
    openssl("pkcs12","-export","-inkey",serverkey,"-in",server,"-out",pfx,"-passout","file:"+str(password))
    private(pfx)
    scope="A"*64; port=free_port()
    reader=write("reader.json",json.dumps({"scope":scope,"clusterId":"1","caFile":str(ca),"certFile":str(node),"keyFile":str(nodekey),"endpoints":[{"url":"https://127.0.0.1:"+str(i),"leafSha256":str(i)*64,"memberId":str(i)} for i in (1,2,3)]}))
    supervisor=write("supervisor.json","{}")
    config=write("agent.json",json.dumps({"scope":scope,"nodePin":pin(node),"otherPin":pin(peer),"readerConfig":str(reader),"supervisorConfig":str(supervisor),"server":{"listenIp":"127.0.0.1","port":port,"pfx":str(pfx),"passwordFile":str(password),"clientCaFile":str(ca),"clientPin":pin(provider)}}))
    if WIN:
        created.append(GATEWAY)
        run("sc.exe","create",GATEWAY,"binPath=",str(Path(os.environ["SystemRoot"])/"System32/whoami.exe"),"start=","demand")
        created.append(AGENT)
        run("pwsh","-NoProfile","-File",INSTALLER,"-Role","agent","-Executable",EXE,"-Config",config,"-Apply")
    else:
        created.append(GATEWAY)
        unit=Path("/etc/systemd/system")/(GATEWAY+".service")
        with unit.open("x") as stream: stream.write("[Service]\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n")
        run("systemctl","daemon-reload")
        write("supervisor.json",json.dumps({"serviceName":GATEWAY+".service"}))
        created.append(AGENT)
        run("bash",INSTALLER,"agent",EXE,config,"root","--apply")
    if WIN: run("pwsh","-NoProfile","-File",HERE/"Set-VipFixtureAcl.ps1","-Directory",root,"-Identity","NT AUTHORITY\\SYSTEM")
    # Use the very same shipping executable/config before SCM startup to expose
    # safe stage diagnostics. This never substitutes for the installed test.
    process=subprocess.Popen([str(EXE),"--vip-node-agent",str(config)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        deadline=time.monotonic()+20
        while time.monotonic()<deadline and process.poll() is None:
            try:
                if call(port,ca,provider,providerkey)==503: break
            except (OSError,http.client.HTTPException): pass
            time.sleep(.25)
        else: raise AssertionError("Foreground agent did not become ready")
    finally:
        if process.poll() is None: process.terminate()
        try: output,errors=process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill();output,errors=process.communicate(timeout=10)
        print(errors[-4000:],flush=True)
    try: start(AGENT);wait_ready(port,ca,provider,providerkey)
    except (AssertionError,subprocess.CalledProcessError):
        diagnostics(AGENT);raise
    for cert,key in ((None,None),(wrong,wrongkey)):
        try: status=call(port,ca,cert,key)
        except (OSError,http.client.HTTPException): continue
        if status!=403: raise AssertionError("Unauthorized credential reached service")
    print("PASS: installed shipping agent starts with protected credentials and rejects unpinned clients",flush=True)
    stop(AGENT);wait_closed(port)
    start(AGENT);wait_ready(port,ca,provider,providerkey)
    print("PASS: real service stop and restart restores pinned HTTPS listener",flush=True)
    stop(AGENT);wait_closed(port)
    before=refusal_event() if WIN else 0
    if WIN: run("icacls",nodekey,"/grant","*S-1-5-32-545:R")
    else: nodekey.chmod(0o644)
    start(AGENT,check=False);wait_closed(port)
    if WIN:
        deadline=time.monotonic()+30
        while refusal_event()<=before and time.monotonic()<deadline: time.sleep(.25)
        if refusal_event()<=before: raise AssertionError("Expected new exact private-file ACL refusal event")
    if not WIN:
        status=run("systemctl","show","-p","ExecMainStatus","--value",AGENT+".service").stdout.strip()
        if status!="78": raise AssertionError("Expected explicit credential refusal exit 78, got "+status)
    if WIN: run("icacls",nodekey,"/remove:g","*S-1-5-32-545")
    else: nodekey.chmod(0o600)
    start(AGENT);wait_ready(port,ca,provider,providerkey)
    print("PASS: insecure referenced key denies service startup; restored protection recovers",flush=True)
finally:
    for name in reversed(created):
        if installed(name):
            stop(name)
            if WIN: run("sc.exe","delete",name)
            else:
                run("systemctl","disable",name+".service",check=False)
                (Path("/etc/systemd/system")/(name+".service")).unlink(missing_ok=True)
    if not WIN: run("systemctl","daemon-reload")
    shutil.rmtree(root)
