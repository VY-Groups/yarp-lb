"""Hosted-only installed provider/controller runtime, with independent identities.
No physical BMC, live quorum, or production credentials are used."""
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
import uuid

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
PROVIDER = "GatewayCoreVipFenceProvider" if WIN else "gatewaycore-vip-fence-provider"
CONTROLLER = "GatewayCoreVipController" if WIN else "gatewaycore-vip-controller"
OPENSSL = shutil.which("openssl") or (r"C:\Program Files\Git\usr\bin\openssl.exe" if WIN else "/usr/bin/openssl")
parent = os.environ["ProgramData"] if WIN else "/tmp"
roots, services, users = [], [], []
def run(*args, check=True):
    return subprocess.run([str(a) for a in args], check=check, capture_output=True, text=True, timeout=150)
def temp(prefix):
    p=Path(tempfile.mkdtemp(prefix=prefix,dir=parent))
    roots.append(p)
    if WIN:
        run("pwsh","-NoProfile","-File",HERE/"Set-VipFixtureAcl.ps1","-Directory",p,"-Identity","NT AUTHORITY\\SYSTEM")
    else: p.chmod(0o700)
    return p
def write(directory,name,value):
    p=directory/name
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,"w",encoding="ascii") as stream:
        if isinstance(value,str): stream.write(value)
        else: json.dump(value,stream)
    if not WIN: p.chmod(0o600)
    return p
def copy(directory,source):
    p=directory/source.name
    shutil.copyfile(source,p)
    if not WIN: p.chmod(0o600)
    return p
def openssl(*args): run(OPENSSL,*args)
def pin(p): return hashlib.sha256(ssl.PEM_cert_to_DER_cert(p.read_text())).hexdigest().upper()
def query(name):
    if WIN: return run("sc.exe","query",name,check=False)
    return run("systemctl","show",name+".service","-p","LoadState","-p","ActiveState","-p","ExecMainStatus",check=False)
def installed(name):
    if WIN: return query(name).returncode==0
    return run("systemctl","cat",name+".service",check=False).returncode==0
def active(name):
    if WIN: return "RUNNING" in query(name).stdout
    return run("systemctl","is-active","--quiet",name+".service",check=False).returncode==0
def stopped(name):
    if WIN: return "STOPPED" in query(name).stdout
    return any(s in query(name).stdout for s in ("ActiveState=inactive","ActiveState=failed"))
def start(name,check=True):
    result=run(*(("sc.exe","start",name) if WIN else ("systemctl","start",name+".service")),check=False)
    if check and result.returncode!=0:
        print(result.stdout,flush=True)
        raise AssertionError("Service start failed: "+name)
def stop(name):
    run(*(("sc.exe","stop",name) if WIN else ("systemctl","stop",name+".service")),check=False)
    until=time.monotonic()+40
    while not stopped(name) and time.monotonic()<until: time.sleep(.25)
    if not stopped(name): raise AssertionError("Service stop not confirmed: "+name)
def wait(predicate,label,seconds=45):
    until=time.monotonic()+seconds
    while time.monotonic()<until:
        try:
            if predicate(): return
        except (OSError,http.client.HTTPException): pass
        time.sleep(.25)
    raise AssertionError(label)
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]
def https(port,ca,cert=None,key=None):
    context=ssl.create_default_context(cafile=str(ca))
    if cert is not None: context.load_cert_chain(str(cert),str(key))
    conn=http.client.HTTPSConnection("127.0.0.1",port,context=context,timeout=3)
    try:
        conn.request("POST","/v1/vip/hard-fence",body='{"unexpected":true}',headers={"Content-Type":"application/json"})
        response=conn.getresponse(); response.read(4096); return response.status
    finally: conn.close()
def closed(port):
    try:
        with socket.create_connection(("127.0.0.1",port),timeout=.5): return False
    except OSError: return True
def account(role):
    if WIN: return "NT SERVICE\\"+(PROVIDER if role=="provider" else CONTROLLER)
    name="gcvip"+role[0]+str(os.getpid())
    if run("id",name,check=False).returncode==0: raise AssertionError("Existing fixture account")
    run("useradd","--system","--no-create-home","--shell","/usr/sbin/nologin",name)
    users.append(name); return name
def protect(directory,identity):
    if WIN:
        run("pwsh","-NoProfile","-File",HERE/"Set-VipFixtureAcl.ps1","-Directory",directory,"-Identity",identity)
    else:
        run("chown","-R",identity,directory)
        directory.chmod(0o700)
        for p in directory.iterdir(): p.chmod(0o600)
def expose(path):
    if WIN: run("icacls",path,"/grant","*S-1-5-32-545:R")
    else: path.chmod(0o644)
def restore(path):
    if WIN: run("icacls",path,"/remove:g","*S-1-5-32-545")
    else: path.chmod(0o600)
def install(role,name,binary,config,identity,extra=()):
    services.append(name)
    if WIN:
        run("pwsh","-NoProfile","-File",INSTALLER,"-Role",role,"-Executable",binary,"-Config",config,*extra,"-Apply")
    else:
        run("bash",INSTALLER,role,binary,config,identity,*extra,"--apply")
def refusal_event(event_id):
    command="$e=Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='GatewayCoreVipSecurity';Id="+str(event_id)+"} -MaxEvents 1 -ErrorAction SilentlyContinue; if($e){$e.RecordId}else{0}"
    return int(run("pwsh","-NoProfile","-Command",command).stdout.strip())
def assert_refusal(name,path,port=None):
    stop(name)
    event_id=7801 if name==PROVIDER else 7802
    before=refusal_event(event_id) if WIN else 0
    expose(path)
    try:
        start(name,check=False)
        wait(lambda: stopped(name) and (port is None or closed(port)) and (not WIN or refusal_event(event_id)>before), "Exposed credential did not produce specific refusal evidence")
        if not WIN and "ExecMainStatus=78" not in query(name).stdout:
            raise AssertionError("Expected explicit credential refusal")
    finally: restore(path)

try:
    if installed(PROVIDER) or installed(CONTROLLER): raise AssertionError("Existing roles; refuse mutation")
    issuer=temp("gc-vip-ci-issuer-"); pdir=temp("gc-vip-ci-provider-"); cdir=temp("gc-vip-ci-controller-")
    bindir=temp("gc-vip-ci-bin-")
    shutil.copytree(EXE.parent,bindir,dirs_exist_ok=True)
    binary=bindir/EXE.name
    if not WIN:
        for path in bindir.rglob("*"):
            if path.is_dir(): path.chmod(0o755)
            else: path.chmod(0o755 if path==binary else 0o644)
        bindir.chmod(0o755)
    ca=issuer/"ca.pem"; cak=issuer/"ca.key"
    openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN=Disposable HA role CA","-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign","-keyout",cak,"-out",ca)
    def issue(name,server=False):
        cert=issuer/(name+".pem"); key=issuer/(name+".key"); csr=issuer/(name+".csr")
        ext=write(issuer,name+".ext","basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+("serverAuth\nsubjectAltName=IP:127.0.0.1\n" if server else "clientAuth\n"))
        openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+name,"-keyout",key,"-out",csr)
        openssl("x509","-req","-in",csr,"-CA",ca,"-CAkey",cak,"-set_serial",str(uuid.uuid4().int),"-days","1","-extfile",ext,"-out",cert)
        return cert,key
    server,serverkey=issue("provider-server",True)
    reader,readerkey=issue("provider-reader")
    writer,writerkey=issue("independent-writer")
    wrong,wrongkey=issue("wrong-client")
    node1,_=issue("node1"); node2,_=issue("node2")
    scope="A"*64; owners=[pin(node1),pin(node2)]
    port=free_port()
    pca=copy(pdir,ca); cca=copy(cdir,ca)
    pcert=copy(pdir,reader); pkey=copy(pdir,readerkey)
    ccert=copy(cdir,writer); ckey=copy(cdir,writerkey)
    def quorum(ca,cert,key):
        return {"scope":scope,"clusterId":"1","caFile":str(ca),"certFile":str(cert),"keyFile":str(key),
                "endpoints":[{"url":"https://127.0.0.1:"+str(i),"leafSha256":str(i)*64,"memberId":str(i)} for i in (1,2,3)]}
    preader=write(pdir,"reader.json",quorum(pca,pcert,pkey))
    secret=pdir/"signer.pem"; public=cdir/"fence-public.pem"
    openssl("ecparam","-name","prime256v1","-genkey","-noout","-out",secret)
    openssl("pkey","-in",secret,"-pubout","-out",public)
    der=issuer/"fence-public.der"
    openssl("pkey","-pubin","-in",public,"-outform","DER","-out",der)
    writer_config=quorum(cca,ccert,ckey)
    writer_config.update(vipFencePublicKeyFile=str(public),vipFencePublicKeySha256=hashlib.sha256(der.read_bytes()).hexdigest().upper())
    writer_path=write(cdir,"writer.json",writer_config)
    provider_pfx=pdir/"server.pfx"; pw=pdir/"password"
    os.close(os.open(pw,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600))
    openssl("rand","-hex","-out",pw,"32")
    openssl("pkcs12","-export","-inkey",serverkey,"-in",server,"-out",provider_pfx,"-passout","file:"+str(pw))
    # This fixture never contacts a BMC. Use a unique non-reusable credential,
    # with the same private file ACL as the installed provider contract.
    bmc_credential=write(pdir,"bmc.json",{"username":"fixture","password":os.urandom(32).hex()})
    nodes=[]
    for index,owner in enumerate(owners):
        def machine(offset):
            return {"origin":"https://127.0.0.1:"+str(100+index*10+offset),"leafSha256":pin(server),
                    "caFile":str(pca),"certFile":str(pcert),"keyFile":str(pkey)}
        nodes.append({"pin":owner,"bmc":{"origin":"https://127.0.0.1:"+str(200+index),"leafSha256":pin(server),
            "caFile":str(pca),"systemPath":"/redfish/v1/Systems/fixture","systemUuid":str(uuid.uuid4()),"credentialFile":str(bmc_credential)},
            "agent":machine(1),"drain":machine(2)})
    rearm=pdir/"rearm.journal"
    provider_config=write(pdir,"provider.json",{"listenIp":"127.0.0.1","port":port,"scope":scope,"readerConfig":str(preader),
        "serverPfx":str(provider_pfx),"serverPasswordFile":str(pw),"writerCaFile":str(pca),"writerPin":pin(writer),
        "signingKeyFile":str(secret),"nodes":nodes,"standbyBootIsolationApproved":True,"rearmJournalFile":str(rearm)})
    provider_client=write(cdir,"provider-client.json",{"origin":"https://127.0.0.1:"+str(port),"leafSha256":pin(server),
        "caFile":str(cca),"certFile":str(ccert),"keyFile":str(ckey),"scope":scope,"ownerPins":owners})
    policy=write(cdir,"policy.json",{"version":1,"scope":scope,"preferredPin":owners[0],"otherPin":owners[1],"failbackEnabled":False,
        "pollSeconds":5,"failureSamples":3,"failureSeconds":10,"failbackEligibleSeconds":120,"minimumOwnerSeconds":300})
    journal=cdir/"controller.journal"
    pa=account("provider"); wa=account("controller")
    install("provider",PROVIDER,binary,provider_config,pa)
    extra=("-Scope",scope,"-Policy",policy,"-Provider",provider_client,"-Journal",journal) if WIN else (scope,policy,provider_client,journal)
    install("controller",CONTROLLER,binary,writer_path,wa,extra)
    protect(pdir,pa); protect(cdir,wa)
    if WIN:
        for identity in (pa,wa): run("icacls",bindir,"/grant:r",identity+":(OI)(CI)RX","/T")
    else:
        for identity,other in ((pa,cdir),(wa,pdir)):
            if run("runuser","-u",identity,"--","test","-r",other,check=False).returncode==0:
                raise AssertionError("Cross-role credential directory accessible")
    def provider_ready(): return active(PROVIDER) and https(port,ca,writer,writerkey)==503
    start(PROVIDER);wait(provider_ready,"Installed provider pinned HTTPS not ready")
    for cert,key in ((None,None),(wrong,wrongkey)):
        try: status=https(port,ca,cert,key)
        except (OSError,http.client.HTTPException): continue
        if status!=403: raise AssertionError("Unpinned client admitted")
    stop(PROVIDER)
    if not rearm.exists() or rearm.stat().st_size!=0: raise AssertionError("Unexpected rearm mutation")
    start(PROVIDER);wait(provider_ready,"Idle provider journal restart failed")
    assert_refusal(PROVIDER,secret,port)
    start(PROVIDER);wait(provider_ready,"Provider did not recover after credential restoration")
    print("PASS: installed independent provider, pinned mTLS, empty journal restart, exposed signing key refusal and restoration",flush=True)
    def controller_ready(): return active(CONTROLLER) and journal.exists()
    if not WIN: print(run("systemctl","show",CONTROLLER+".service","-p","ExecStart","-p","User").stdout,flush=True)
    start(CONTROLLER);wait(controller_ready,"Installed writer did not open durable journal")
    if WIN:
        probe_dir=bindir/"role-probe"
        build=run("dotnet","build",HERE/"VipRoleProbe"/"VipRoleProbe.csproj","-c","Release","-o",probe_dir,check=False)
        if build.returncode:
            print(build.stdout[-6000:],build.stderr[-6000:],flush=True)
            raise AssertionError("CI role probe compilation failed")
        for identity in (pa,wa): run("icacls",probe_dir,"/grant:r",identity+":(OI)(CI)RX","/T")
        result=run("pwsh","-NoProfile","-File",HERE/"Test-VipRoleIsolation.ps1","-ProviderDirectory",pdir,"-ControllerDirectory",cdir,"-ProviderKey",secret,"-ControllerKey",ckey,"-ProbeExe",probe_dir/"VipRoleProbe.exe",check=False)
        print(result.stdout,flush=True)
        if result.returncode!=0:
            # Disposable synthetic fixture only; print the precise bounded
            # PowerShell failure rather than masking it in CalledProcessError.
            print(result.stderr[-6000:],flush=True)
            raise AssertionError("Windows role isolation probe failed")
        wait(provider_ready,"Restored shipping provider not ready")
        wait(controller_ready,"Restored shipping controller not ready")
    time.sleep(6)
    if not active(CONTROLLER): raise AssertionError("Controller did not survive unavailable quorum")
    stop(CONTROLLER)
    if journal.stat().st_size!=0: raise AssertionError("Unexpected owner transition without quorum")
    start(CONTROLLER);wait(controller_ready,"Idle controller journal restart failed")
    assert_refusal(CONTROLLER,ckey)
    start(CONTROLLER);wait(controller_ready,"Writer did not recover after credential restoration")
    time.sleep(6)
    stop(CONTROLLER)
    if journal.stat().st_size!=0: raise AssertionError("Unexpected writer mutation without quorum")
    print("PASS: installed independent controller, unavailable-quorum no mutation, idle journal restart, exposed key refusal and restoration",flush=True)
except Exception:
    for name in services:
        if installed(name):
            print(query(name).stdout,flush=True)
            if not WIN: print(run("journalctl","-u",name+".service","--no-pager","-n","25",check=False).stdout,flush=True)
    raise
finally:
    for name in reversed(services):
        if installed(name):
            stop(name)
            if WIN: run("sc.exe","delete",name)
            else: (Path("/etc/systemd/system")/(name+".service")).unlink(missing_ok=True)
    if not WIN:
        run("systemctl","daemon-reload")
        for user in reversed(users): run("userdel",user)
    for directory in reversed(roots): shutil.rmtree(directory)
