#!/usr/bin/env python3
"""Compile all separate commercial engines and test real L4 admission and revocation."""
import json
import hashlib
import os
import ssl
import urllib.request
import urllib.error
import secrets
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

assert os.environ.get("CI")=="true" and os.environ.get("GITHUB_ACTIONS")=="true"
root=Path.cwd()
fixture=root/"tests/OfflineLicensing/bin/Release/net10.0/OfflineLicensing.dll"
projects=[
    ("engines/L4/L4Proxy.csproj","L4Proxy.dll"),
    ("engines/GslbDns/GslbDns.csproj","GslbDns.dll"),
    ("engines/GslbObserver/GslbObserver.csproj","GslbObserver.dll"),
    ("control-center/GatewayAgent/GatewayCoreGatewayAgent.csproj","GatewayCoreGatewayAgent.dll")]
def run(*args,env=None,ok=True):
    result=subprocess.run(["dotnet",*map(str,args)],env=env,capture_output=True,text=True,timeout=120)
    if (result.returncode==0)!=ok:
        raise AssertionError(result.stdout+result.stderr)
    return result
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(4096)
            if not data:return
            self.request.sendall(data)
class UdpEcho(socketserver.BaseRequestHandler):
    def handle(self):
        data,sock=self.request;sock.sendto(data,self.client_address)
def free_port(kind):
    with socket.socket(socket.AF_INET,kind) as s:
        s.bind(("127.0.0.1",0));return s.getsockname()[1]
with tempfile.TemporaryDirectory(prefix="gc-engine-acceptance-") as td:
    folder=Path(td);key=folder/"authority"
    run(fixture,"--ci-engine-key",key)
    trust=key/"trust.json"
    env=dict(os.environ,GATEWAYCORE_ENGINE_LICENSE_DIR=str(folder/"identity"))
    dlls=[]
    release=folder/"release"
    run(fixture,"--ci-release-key",release)
    commit=os.environ["GITHUB_SHA"]
    for project,dll in projects:
        out=folder/Path(project).stem
        run("publish",root/project,"-c","Release","-o",out,"-p:GatewayCoreCommercial=true",
            f"-p:GatewayCoreTrustFile={trust}","-p:GatewayCoreReleasePackage=true",
            f"-p:GatewayCoreReleaseTrustFile={release/'release-trust.json'}",f"-p:GatewayCoreReleaseSourceCommit={commit}")
        dlls.append(out/dll)
        rejected=run(out/dll,"--license-init",env=env,ok=False)
        assert rejected.returncode==78 and "Commercial package integrity rejected" in rejected.stderr
        run(fixture,"--ci-release-manifest",release,out,commit)
        verified=run(out/dll,"--verify-release",env=env)
        assert "COMMERCIAL_RELEASE_INTEGRITY_PASS "+commit in verified.stdout
        injected=out/"injected.txt"
        injected.write_text("unsigned")
        rejected=run(out/dll,"--license-init",env=env,ok=False)
        assert rejected.returncode==78 and "Commercial package integrity rejected" in rejected.stderr
        injected.unlink()
        result=run(out/dll,env=env,ok=False)
        assert "License" in result.stderr or "license" in result.stderr,result.stderr
    l4=dlls[0]
    run(l4,"--license-init",env=env)
    request=folder/"activation.gcr";licensefile=folder/"active.lic";revoke=folder/"revoke.gcv"
    run(l4,"--license-request",request,env=env)
    run(fixture,"--ci-engine-license",key,request,licensefile,"l4")
    run(l4,"--license-import",licensefile,env=env)
    for dll in dlls[1:]:
        result=run(dll,env=env,ok=False)
        assert "Active engine feature entitlement required" in result.stderr,result.stderr
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),Echo) as tcp,socketserver.ThreadingUDPServer(("127.0.0.1",0),UdpEcho) as udp:
        for server in (tcp,udp):threading.Thread(target=server.serve_forever,daemon=True).start()
        tp,up=free_port(socket.SOCK_STREAM),free_port(socket.SOCK_DGRAM)
        config=folder/"l4.json"
        def row(name,port,origin):return {"name":name,"listenHost":"127.0.0.1","listenPort":port,
            "backends":[{"host":"127.0.0.1","port":origin}]}
        config.write_text(json.dumps({"allowNonLoopbackListeners":False,"tcp":[row("tcp",tp,tcp.server_address[1])],
            "udp":[row("udp",up,udp.server_address[1])]}))
        with (folder/"engine.log").open("w+") as log:
            process=subprocess.Popen(["dotnet",str(l4),str(config)],env=env,stdout=log,stderr=subprocess.STDOUT)
            try:
                def tcp_echo():
                    try:
                        with socket.create_connection(("127.0.0.1",tp),timeout=.5) as c:
                            c.sendall(b"test");return c.recv(4)==b"test"
                    except OSError:return False
                def udp_echo():
                    try:
                        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as c:
                            c.settimeout(.5);c.sendto(b"test",("127.0.0.1",up));return c.recv(4)==b"test"
                    except OSError:return False
                for _ in range(40):
                    if process.poll() is not None:raise AssertionError("Engine exited")
                    if tcp_echo() and udp_echo():break
                    time.sleep(.2)
                else:raise AssertionError("Licensed traffic failed")
                with socket.create_connection(("127.0.0.1",tp),timeout=2) as established, socket.create_connection(("127.0.0.1",tp),timeout=2) as idle:
                    established.sendall(b"before")
                    assert established.recv(6)==b"before"
                    idle.sendall(b"warmup")
                    assert idle.recv(6)==b"warmup"
                    established.sendall(b"second")
                    assert established.recv(6)==b"second","fixture must maintain established stream"
                    run(fixture,"--ci-engine-revoke",key,request,revoke,"l4")
                    for _ in range(10):
                        imported=subprocess.run(["dotnet",str(l4),"--license-revoke",str(revoke)],env=env,capture_output=True)
                        if imported.returncode==0:break
                        time.sleep(.2)
                    else:raise AssertionError("Revocation import failed")
                    # Even an idle read must wake up and close, without requiring
                    # any additional client bytes or the normal 300s idle timeout.
                    assert process.wait(timeout=5)==78,"entitlement loss must stop the engine"
                    def closed(sock):
                        sock.settimeout(1)
                        try:return sock.recv(1)==b""
                        except (ConnectionResetError,ConnectionAbortedError,BrokenPipeError):return True
                    assert closed(idle),"already-open idle TCP flow survived revocation"
                    assert closed(established),"already-open active TCP flow survived revocation"
                    assert not tcp_echo() and not udp_echo(),"revoked engine admitted new traffic"
                print("COMMERCIAL_ENGINE_L4_ESTABLISHED_TCP_UDP_REVOCATION_PASS",flush=True)
            except Exception:
                log.flush();log.seek(0);print(log.read()[-6000:]);raise
            finally:
                if process.poll() is None:process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        result=run(l4,config,env=env,ok=False)
        assert "Active engine feature entitlement required" in result.stderr
        tcp.shutdown();udp.shutdown()
    if os.name=="posix":
        # Real agent binary and its existing loopback-only mTLS lab PKI.
        # No production PKI relaxation or gateway signing keys.
        pki=folder/"agent-pki";pki.mkdir()
        def openssl(*args):
            result=subprocess.run(["openssl",*map(str,args)],cwd=pki,capture_output=True,text=True,timeout=30)
            if result.returncode:raise AssertionError(result.stderr)
        openssl("req","-x509","-newkey","rsa:2048","-nodes","-days","2","-subj","/CN=disposable-fleet-root",
                "-addext","basicConstraints=critical,CA:TRUE","-addext","keyUsage=critical,keyCertSign,cRLSign",
                "-keyout","ca.key","-out","ca.pem")
        def cert(name,usage):
            openssl("req","-new","-newkey","rsa:2048","-nodes","-subj","/CN="+name,
                    "-keyout",name+".key","-out",name+".csr")
            ext=pki/(name+".ext")
            ext.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage="+usage+
                ("\nsubjectAltName=IP:127.0.0.1\n" if usage=="serverAuth" else "\n"))
            openssl("x509","-req","-in",name+".csr","-CA","ca.pem","-CAkey","ca.key","-CAcreateserial",
                    "-days","1","-sha256","-extfile",ext.name,"-out",name+".pem")
        cert("server","serverAuth");cert("controller","clientAuth");cert("untrusted-controller","clientAuth")
        pin="SHA256:"+hashlib.sha256(ssl.PEM_cert_to_DER_cert((pki/"controller.pem").read_text())).hexdigest().upper()
        # Existing agent policy accepts SHA-1 or SHA-256 pins; use SHA-256.
        def client(name=None):
            context=ssl.create_default_context(cafile=str(pki/"ca.pem"))
            if name:context.load_cert_chain(str(pki/(name+".pem")),str(pki/(name+".key")))
            return urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=context))
        def proof_request(opener,origin,nonce,expected=200):
            req=urllib.request.Request(origin+"/agent/v1/license/proof",data=json.dumps({"challenge":nonce}).encode(),
                headers={"Content-Type":"application/json"})
            try:
                with opener.open(req,timeout=4) as res:status,body=res.status,res.read()
            except urllib.error.HTTPError as exc:status,body=exc.code,exc.read()
            assert status==expected,(status,body[:300])
            return json.loads(body)["proof"] if expected==200 else None
        agent=dlls[3];processes=[];logs=[];nodes=[]
        try:
            for site in ("dc","dr"):
                node=folder/("agent-"+site);node.mkdir()
                node_env=dict(os.environ,GATEWAYCORE_ENGINE_LICENSE_DIR=str(node/"identity"))
                run(agent,"--license-init",env=node_env)
                activation=node/"activation.gcr";license_path=node/"active.lic"
                run(agent,"--license-request",activation,env=node_env)
                run(fixture,"--ci-fleet-license",key,activation,license_path,site)
                run(agent,"--license-import",license_path,env=node_env)
                port=free_port(socket.SOCK_STREAM);origin=f"https://127.0.0.1:{port}"
                node_env.update({"Agent__TrustedClientThumbprints__0":pin,
                    "Agent__LabOnlyClientCaCertificatePath":str(pki/"ca.pem"),
                    "Agent__EnableConfigChanges":"false","Agent__EnableEngineConfigChanges":"false","Agent__EnableServiceActions":"false",
                    "Kestrel__Endpoints__AgentHttps__Url":origin,
                    "Kestrel__Endpoints__AgentHttps__Certificate__Path":str(pki/"server.pem"),
                    "Kestrel__Endpoints__AgentHttps__Certificate__KeyPath":str(pki/"server.key")})
                log=(node/"agent.log").open("w+");logs.append(log)
                process=subprocess.Popen(["dotnet",str(agent)],cwd=node,env=node_env,stdout=log,stderr=subprocess.STDOUT)
                processes.append(process);nodes.append((origin,node_env,activation,node))
            controller=client("controller")
            challenges=[secrets.token_hex(32).upper() for _ in nodes]
            proofs=[]
            for (origin,_,_,node),challenge in zip(nodes,challenges):
                for _ in range(40):
                    try:
                        value=proof_request(controller,origin,challenge)
                        break
                    except (OSError,urllib.error.URLError):time.sleep(.25)
                else:raise AssertionError("Licensed agent did not become ready")
                path=node/"proof.gcp";path.write_text(value,encoding="ascii");proofs.append(path)
            result=run(fixture,"--ci-verify-fleet-proofs",trust,*challenges,*proofs)
            assert "REAL_MTLS_FLEET_PROOFS_VERIFIED" in result.stdout
            run(fixture,"--ci-verify-fleet-proofs",trust,secrets.token_hex(32).upper(),challenges[1],*proofs,ok=False)
            for unauthorized in (client(),client("untrusted-controller")):
                try:
                    proof_request(unauthorized,nodes[0][0],challenge)
                except (OSError,urllib.error.URLError,AssertionError) as exc:
                    if isinstance(exc,AssertionError):
                        assert exc.args and exc.args[0][0] in (401,403),exc
                else:raise AssertionError("Unauthorized client obtained a fleet proof")
            origin,node_env,activation,node=nodes[1]
            revocation=node/"revoke.gcv"
            run(fixture,"--ci-engine-revoke",key,activation,revocation,"fleet")
            for _ in range(10):
                imported=subprocess.run(["dotnet",str(agent),"--license-revoke",str(revocation)],env=node_env,capture_output=True)
                if imported.returncode==0:break
                time.sleep(.2)
            else:raise AssertionError("Agent revocation import failed")
            time.sleep(4)
            proof_request(controller,origin,secrets.token_hex(32).upper(),expected=402)
            print("COMMERCIAL_REAL_TWO_AGENT_MTLS_SITE_PROOF_REVOCATION_PASS",flush=True)
        except Exception:
            for log in logs:log.flush();log.seek(0);print(log.read()[-5000:])
            raise
        finally:
            for process in processes:
                if process.poll() is None:process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            for log in logs:log.close()
