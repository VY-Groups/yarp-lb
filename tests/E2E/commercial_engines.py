#!/usr/bin/env python3
"""Compile all separate commercial engines and test real L4 admission and revocation."""
import json
import os
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
        data=self.request.recv(4096)
        if data:self.request.sendall(data)
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
    for project,dll in projects:
        out=folder/Path(project).stem
        run("build",root/project,"-c","Release","-o",out,"-p:GatewayCoreCommercial=true",f"-p:GatewayCoreTrustFile={trust}")
        dlls.append(out/dll)
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
                run(fixture,"--ci-engine-revoke",key,request,revoke,"l4")
                # Local state lock can transiently contend with the independent refresh.
                for _ in range(10):
                    imported=subprocess.run(["dotnet",str(l4),"--license-revoke",str(revoke)],env=env,capture_output=True)
                    if imported.returncode==0:break
                    time.sleep(.2)
                else:raise AssertionError("Revocation import failed")
                time.sleep(4)
                assert not tcp_echo() and not udp_echo(),"revoked engine admitted new traffic"
                print("COMMERCIAL_ENGINE_L4_TCP_UDP_REVOCATION_PASS",flush=True)
            except Exception:
                log.flush();log.seek(0);print(log.read()[-6000:]);raise
            finally:
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()
        result=run(l4,config,env=env,ok=False)
        assert "Active engine feature entitlement required" in result.stderr
        tcp.shutdown();udp.shutdown()
