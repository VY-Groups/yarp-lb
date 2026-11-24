"""Combined shipping gateway + distributed ring cutover on disposable CI.
No management endpoints are routed through the data-plane proxy.
"""
import contextlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

USER = {"username":"fixture-admin","password":"Disposable-fixture-password!",
        "email":"fixture@example.invalid","provider":"local"}

def private_write(path, data):
    tmp=path.with_name(path.name+".next")
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,"wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp,path)
    finally:
        tmp.unlink(missing_ok=True)

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0))
        return sock.getsockname()[1]

def request(p, path, body=None, cookie=None):
    conn=http.client.HTTPConnection("127.0.0.1",p,timeout=5)
    headers={"Accept":"application/json"}
    if cookie: headers["Cookie"]=cookie
    if body is not None: headers["Content-Type"]="application/json"
    try:
        conn.request("GET" if body is None else "POST",path,
                     None if body is None else json.dumps(body),headers)
        res=conn.getresponse()
        data=res.read()
        if res.status!=200:
            raise RuntimeError("shipping HTTP acceptance failed: "+str(res.status))
        return data,res.getheaders()
    finally: conn.close()

class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        data=self.server.label.encode("ascii")
        self.send_response(200)
        self.send_header("Content-Length",str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self,*args): pass

class Node:
    def __init__(self,root,product,wrapping,distributed=None):
        self.root=root;self.product=product;self.wrapping=wrapping
        self.distributed=distributed;self.process=None;self.port=port()
        root.mkdir(mode=0o700)
        (root/"config").mkdir(mode=0o700)
    def apply(self,destinations):
        config={"Logging":{"LogLevel":{"Default":"Warning"}},"AllowedHosts":"localhost;127.0.0.1",
            "ReverseProxy":{"Routes":{"fixture":{"ClusterId":"fixture","Match":{"Path":"/work/{**catch-all}"},
                "Transforms":[{"PathRemovePrefix":"/work"}]}},
                "Clusters":{"fixture":{"LoadBalancingPolicy":"RoundRobin","Destinations":{
                    name:{"Address":"http://127.0.0.1:"+str(p)+"/",
                          "Metadata":{"TrafficState":"draining" if drain else "active"}}
                    for name,(p,drain) in destinations.items()}}}}}
        private_write(self.root/"config"/"appsettings.json",json.dumps(config).encode())
    def start(self):
        env={k:v for k,v in os.environ.items() if not k.startswith(("YARP_","GATEWAY_","ASPNETCORE_"))}
        env.update(ASPNETCORE_ENVIRONMENT="Production",ASPNETCORE_URLS="http://127.0.0.1:"+str(self.port),
            YARP_CONTROL_PLANE_DIR=str(self.root),
            YARP_RUNTIME_CONFIG_PATH=str(self.root/"config"/"appsettings.json"),
            YARP_LINUX_DP_CERT_PFX_PATH=self.wrapping[0],YARP_LINUX_DP_CERT_PASSWORD_FILE=self.wrapping[1])
        if self.distributed: env["YARP_LINUX_DP_DISTRIBUTED_RING_CONFIG"]=self.distributed
        self.process=subprocess.Popen(["dotnet",str(self.product)],cwd=self.product.parent,
            env=env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            if self.process.poll() is not None: raise RuntimeError("shipping distributed gateway exited")
            try:
                request(self.port,"/gateway/health")
                return
            except (OSError,http.client.HTTPException,RuntimeError):
                time.sleep(.1)
        raise RuntimeError("shipping distributed gateway failed readiness")
    def stop(self):
        if self.process is not None:
            self.process.terminate()
            try: self.process.wait(timeout=8)
            except subprocess.TimeoutExpired: self.process.kill();self.process.wait(timeout=5)
            self.process=None
        if self.distributed:
            ring=self.root/"data-protection-keys"
            if ring.exists() and list(ring.iterdir()):
                raise RuntimeError("shipping distributed gateway persisted local keys")
    def login(self,bootstrap=False):
        raw,headers=request(self.port,"/admin/api/"+("bootstrap" if bootstrap else "login"),USER)
        if not json.loads(raw).get("authenticated"): raise RuntimeError("shipping login failed")
        tokens=[v.split(";",1)[0] for k,v in headers if k.lower()=="set-cookie" and
                v.startswith("GatewayCoreYarpAdmin=")]
        if len(tokens)!=1: raise RuntimeError("shipping login cookie missing")
        return tokens[0]
    def verify(self,cookie):
        raw,_=request(self.port,"/admin/api/session",cookie=cookie)
        result=json.loads(raw)
        if not result.get("authenticated") or result.get("username")!=USER["username"]:
            raise RuntimeError("shipping session continuity failed")

class Cutover:
    def __init__(self,root,product,wrap_a,wrap_b,writer_a,reader_b):
        self.root=root;root.mkdir(mode=0o700)
        self.a=Node(root/"a",product,wrap_a,writer_a)
        self.b=Node(root/"b",product,wrap_b,reader_b)
        self.proxy=Node(root/"proxy",product,wrap_a)
        self.origins=[];self.threads=[]
        self.gate=threading.Lock();self.stop_event=threading.Event()
        self.error=None;self.count=0;self.worker=None
        self.cookies=[]
    def __enter__(self):
        try:
            for label,node in (("a",self.a),("b",self.b)):
                origin=ThreadingHTTPServer(("127.0.0.1",0),Origin);origin.label=label
                self.origins.append(origin)
                thread=threading.Thread(target=origin.serve_forever,daemon=True)
                thread.start();self.threads.append(thread)
                node.apply({"origin":(origin.server_port,False)})
            self.a.start()
            self.old=self.a.login(bootstrap=True)
            # Fixture-only identity seeding while B is offline. Shared ring
            # is not an identity replication mechanism.
            private_write(self.b.root/"admin-users.json",(self.a.root/"admin-users.json").read_bytes())
            self.b.start();self.a.verify(self.old);self.b.verify(self.old)
            self.proxy.apply({"a":(self.a.port,False),"b":(self.b.port,False)})
            self.proxy.start()
            self.confirm({"a","b"})
            self.worker=threading.Thread(target=self.traffic,daemon=True);self.worker.start()
            return self
        except BaseException:
            self.__exit__(None,None,None);raise
    def probe(self):
        data,_=request(self.proxy.port,"/work/work/identity")
        label=data.decode("ascii")
        if label not in ("a","b"): raise RuntimeError("unexpected route result")
        return label
    def traffic(self):
        try:
            while not self.stop_event.is_set():
                with self.gate:
                    self.probe();self.count+=1
                time.sleep(.025)
        except BaseException as exc:
            self.error=exc
    def check(self):
        if self.error is not None: raise RuntimeError("continuous proxy workload failed") from self.error
    def confirm(self,active):
        deadline=time.monotonic()+20
        seen=set();consecutive=0
        while time.monotonic()<deadline:
            self.check()
            label=self.probe()
            if label in active:
                seen.add(label);consecutive+=1
                if seen==active and consecutive>=8: return
            else: seen.clear();consecutive=0
            time.sleep(.03)
        raise RuntimeError("shipping drain did not converge")
    def admit(self,active):
        self.proxy.apply({"a":(self.a.port,"a" not in active),
                          "b":(self.b.port,"b" not in active)})
        self.confirm(active)
        # Wait for the only continuous workload request to finish before
        # stopping the excluded process.
        with self.gate: self.check()
    def drain_a(self):
        self.admit({"b"});self.a.stop()
        self.b.verify(self.old);self.cookies.append(self.b.login())
        self.before=self.count
    def rejoin(self,reader_a,writer_b):
        self.check()
        self.a.distributed=reader_a;self.a.start();self.a.verify(self.old)
        new=self.a.login()
        import base64
        def keyid(cookie):
            token=cookie.split("=",1)[1]
            return base64.urlsafe_b64decode(token+"="*((-len(token))%4))[4:20]
        if keyid(new)==keyid(self.old): raise RuntimeError("shipping login did not use new ring key")
        self.cookies.append(new)
        self.admit({"a"});self.b.stop()
        self.a.verify(self.old);self.a.verify(new)
        self.b.distributed=writer_b;self.b.start()
        for cookie in [self.old,*self.cookies]:
            self.a.verify(cookie);self.b.verify(cookie)
        self.admit({"a","b"})
        deadline=time.monotonic()+10
        while self.count<self.before+3:
            self.check()
            if time.monotonic()>deadline: raise RuntimeError("no workload progress during restart")
            time.sleep(.03)
        self.check()
        print("PASS: delivered credentials + real Raft writer rollover + actual shipping gateway login continuity and continuous YARP drain",flush=True)
    def __exit__(self,exc_type,exc,tb):
        self.stop_event.set()
        try:
            if self.worker:
                self.worker.join(8)
                if self.worker.is_alive(): raise RuntimeError("workload did not stop")
            if exc_type is None: self.check()
        finally:
            for node in (self.proxy,self.a,self.b):
                try: node.stop()
                except Exception:
                    if exc_type is None: raise
            for origin in self.origins: origin.shutdown();origin.server_close()
            for thread in self.threads: thread.join(2)
