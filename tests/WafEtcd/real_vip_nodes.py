"""Hosted-only two shipping gateway/agent instances in separate Linux netns.

The TCP relays do not terminate TLS, interpret requests, or choose owners.
Redfish hardware power/boot remains simulated by stopping fixture units and
removing their exact disposable interface address. No physical HA claim.
"""
import concurrent.futures
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import uuid


def guard():
    if (os.geteuid()!=0 or os.getenv("GITHUB_ACTIONS")!="true" or
            os.getenv("RUNNER_ENVIRONMENT")!="github-hosted"):
        raise RuntimeError("Disposable elevated hosted CI only")


class Relay(socketserver.ThreadingTCPServer):
    allow_reuse_address=True
    daemon_threads=True
    block_on_close=False

    def __init__(self, address, target):
        self.target=target
        super().__init__(address, RelayHandler)


class RelayHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            with socket.create_connection(self.server.target,timeout=3) as remote:
                self.request.settimeout(10)
                remote.settimeout(10)
                peers={self.request:remote,remote:self.request}
                readers=list(peers)
                while readers:
                    ready,_,_=select.select(readers,[],[],180)
                    if not ready:
                        return
                    for src in ready:
                        data=src.recv(65536)
                        dst=peers[src]
                        if data:
                            dst.sendall(data)
                        else:
                            readers.remove(src)
                            try:
                                dst.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
        except OSError:
            pass


class RealVipNodes:
    def __init__(self,root,executable,manifest,scope,fleet,vip,run,put,copy,passfile):
        guard()
        self.root=Path(root)
        self.executable=Path(executable)
        self.manifest=manifest
        self.scope,self.fleet,self.vip=scope,fleet,vip
        self.run,self.put,self.copy,self.passfile=run,put,copy,passfile
        self.nodes={}
        self.units=[]
        self.namespaces=[]
        self.links=[]
        self.host_relays=[]
        self.children=[]
        self.backends=[]
        self.done=threading.Event()
        self.monitor=None
        self.monitor_error=None
        self.samples=[]
        self.sample_lock=threading.Lock()
        self.suffix=uuid.uuid4().hex[:7]
        self.port=18443  # Same application address and port, separate netns.
        self.ca_dir=self.root/"real-node-traffic-ca"
        self.ca_dir.mkdir(mode=0o700)
        self.ca_key=self.ca_dir/"ca.key"
        self.ca=self.ca_dir/"ca.pem"
        self.run("openssl","req","-new","-x509","-nodes","-newkey","rsa:3072",
            "-sha256","-days","2","-subj","/CN=Disposable two-node VIP CA",
            "-addext","basicConstraints=critical,CA:TRUE",
            "-addext","keyUsage=keyCertSign,cRLSign","-keyout",self.ca_key,"-out",self.ca)
        self.ca_key.chmod(0o600)
        self.ca.chmod(0o600)

    def openssl(self,*args):
        self.run("openssl",*args)

    def pfx(self,d,name,key,cert):
        pw=self.passfile(d,name+".password")
        target=d/(name+".pfx")
        self.openssl("pkcs12","-export","-in",cert,"-inkey",key,
            "-out",target,"-passout","file:"+str(pw))
        target.chmod(0o600)
        return str(target),str(pw)

    def pin(self,path):
        return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(path).read_text())).hexdigest().upper()

    def host_relay(self,listen,target):
        server=Relay(listen,target)
        self.host_relays.append(server)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        return server.server_address[1]

    def namespace_relay(self,ns,listen_ip,port,target_ip,target_port):
        process=subprocess.Popen(["ip","netns","exec",ns,sys.executable,str(Path(__file__).resolve()),
            "--relay",listen_ip,str(port),target_ip,str(target_port)],
            stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True)
        self.children.append(process)
        ready,_,_=select.select([process.stdout],[],[],10)
        if not ready or process.stdout.readline().strip()!="READY":
            raise AssertionError("Disposable namespace relay failed to start")
        process.stdout.close()

    def unit(self,name,ns,args,env):
        path=Path("/etc/systemd/system")/(name+".service")
        if path.exists() or path.is_symlink() or self.run("systemctl","cat",name+".service",check=False).returncode==0:
            raise AssertionError("Existing fixture unit; refuse mutation")
        # All values are fixture-generated paths/hex identifiers, not site input.
        for value in [str(self.executable),str(self.executable.parent),str(Path("/run/netns")/ns),*map(str,args),*env.values()]:
            if any(c in value for c in (' ','\n','\r','"','%','\\')):
                raise AssertionError("Unexpected fixture service argument")
        data="[Unit]\nDescription=Disposable two-node VIP acceptance\n[Service]\n"
        data+="Type=simple\nRestart=no\nUMask=0077\nTimeoutStopSec=30\n"
        data+="NetworkNamespacePath=/run/netns/"+ns+"\nWorkingDirectory="+str(self.executable.parent)+"\n"
        for k,v in env.items():
            data+="Environment="+k+"="+v+"\n"
        data+="ExecStart="+str(self.executable)+(" "+" ".join(map(str,args)) if args else "")+"\n"
        with path.open("x",encoding="ascii") as out:
            out.write(data)
        self.units.append((name,path))
        self.run("systemctl","daemon-reload")

    def addresses(self):
        # Never overlap an existing non-default route. Only benchmarking
        # addresses in a fresh, directly connected /30 are used for relays.
        routes=json.loads(self.run("ip","-j","route","show","table","all").stdout)
        networks=[ipaddress.ip_network(x["dst"],strict=False) for x in routes
            if x.get("dst") not in (None,"default") and ":" not in x["dst"]]
        for _ in range(32):
            octet=os.urandom(1)[0]
            nets=[ipaddress.ip_network("198.19."+str(octet)+"."+str(n)+"/30") for n in (0,4)]
            if not any(n.overlaps(existing) for n in nets for existing in networks):
                return nets
        raise AssertionError("No unused disposable relay subnets")

    def prepare(self):
        for i,net in enumerate(self.addresses()):
            self.prepare_one(i,net)

    def prepare_one(self,i,net):
        label="a" if i==0 else "b"
        ns="gcvip-"+self.suffix+"-"+label
        host="gch"+self.suffix+label
        peer="gcm"+self.suffix+label
        nic="gcv"+self.suffix+label
        dummy_peer="gcp"+self.suffix+label
        host_ip,node_ip=map(str,net.hosts())
        if self.run("ip","netns","list").stdout.find(ns)!=-1:
            raise AssertionError("Existing fixture namespace")
        if self.run("ip","link","show","dev",host,check=False).returncode==0:
            raise AssertionError("Existing fixture link")
        self.run("ip","netns","add",ns)
        self.namespaces.append(ns)
        self.run("ip","link","add",host,"type","veth","peer","name",peer)
        self.links.append(host)
        self.run("ip","link","set",peer,"netns",ns)
        self.run("ip","addr","add",host_ip+"/30","dev",host)
        self.run("ip","link","set",host,"up")
        self.run("ip","-n",ns,"addr","add",node_ip+"/30","dev",peer)
        self.run("ip","-n",ns,"link","set",peer,"up")
        self.run("ip","-n",ns,"link","set","lo","up")
        self.run("ip","-n",ns,"link","add",nic,"type","veth","peer","name",dummy_peer)
        self.run("ip","-n",ns,"link","set",nic,"up")
        self.run("ip","-n",ns,"link","set",dummy_peer,"up")
        # etcd publishes host-loopback-only TLS endpoints. Forward raw TCP
        # from the same loopback address/port inside each isolated namespace.
        for endpoint in self.manifest["endpoints"]:
            p=int(endpoint["url"].rsplit(":",1)[1])
            relay=self.host_relay((host_ip,0),("127.0.0.1",p))
            self.namespace_relay(ns,"127.0.0.1",p,host_ip,relay)

        d=self.root/("real-node-"+label)
        d.mkdir(mode=0o700)
        state=d/"state";state.mkdir(mode=0o700)
        journal=d/"vip-journal";journal.mkdir(mode=0o700)
        certdir=d/"certs";certdir.mkdir(mode=0o700)
        cfg=state/"config";cfg.mkdir(mode=0o700)
        node=self.manifest["nodeA" if i==0 else "nodeB"]
        other=self.manifest["nodeB" if i==0 else "nodeA"]
        ra,_,provider_pin=self.manifest["reader"]
        server_cert,server_key,server_pin=self.manifest["agent"+str(i)]
        ca=self.copy(certdir,"quorum-ca.pem",self.manifest["ca"])
        node_cert=self.copy(certdir,"node.pem",node[0])
        node_key=self.copy(certdir,"node.key",node[1])
        reader=self.put(d,"reader.json",{"scope":self.scope,"clusterId":str(self.manifest["cluster"]),
            "caFile":str(ca),"certFile":str(node_cert),"keyFile":str(node_key),
            "endpoints":[dict(e,memberId=str(e["memberId"])) for e in self.manifest["endpoints"]]})
        server_pfx,server_pass=self.pfx(certdir,"management",server_key,server_cert)
        tk=certdir/"traffic.key";tc=certdir/"traffic.pem";csr=certdir/"traffic.csr"
        self.openssl("req","-new","-nodes","-newkey","rsa:2048","-subj","/CN=Disposable VIP "+label,
            "-keyout",tk,"-out",csr)
        ext=self.put(certdir,"traffic.ext","subjectAltName=IP:"+self.vip+"\nextendedKeyUsage=serverAuth\n")
        self.openssl("x509","-req","-in",csr,"-CA",self.ca,"-CAkey",self.ca_key,"-CAcreateserial",
            "-days","2","-sha256","-extfile",ext,"-out",tc)
        traffic_pfx,traffic_pass=self.pfx(certdir,"traffic",tk,tc)
        dpkey=certdir/"dp.key";dpcrt=certdir/"dp.crt"
        self.openssl("req","-new","-x509","-nodes","-newkey","rsa:3072","-sha256","-days","7",
            "-subj","/CN=Disposable VIP DP "+label,"-addext","basicConstraints=critical,CA:FALSE",
            "-addext","keyUsage=critical,keyEncipherment","-keyout",dpkey,"-out",dpcrt)
        dp_pfx,dp_pass=self.pfx(certdir,"dp",dpkey,dpcrt)
        probe_ca=self.copy(certdir,"traffic-ca.pem",self.ca)
        for p in certdir.iterdir():
            p.chmod(0o600)
        healthy=threading.Event();healthy.set()
        marker=("fixture-"+label).encode("ascii")
        class Backend(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_GET(self):
                if self.path not in ("/api/identity","/health/ready"):
                    code,body=404,b"unknown"
                elif not healthy.is_set():
                    code,body=503,b"not ready"
                else:
                    code,body=200,marker if self.path=="/api/identity" else b"ready"
                self.send_response(code)
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        backend=http.server.ThreadingHTTPServer((host_ip,0),Backend)
        self.backends.append(backend)
        threading.Thread(target=backend.serve_forever,daemon=True).start()
        # Node-local management and traffic ports are intentionally distinct
        # from the stable VIP port. Only the host loopback relay is exposed.
        # Reserve the etcd relay ports from the fixed fixture port range.
        used={int(e["url"].rsplit(":",1)[1]) for e in self.manifest["endpoints"]}|{self.port}
        ports=[p for p in range(18500,18520) if p not in used][:6]
        http_port,https_port,admin_port,metrics_port,agent_port,probe_port=ports
        listener=self.put(d,"listeners.json",{"trafficIp":"127.0.0.2","trafficHttpPort":http_port,
            "trafficHttpsPort":https_port,"managementIp":node_ip,"adminPort":admin_port,
            "metricsPort":metrics_port,"trafficPfxPath":traffic_pfx,"trafficPfxPasswordFile":traffic_pass,
            "managementPfxPath":server_pfx,"managementPfxPasswordFile":server_pass,
            "clientCaPemPath":str(ca),"clientThumbprints":[provider_pin],
            "allowedAdminCidrs":[host_ip+"/32"],"maxConcurrentConnections":64,"httpVersion":"1.1",
            "virtualServices":[{"id":"policy-vip","ip":self.vip,"port":self.port,"protocol":"HTTPS",
                "requireLocalAddressPresence":True,"vipFleetId":self.fleet,"vipQuorumConfigPath":str(reader),
                "vipJournalDirectory":str(journal),"vipInterfaceId":nic}]})
        runtime=self.put(cfg,"appsettings.json",{"Logging":{"LogLevel":{"Default":"Warning"}},
            "ReverseProxy":{"Routes":{"policy-vip":{"ClusterId":"policy-backend",
                "Match":{"Path":"/api/identity"},"Metadata":{"ADC.VirtualServer.Id":"policy-vip"}}},
                "Clusters":{"policy-backend":{"HealthCheck":{"AvailableDestinationsPolicy":"HealthyAndUnknown",
                    "Active":{"Enabled":True,"Interval":"00:00:01","Timeout":"00:00:01",
                        "Policy":"ConsecutiveFailures","Path":"/health/ready"}},
                    "Destinations":{"fixture":{"Address":"http://"+host_ip+":"+str(backend.server_port)+"/"}}}}}})
        gateway="gc-vip-ci-"+self.suffix+"-"+label+"-gateway"
        agent="gc-vip-ci-"+self.suffix+"-"+label+"-agent"
        supervisor=self.put(d,"supervisor.json",{"scope":self.scope,"serviceId":"policy-vip",
            "serviceName":gateway+".service","listenerConfig":str(listener),
            "probePath":"/api/identity","probeCaFile":str(probe_ca),"probeLeafSha256":self.pin(tc),
            "probeBodySha256":hashlib.sha256(marker).hexdigest().upper()})
        agent_config=self.put(d,"agent.json",{"scope":self.scope,"nodePin":node[2],"otherPin":other[2],
            "readerConfig":str(reader),"supervisorConfig":str(supervisor),"server":{"listenIp":node_ip,
                "port":agent_port,"pfx":server_pfx,"passwordFile":server_pass,
                "clientCaFile":str(ca),"clientPin":provider_pin}})
        common={"DOTNET_ROOT":os.environ["DOTNET_ROOT"],"ASPNETCORE_ENVIRONMENT":"Production"}
        env=dict(common,YARP_CONTROL_PLANE_DIR=str(state),YARP_RUNTIME_CONFIG_PATH=str(runtime),
            YARP_LISTENERS_CONFIG_FILE=str(listener),YARP_LINUX_DP_CERT_PFX_PATH=dp_pfx,
            YARP_LINUX_DP_CERT_PASSWORD_FILE=dp_pass,GATEWAYCORE_VIP_DRAIN_CLIENT_SHA256=provider_pin,
            GATEWAYCORE_VIP_DRAIN_SCOPE=self.scope)
        self.unit(gateway,ns,[],env)
        self.unit(agent,ns,["--vip-node-agent",agent_config],common)
        inspection=self.run("ip","netns","exec",ns,self.executable,"--vip-node-agent",agent_config,"inspect")
        evidence=json.loads(inspection.stdout)
        if not evidence["validated"] or evidence["mutated"] or evidence["networkVerified"] or evidence["nodePin"]!=node[2]:
            raise AssertionError("Actual node preflight not confirmed")
        ap=self.host_relay(("127.0.0.1",0),(node_ip,agent_port))
        dp=self.host_relay(("127.0.0.1",0),(node_ip,admin_port))
        self.namespace_relay(ns,node_ip,probe_port,self.vip,self.port)
        self.nodes[node[2]]={"label":label,"ns":ns,"nic":nic,"gateway":gateway,"agent":agent,
            "journal":journal,"state":state,"healthy":healthy,"marker":marker,
            "address":node_ip,"probe":probe_port,"agent_port":ap,"drain_port":dp,
            "server_pin":server_pin,"other":other[2]}
        self.run("systemctl","start",agent+".service")
        self.wait_agent(node[2])

    def active(self,name):
        return self.run("systemctl","is-active","--quiet",name+".service",check=False).returncode==0

    def stop_unit(self,name):
        self.run("systemctl","stop",name+".service")
        if self.active(name):
            raise AssertionError("Fixture service did not stop")

    def request_agent(self,pin,route,payload):
        node=self.nodes[pin]
        cert,key,_=self.manifest["reader"]
        ctx=ssl.create_default_context(cafile=self.manifest["ca"])
        ctx.load_cert_chain(cert,key)
        conn=http.client.HTTPSConnection("127.0.0.1",node["agent_port"],context=ctx,timeout=105)
        try:
            conn.request("POST",route,json.dumps(payload),{"Content-Type":"application/json"})
            response=conn.getresponse()
            body=response.read(4096)
            return response.status,body
        finally:
            conn.close()

    def wait_agent(self,pin):
        end=time.monotonic()+35
        while time.monotonic()<end:
            try:
                if self.active(self.nodes[pin]["agent"]) and self.request_agent(pin,"/v1/vip-node/status",{"unexpected":True})[0]==503:
                    return
            except (OSError,http.client.HTTPException):
                pass
            time.sleep(.3)
        raise AssertionError("Actual node agent did not start")

    def machine(self,pin,ca,cert,key,drain=False):
        node=self.nodes[pin]
        port=node["drain_port" if drain else "agent_port"]
        return {"origin":"https://127.0.0.1:"+str(port),"leafSha256":node["server_pin"],
            "caFile":str(ca),"certFile":str(cert),"keyFile":str(key)}

    def present(self,pin):
        n=self.nodes[pin]
        items=json.loads(self.run("ip","-n",n["ns"],"-j","address","show").stdout)
        matches=[(x["ifname"],a["prefixlen"]) for x in items for a in x.get("addr_info",[]) if a.get("local")==self.vip]
        if matches and matches!=[(n["nic"],32)]:
            raise AssertionError("Unexpected fixture VIP interface or prefix")
        return bool(matches)

    def power_off(self,pin):
        n=self.nodes[pin]
        self.stop_unit(n["gateway"])
        self.stop_unit(n["agent"])
        # Simulated power loss only: kernel loses its assigned address, but
        # the shipping node's private durable journal is left untouched.
        if self.present(pin):
            self.run("ip","-n",n["ns"],"address","del",self.vip+"/32","dev",n["nic"])
        if self.present(pin):
            raise AssertionError("Simulated power-off did not isolate fixture node")

    def power_on(self,pin):
        n=self.nodes[pin]
        if self.active(n["gateway"]) or self.present(pin):
            raise AssertionError("Rearm must boot a non-serving standby")
        n["healthy"].set()
        self.run("systemctl","start",n["agent"]+".service")
        self.wait_agent(pin)

    def healthy(self,pin,value):
        event=self.nodes[pin]["healthy"]
        event.set() if value else event.clear()

    def compensated(self,pin):
        node=self.nodes[pin]
        if self.active(node["gateway"]) or self.present(pin):
            return False
        files=list(node["journal"].glob("*.journal"))
        if len(files)!=1:
            return False
        rows=files[0].read_text().splitlines()
        return bool(rows) and json.loads(rows[-1])["Phase"]=="withdrawn"

    def probe(self,pin):
        node=self.nodes[pin]
        ctx=ssl.create_default_context(cafile=str(self.ca))
        conn=http.client.HTTPSConnection(self.vip,self.port,context=ctx,timeout=2)
        # TCP-only relay targets the exact VIP inside this namespace; keep
        # the original VIP TLS name and CA validation at the actual client.
        conn._create_connection=lambda _address,timeout,source_address: socket.create_connection(
            (node["address"],node["probe"]),timeout,source_address)
        try:
            conn.request("GET","/api/identity",headers={"Connection":"close"})
            response=conn.getresponse()
            data=response.read(1024)
            if response.status==200:
                if data!=node["marker"]:
                    raise AssertionError("Actual gateway returned incorrect origin identity")
                return True
            if response.status not in (502,503,504):
                raise AssertionError("Unexpected actual VIP HTTP status "+str(response.status))
            return False
        except ssl.SSLCertVerificationError:
            raise
        except (OSError,http.client.HTTPException):
            return False
        finally:
            conn.close()

    def activate_initial(self,pin,epoch):
        code,body=self.request_agent(pin,"/v1/vip-node/activate",
            {"scope":self.scope,"ownerPin":pin,"epoch":epoch,"otherPin":self.nodes[pin]["other"],
                "nonce":os.urandom(32).hex().upper()})
        if code!=200 or json.loads(body).get("serving") is not True or not self.probe(pin):
            raise AssertionError("Actual initial owner activation failed")
        if self.present(self.nodes[pin]["other"]) or self.probe(self.nodes[pin]["other"]):
            raise AssertionError("Actual initial standby exposed VIP")
        self.monitor=threading.Thread(target=self.sample,daemon=True)
        self.monitor.start()

    def sample(self):
        pins=list(self.nodes)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                while not self.done.is_set():
                    results=list(pool.map(self.probe,pins))
                    with self.sample_lock:
                        self.samples.append((time.monotonic(),tuple(results)))
                        if len(self.samples)>5000:
                            raise AssertionError("Unbounded traffic fixture")
                    if all(results):
                        raise AssertionError("Both actual gateways admitted traffic in one concurrent sample")
                    self.done.wait(.35)
        except BaseException as error:
            self.monitor_error=error
            self.done.set()

    def assert_outage(self):
        if self.monitor_error:
            raise self.monitor_error
        with self.sample_lock:
            recent=[v for t,v in self.samples if time.monotonic()-t<8]
        if not recent or any(any(v) for v in recent):
            raise AssertionError("Actual VIP did not fail closed in the stable outage window")

    def verify_traffic(self):
        if self.monitor_error:
            raise self.monitor_error
        with self.sample_lock:
            samples=list(self.samples)
        counts=[sum(1 for _,v in samples if v[i]) for i in range(2)]
        outages=sum(1 for _,v in samples if not any(v))
        if min(counts)<5 or outages<5 or any(all(v) for _,v in samples):
            raise AssertionError("Insufficient actual two-node traffic transition coverage")
        print("PASS: continuously sampled both actual VIP TLS sockets; successful node samples="+
            str(counts)+", fail-closed outage samples="+str(outages)+", simultaneous successful samples=0",flush=True)

    def close(self):
        errors=[]
        self.done.set()
        if self.monitor:
            self.monitor.join(timeout=10)
            if self.monitor.is_alive():
                errors.append("traffic sampler")
        for name,path in reversed(self.units):
            try:
                self.stop_unit(name)
                path.unlink()
            except Exception:
                errors.append("service "+name)
        try:
            self.run("systemctl","daemon-reload")
        except Exception:
            errors.append("systemd reload")
        for p in reversed(self.children):
            try:
                p.terminate()
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill();p.wait(timeout=5)
        for server in self.host_relays+self.backends:
            server.shutdown();server.server_close()
        for host in reversed(self.links):
            try:
                self.run("ip","link","delete",host)
            except Exception:
                errors.append("fixture link")
        for ns in reversed(self.namespaces):
            try:
                self.run("ip","netns","delete",ns)
            except Exception:
                errors.append("fixture namespace")
        if errors:
            raise AssertionError("Incomplete disposable node cleanup: "+", ".join(errors))


if __name__=="__main__":
    guard()
    if len(sys.argv)!=6 or sys.argv[1]!="--relay":
        raise SystemExit("Internal hosted fixture relay only")
    with Relay((sys.argv[2],int(sys.argv[3])),(sys.argv[4],int(sys.argv[5]))) as relay:
        print("READY",flush=True)
        relay.serve_forever()
