#!/usr/bin/env python3
"""Real three-member etcd with pinned mTLS and actual commercial fleet rollout.
Persistent CAS ownership is tested across independent processes and partitions.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from real_quorum import certs, docker, open_port, post

ROOT=Path(__file__).resolve().parents[2]
IMAGE=os.environ["ETCD_IMAGE"]
assert os.environ.get("GITHUB_ACTIONS")=="true" and os.environ.get("RUNNER_ENVIRONMENT")=="github-hosted"
assert IMAGE.startswith("quay.io/coreos/etcd@sha256:") and len(IMAGE.rsplit(":",1)[1])==64
fixture=Path(os.environ["GC_FLEET_QUORUM_DLL"])
assert fixture.is_file()
def run(*args,env=None,ok=True):
    r=subprocess.run(["dotnet",str(fixture),*map(str,args)],env=env,text=True,capture_output=True,timeout=30)
    if (r.returncode==0)!=ok:raise AssertionError(r.stdout+r.stderr)
    return r.stdout.strip()
with tempfile.TemporaryDirectory(prefix="gc-fleet-raft-") as tmp:
    root=Path(tmp)
    root.chmod(0o700)
    ca,ids=certs(root/"certs")
    label=secrets.token_hex(8)
    network="gc-fleet-raft-"+label
    containers=[]
    ports=[open_port() for _ in range(3)]
    while len(set(ports))!=3:ports=[open_port() for _ in range(3)]
    try:
        docker("network","create",network)
        peers=",".join(f"ci{i}=http://ci{i}:2380" for i in (1,2,3))
        for i in (1,2,3):
            name="ci"+str(i);container=network+"-"+name
            data=root/name;data.mkdir(mode=0o700)
            docker("run","-d","--rm","--name",container,"--network",network,"--network-alias",name,
                "--user",f"{os.geteuid()}:{os.getegid()}","--cap-drop","ALL","--security-opt","no-new-privileges",
                "--pids-limit","128","--memory","512m","-v",str(root/"certs")+":/certs:ro","-v",str(data)+":/data",
                "-p",f"127.0.0.1:{ports[i-1]}:2379",IMAGE,"/usr/local/bin/etcd","--name="+name,"--data-dir=/data",
                "--listen-client-urls=https://0.0.0.0:2379","--advertise-client-urls=https://"+name+":2379",
                "--listen-peer-urls=http://0.0.0.0:2380","--initial-advertise-peer-urls=http://"+name+":2380",
                "--initial-cluster="+peers,"--initial-cluster-state=new","--initial-cluster-token="+label,
                "--cert-file=/certs/"+name+".pem","--key-file=/certs/"+name+".key","--trusted-ca-file=/certs/ca.pem",
                "--client-cert-auth=true")
            containers.append(container)
        writer_cert,writer_key,_=ids["writer"]
        probe=base64.b64encode(b"/gatewaycore/ci/probe").decode("ascii")
        endpoints=[];cluster=None
        for i,port in enumerate(ports,1):
            for _ in range(45):
                try:
                    h=post(("127.0.0.1",port),("/v3/kv/range",{"key":probe,"serializable":False}),ca,writer_cert,writer_key)["header"]
                    break
                except Exception:time.sleep(.5)
            else:raise AssertionError("Raft not ready")
            cluster=cluster or str(h["cluster_id"])
            assert cluster==str(h["cluster_id"])
            endpoints.append({"url":f"https://127.0.0.1:{port}/","leafSha256":ids["ci"+str(i)][2],"memberId":str(h["member_id"])})
        assert len({x["memberId"] for x in endpoints})==3
        scope=hashlib.sha256(b"engine-ci\nci\nci").hexdigest().upper()
        def config(role,overrides=None):
            cert,key,_=ids[role]
            p=root/(role+".json")
            doc={"scope":scope,"clusterId":cluster,"caFile":ca,"certFile":cert,"keyFile":key,"endpoints":endpoints}
            if overrides:doc.update(overrides)
            p.write_text(json.dumps(doc));p.chmod(0o600)
            return p
        writer=config("writer");reader=config("reader")
        one="rollout_"+"A"*24;two="rollout_"+"B"*24
        def contender(tx):
            p=subprocess.run(["dotnet",str(fixture),"acquire",str(writer),tx,"0"],capture_output=True,text=True,timeout=30)
            return tx,p
        with ThreadPoolExecutor(max_workers=2) as executor:
            race=list(executor.map(contender,(one,two)))
        winners=[(tx,int(p.stdout)) for tx,p in race if p.returncode==0]
        assert len(winners)==1,[(tx,p.returncode,p.stderr) for tx,p in race]
        tx,epoch=winners[0];loser=two if tx==one else one
        run("assert",reader,tx,epoch)
        run("assert",reader,loser,epoch,ok=False)
        run("release",writer,loser,epoch,ok=False)
        run("acquire",writer,loser,epoch,ok=False)
        run("release",writer,tx,epoch)
        run("acquire",writer,tx,epoch,ok=False)
        next_epoch=int(run("acquire",writer,loser,epoch))
        assert next_epoch>epoch
        run("assert",reader,tx,epoch,ok=False)
        run("release",writer,tx,epoch)
        run("wrong-outcome",writer,tx,epoch,ok=False)
        run("assert",reader,loser,next_epoch)
        run("release",writer,loser,next_epoch)
        print("PASS: actual independent controller CAS race, exact owner release, monotonic epoch and stale rejection",flush=True)
        # Real product acceptance uses the same three-member quorum, not mocks.
        env=dict(os.environ,GATEWAYCORE_FLEET_QUORUM_CONFIG=str(writer),GATEWAYCORE_AGENT_QUORUM_CONFIG=str(reader),
                 GC_FLEET_QUORUM_MEMBER_CONTAINERS=json.dumps(containers))
        subprocess.run([sys.executable,str(ROOT/"control-center/tests/EngineConfigSecurityTests/agent_crl_acceptance.py")],
            env=env,check=True,timeout=700)
        # Repeat quorum proof under actual 1/3 and 2/3 failures.
        one="rollout_"+"C"*24;two="rollout_"+"D"*24
        epoch=int(run("acquire",writer,one,0))
        docker("stop","--time","1",containers[-1])
        run("assert",reader,one,epoch)
        run("acquire",writer,two,epoch,ok=False)
        docker("stop","--time","1",containers[-2])
        run("assert",reader,one,epoch,ok=False)
        run("release",writer,one,epoch,ok=False)
        print("COMMERCIAL_FLEET_RAFT_FENCE_ACCEPTANCE_PASS",flush=True)
    finally:
        for c in reversed(containers):
            try:docker("rm","-f",c,timeout=15)
            except Exception:pass
        try:docker("network","rm",network,timeout=15)
        except Exception:pass
