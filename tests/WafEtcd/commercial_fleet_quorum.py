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
    ca,ids=certs(root/"certs",("vip-successor",))
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
        # Separate VIP owner namespace, exact canonical address and independent client cert.
        vip_scope=hashlib.sha256(b"gatewaycore-adc-vip-v1\nci\n192.0.2.10").hexdigest().upper()
        vip_key=base64.b64encode(("/gatewaycore/adc-vip/v1/"+vip_scope).encode()).decode()
        vip_reader=root/"vip-reader.json";vip_writer=root/"vip-writer.json";vip_successor=root/"vip-successor.json"
        for path,role in [(vip_reader,"reader"),(vip_writer,"writer"),(vip_successor,"vip-successor")]:
            cert,key,_=ids[role]
            path.write_text(json.dumps({"scope":vip_scope,"clusterId":cluster,"caFile":ca,"certFile":cert,
                                        "keyFile":key,"endpoints":endpoints}));path.chmod(0o600)
        # Independent disposable P-256 signing authority. No production keys.
        fence_key=root/"fence.key";fence_pub=root/"fence.pub";sig=root/"permit.der";message=root/"permit.txt"
        subprocess.run(["openssl","genpkey","-algorithm","EC","-pkeyopt","ec_paramgen_curve:P-256","-out",str(fence_key)],check=True)
        fence_key.chmod(0o600)
        subprocess.run(["openssl","pkey","-in",str(fence_key),"-pubout","-out",str(fence_pub)],check=True)
        spki=subprocess.check_output(["openssl","pkey","-pubin","-in",str(fence_pub),"-outform","DER"])
        authority_config=json.loads(vip_writer.read_text())
        authority_config.update(vipFencePublicKeyFile=str(fence_pub),vipFencePublicKeySha256=hashlib.sha256(spki).hexdigest().upper())
        vip_writer.write_text(json.dumps(authority_config));vip_writer.chmod(0o600)
        def permit(old,epoch,new,expires):
            message.write_text("\n".join(("GatewayCore.VIP.HardFence.v1",vip_scope,old,str(epoch),new,str(expires))),encoding="utf-8")
            subprocess.run(["openssl","dgst","-sha256","-sign",str(fence_key),"-out",str(sig),str(message)],check=True)
        def owner(*args,ok=True):
            return json.loads(run("--vip-owner",vip_writer,vip_scope,*args,ok=ok)) if ok else run("--vip-owner",vip_writer,vip_scope,*args,ok=False)
        reader_pin=ids["reader"][2];successor_pin=ids["vip-successor"][2]
        run("vip-check",vip_reader,vip_scope,1,ok=False)
        expires=int(time.time())+120
        permit("-",0,reader_pin,expires)
        vip_epoch=owner("activate","-",0,reader_pin,expires,sig)["epoch"]
        run("vip-check",vip_reader,vip_scope,vip_epoch)
        run("vip-check",vip_successor,vip_scope,vip_epoch,ok=False)
        run("vip-check",vip_reader,vip_scope,vip_epoch+1,ok=False)
        run("vip-check",vip_reader,scope,vip_epoch,ok=False)
        owner("activate","-",0,reader_pin,expires,sig,ok=False)
        owner("revoke",reader_pin,vip_epoch+1,ok=False)
        revoked=owner("revoke",reader_pin,vip_epoch)["epoch"]
        assert revoked>vip_epoch
        run("vip-check",vip_reader,vip_scope,vip_epoch,ok=False)
        run("vip-check",vip_successor,vip_scope,revoked,ok=False)
        # Replay and wrong-successor permits cannot authorize the new owner.
        owner("activate","-",0,reader_pin,expires,sig,ok=False)
        expires=int(time.time())+120
        permit(reader_pin,revoked,successor_pin,expires)
        owner("activate",reader_pin,revoked,reader_pin,expires,sig,ok=False)
        vip_epoch=owner("activate",reader_pin,revoked,successor_pin,expires,sig)["epoch"]
        assert vip_epoch>revoked
        run("vip-check",vip_successor,vip_scope,vip_epoch)
        run("vip-check",vip_reader,vip_scope,vip_epoch,ok=False)
        owner("activate",reader_pin,revoked,successor_pin,expires,sig,ok=False)
        assert owner("status")=={"owner":"vip_"+successor_pin,"epoch":vip_epoch}
        print("PASS: actual Raft VIP revoke, signed exact successor CAS, replay and old owner rejection",flush=True)
        # The real interrupted-transaction fixture reserves A*24. Never reuse a completed ID.
        one="rollout_"+"6"*24;two="rollout_"+"7"*24
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
        run("vip-check",vip_successor,vip_scope,vip_epoch)
        run("assert",reader,one,epoch)
        run("acquire",writer,two,epoch,ok=False)
        docker("stop","--time","1",containers[-2])
        run("vip-check",vip_successor,vip_scope,vip_epoch,ok=False)
        owner("status",ok=False)
        run("assert",reader,one,epoch,ok=False)
        run("release",writer,one,epoch,ok=False)
        print("COMMERCIAL_FLEET_RAFT_FENCE_ACCEPTANCE_PASS",flush=True)
    finally:
        for c in reversed(containers):
            try:docker("rm","-f",c,timeout=15)
            except Exception:pass
        try:docker("network","rm",network,timeout=15)
        except Exception:pass
