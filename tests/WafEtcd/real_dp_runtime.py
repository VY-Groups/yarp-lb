"""Real .NET encrypted ring and cookie acceptance against disposable Raft.

No synthetic RPCs. The caller owns the real cluster and removes it.
The fixture uses distinct TLS leaves and independent private state roots.
It does not enable etcd RBAC or claim independently housed physical hosts.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time

FLEET = "fleet-dotnet-ci"
PREFIX = "/gatewaycore/linux-dp/runtime-ring/" + FLEET + "/"
WRITER = "/gatewaycore/linux-dp/runtime-writer/" + FLEET


def b64(value):
    return base64.b64encode(value.encode("ascii")).decode("ascii")


def private_file(path, data):
    with os.fdopen(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600),
                   "w", encoding="ascii") as output:
        output.write(data)
    return str(path)


def run(root, endpoints, cluster, ca, ids, addr, post, checked):
    dll = Path(os.environ.get("DP_RUNTIME_FIXTURE_DLL", ""))
    if not dll.is_absolute() or not dll.is_file():
        raise RuntimeError("required real .NET acceptance executable missing")
    state = root / "dotnet-runtime"
    state.mkdir(mode=0o700)
    provision = state / "provision"
    provision.mkdir(mode=0o700)
    wrapping_key, wrapping_crt = provision/"wrap.key", provision/"wrap.pem"
    checked(["openssl","req","-x509","-nodes","-newkey","rsa:3072","-sha256",
             "-days","30","-subj","/CN=Disposable DP wrapping",
             "-addext","basicConstraints=critical,CA:FALSE",
             "-addext","keyUsage=critical,keyEncipherment",
             "-keyout",str(wrapping_key),"-out",str(wrapping_crt)])
    wrapping_key.chmod(0o600)
    def pfx_for(name, certificate, key):
        password = private_file(provision/(name+".password"),secrets.token_hex(24))
        pfx = provision/(name+".pfx")
        checked(["openssl","pkcs12","-export","-in",str(certificate),
                 "-inkey",str(key),"-out",str(pfx),"-passout","file:"+password])
        pfx.chmod(0o600)
        return str(pfx), password

    # Provision one source wrapping identity, then use the actual offline
    # delivery CLI in separate processes. The destination runtime only sees
    # its own received credential files, never the original PFX or sender key.
    source_pfx,source_password=pfx_for("source-wrap",wrapping_crt,wrapping_key)
    def pin(cert):
        der=subprocess.run(["openssl","x509","-in",str(cert),"-outform","DER"],
                           check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                           timeout=10).stdout
        return hashlib.sha256(der).hexdigest().upper()

    def identity(label,signing=False):
        directory=state/label
        directory.mkdir(mode=0o700)
        cert,key=directory/"leaf.pem",directory/"leaf.key"
        algorithm=(["-newkey","ec","-pkeyopt","ec_paramgen_curve:prime256v1"]
                   if signing else ["-newkey","rsa:3072"])
        checked(["openssl","req","-x509","-nodes",*algorithm,"-days","2",
                 "-subj","/CN="+label,"-addext","basicConstraints=critical,CA:FALSE",
                 "-addext","keyUsage=critical,"+
                 ("digitalSignature" if signing else "keyEncipherment"),
                 "-keyout",str(key),"-out",str(cert)])
        cert.chmod(0o600);key.chmod(0o600)
        return cert,key,pin(cert)

    signer=identity("delivery-signer",signing=True)
    recipients={node:identity("delivery-"+node) for node in ("node-a","node-b")}
    tool=Path(__file__).resolve().parents[2]/"ops"/"fleet"/"linux_dp_wrap_delivery.py"
    if not tool.is_file():
        raise RuntimeError("required wrapping-key delivery implementation missing")
    wrapping_pin=pin(wrapping_crt)
    transport=state/"sealed";transport.mkdir(mode=0o700)

    def invoke_delivery(command,arguments,expected):
        result=subprocess.run([sys.executable,str(tool),command,*arguments],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
            timeout=90,check=False)
        if result.returncode!=expected:
            raise RuntimeError("unexpected actual credential delivery outcome "+command)

    def receive(node,identity,revision=1):
        cert,key,recipient_pin=identity
        common=["--fleet",FLEET,"--recipient",node,"--revision",str(revision),
                "--signer-certificate",str(signer[0]),"--signer-sha256",signer[2],
                "--recipient-certificate",str(cert),"--recipient-sha256",recipient_pin,
                "--wrapping-sha256",wrapping_pin]
        invoke_delivery("seal",common+["--signer-key",str(signer[1]),
            "--pfx",source_pfx,"--password-file",source_password,
            "--output-root",str(transport)],0)
        envelope=transport/(FLEET+"--"+node+"--"+str(revision))/"envelope.der"
        destination=state/("received-"+node);destination.mkdir(mode=0o700)
        # Test the other node's private key before accepting the envelope.
        other=recipients["node-b" if node=="node-a" else "node-a"]
        common_open=common+["--envelope",str(envelope),"--output-root",str(destination)]
        invoke_delivery("open",common_open+["--recipient-key",str(other[1])],1)
        if list(destination.iterdir()):
            raise RuntimeError("wrong recipient published a wrapping credential")
        invoke_delivery("open",common_open+["--recipient-key",str(key)],0)
        target=destination/(FLEET+"--"+node+"--"+str(revision))
        invoke_delivery("open",common_open+["--recipient-key",str(key)],1)
        if len(list(destination.iterdir()))!=1:
            raise RuntimeError("credential delivery replay changed received inventory")
        pfx,password=target/"wrapper.pfx",target/"wrapper.password"
        if any(path.stat().st_mode&0o777!=0o600 for path in (pfx,password)):
            raise RuntimeError("received credential is not owner-private")
        return str(pfx),str(password)

    wrap_a=receive("node-a",recipients["node-a"])
    wrap_b=receive("node-b",recipients["node-b"])
    # Remove source export before starting either product runtime. The CI
    # account is still shared; this is not OS-user or physical-host isolation.
    Path(source_pfx).unlink();Path(source_password).unlink();wrapping_key.unlink()
    print("PASS: actual recipient-bound credential delivery, cross-recipient and replay denial",flush=True)
    client_a = (*pfx_for("tls-a", *ids["writer"][:2]), ids["writer"][2])
    client_b = (*pfx_for("tls-b", *ids["reader"][:2]), ids["reader"][2])
    Path(ca).chmod(0o600)
    writer_cert, writer_key = ids["writer"][:2]

    def rpc(resource, payload):
        return post(addr,(resource,payload),ca,writer_cert,writer_key)

    def issue(node):
        # Use actual Raft CREATE CAS and independently read the result.
        # No reliance on the app under test to grant its own authority.
        grant=rpc("/v3/lease/grant",{"TTL":"120"})
        lease=int(grant["ID"])
        if lease<=0 or int(grant["TTL"])!=120:
            raise RuntimeError("invalid fixture writer lease")
        record=json.dumps({"schemaVersion":1,"kind":"linux-dp",
            "senderNodeId":node,"receiverNodeId":
            "node-b" if node=="node-a" else "node-a",
            "revision":1,"checkpointSha256":"A"*64,
            "holder":secrets.token_hex(16)},separators=(",",":"))
        txn=rpc("/v3/kv/txn",{"compare":[{"result":"EQUAL","target":"CREATE",
            "key":b64(WRITER),"createRevision":"0"}],
            "success":[{"requestPut":{"key":b64(WRITER),
            "value":b64(record),"lease":str(lease)}}],"failure":[]})
        if txn.get("succeeded") is not True:
            raise RuntimeError("fixture writer epoch contested")
        current=rpc("/v3/kv/range",{"key":b64(WRITER),"serializable":False})
        kv=current["kvs"][0]
        if int(kv["lease"])!=lease:
            raise RuntimeError("fixture epoch mismatch")
        raw=base64.b64decode(kv["value"],validate=True)
        if raw!=record.encode("ascii"):
            raise RuntimeError("fixture epoch record mismatch")
        return lease,int(kv["mod_revision"]),hashlib.sha256(raw).hexdigest().upper()

    def configuration(label,node,mode,client,epoch=None):
        path=provision/(label+".json")
        document={"Fleet":FLEET,"NodeId":node,"ClusterId":str(cluster),
            "MinimumRaftRevision":1,"Members":[{"Url":item["url"],
            "LeafSha256":item["leafSha256"],"MemberId":str(item["memberId"])}
            for item in endpoints],"Mode":mode,"WriterNode":node if epoch else None,
            "LeaseId":epoch[0] if epoch else None,
            "WriterModRevision":epoch[1] if epoch else None,
            "CaPath":ca,"ClientPfxPath":client[0],"ClientPasswordPath":client[1],
            "ClientLeafSha256":client[2],
            "WriterRecordSha256":epoch[2] if epoch else None}
        return private_file(path,json.dumps(document,separators=(",",":")))

    def execute(node,config,wrapping,operation,expected=0,cookie=None):
        directory=state/node
        directory.mkdir(mode=0o700,exist_ok=True)
        env={k:v for k,v in os.environ.items() if not k.startswith("YARP_")}
        env.update(YARP_CONTROL_PLANE_DIR=str(directory),
                   YARP_LINUX_DP_DISTRIBUTED_RING_CONFIG=config,
                   YARP_LINUX_DP_CERT_PFX_PATH=wrapping[0],
                   YARP_LINUX_DP_CERT_PASSWORD_FILE=wrapping[1])
        result=subprocess.run(["dotnet",str(dll),"--distributed-real",operation],
            env=env,input=(cookie+"\n") if cookie else "",text=True,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=45,check=False)
        if result.returncode!=expected:
            raise RuntimeError("unexpected real DP child outcome "+operation+
                               " expected="+str(expected)+" actual="+str(result.returncode))
        ring=directory/"data-protection-keys"
        if ring.exists() and list(ring.iterdir()):
            raise RuntimeError("distributed runtime wrote fallback local key files")
        return result.stdout.strip()

    def inventory():
        doc=rpc("/v3/kv/range",{"key":b64(PREFIX),
                "range_end":b64(PREFIX[:-1]+"0"),"serializable":False})
        return {item["key"]:item["value"] for item in doc.get("kvs",[])}

    epoch_a=issue("node-a")
    writer_a=configuration("writer-a","node-a","writer",client_a,epoch_a)
    reader_b=configuration("reader-b","node-b","reader",client_b)
    wrong_epoch=configuration("wrong-record","node-a","writer",client_a,
                              (epoch_a[0],epoch_a[1],"0"*64))
    execute("a",wrong_epoch,wrap_a,"rotate",expected=5)
    if inventory():
        raise RuntimeError("mismatched authority record published a key")
    wrong_client=configuration("wrong-client","node-a","writer",
                               (client_a[0],client_a[1],client_b[2]),epoch_a)
    execute("a",wrong_client,wrap_a,"rotate",expected=4)
    execute("a",writer_a,wrap_a,"rotate")
    original=inventory()
    if len(original)!=1:
        raise RuntimeError("actual Data Protection did not publish exactly one key")
    for encoded in original.values():
        xml=base64.b64decode(encoded,validate=True)
        if b"encryptedSecret" not in xml or b"masterKey" in xml:
            raise RuntimeError("actual distributed Data Protection key not encrypted")
    old=execute("a",writer_a,wrap_a,"mint")
    if not old:
        raise RuntimeError("actual distributed Data Protection cookie missing")
    execute("b",reader_b,wrap_b,"verify",cookie=old)
    execute("b",reader_b,wrap_b,"rotate",expected=5)
    rpc("/v3/lease/revoke",{"ID":str(epoch_a[0])})
    execute("a",writer_a,wrap_a,"rotate",expected=5)
    if inventory()!=original:
        raise RuntimeError("revoked writer or reader altered encrypted ring")

    # Independently authorize a new epoch. Keep old config to prove stale
    # authority cannot be reused after a role change.
    epoch_b=issue("node-b")
    # Use the independently approved writer TLS leaf for this new writer.
    # Its production RBAC reassignment is NOT exercised by this fixture.
    writer_b=configuration("writer-b","node-b","writer",client_a,epoch_b)
    reader_a=configuration("reader-a","node-a","reader",client_b)
    execute("a",writer_a,wrap_a,"rotate",expected=5)
    time.sleep(1.1)
    execute("b",writer_b,wrap_b,"rotate")
    rotated=inventory()
    if len(rotated)!=2 or any(rotated.get(k)!=v for k,v in original.items()):
        raise RuntimeError("new epoch failed append-only rotation")
    new=execute("b",writer_b,wrap_b,"mint")
    def key_id(token):
        return base64.urlsafe_b64decode(token+"="*((-len(token))%4))[4:20]
    if key_id(new)==key_id(old):
        raise RuntimeError("new distributed cookie did not use rotated key")
    for cookie in (old,new):
        execute("a",reader_a,wrap_a,"verify",cookie=cookie)
        execute("b",writer_b,wrap_b,"verify",cookie=cookie)
    print("PASS: real .NET + three-member mTLS Raft encrypted key storage, "
          "cookie continuity, revoked/stale writer denial and epoch rollover",flush=True)

    def partition():
        # Caller stops two real etcd members before invoking this closure.
        # A fresh runtime must fail at startup rather than fall back to XML.
        execute("a",reader_a,wrap_a,"verify",expected=4,cookie=old)
        execute("b",writer_b,wrap_b,"rotate",expected=4)
        print("PASS: real .NET distributed reader and writer deny minority startup",flush=True)
    return partition
