"""Independent P-256 fleet TLS grant signer; never run with customer web credentials."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

def hex_value(value, length=64):
    return isinstance(value,str) and re.fullmatch("[A-F0-9]{%d}" % length,value) is not None

def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name.casefold() in (key.casefold() for key in result):
            raise ValueError("duplicate or aliased plan property")
        result[name] = value
    return result

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",",":"), ensure_ascii=True).encode("ascii")

def signature_bytes(der):
    # P-256 ECDSA DER -> fixed 64-byte IEEE P1363 signature used by .NET.
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der)-2:
        raise ValueError("unexpected P-256 signature envelope")
    offset=2
    values=[]
    for _ in range(2):
        if offset+2 > len(der) or der[offset] != 2:
            raise ValueError("invalid ECDSA integer")
        size=der[offset+1]
        offset+=2
        raw=der[offset:offset+size]
        offset+=size
        if not raw or len(raw)!=size or raw[0]&128:
            raise ValueError("invalid ECDSA integer")
        value=int.from_bytes(raw,"big")
        if not 0 < value < 2**256:
            raise ValueError("signature is not P-256")
        values.append(value.to_bytes(32,"big"))
    if offset!=len(der):
        raise ValueError("trailing signature data")
    return b"".join(values)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--plan",required=True)
    p.add_argument("--key",required=True)
    p.add_argument("--purpose",choices=["activate","activated","rolled-back"],required=True)
    p.add_argument("--evidence",default="")
    args=p.parse_args()
    key=Path(args.key)
    info=key.lstat()
    if not key.is_absolute() or not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_mode&0o077:
        raise ValueError("independent private signer file required")
    with open(args.plan,"rb") as f:
        raw=f.read(16385)
    if len(raw)>16384:
        raise ValueError("oversized plan")
    plan=json.loads(raw, object_pairs_hook=unique_object)
    if type(plan) is not dict or set(plan)!={"scope","installation","activeDigest","candidateDigest","peerEvidenceSha256","nonce","transactionId","epoch"}:
        raise ValueError("exact plan schema required")
    fields=["scope","installation","activeDigest","candidateDigest","peerEvidenceSha256"]
    if not all(hex_value(plan[x]) for x in fields) or not hex_value(plan["nonce"],32) or plan["activeDigest"]==plan["candidateDigest"] or type(plan["epoch"]) is not int or not 1<=plan["epoch"]<=2**63-1:
        raise ValueError("invalid plan")
    tx="rollout_"+hashlib.sha256("\n".join(["gatewaycore-fleet-tls-plan-v1"]+[plan[x] for x in fields]+[plan["nonce"]]).encode()).hexdigest().upper()[:24]
    if tx!=plan["transactionId"] or (args.evidence!="" if args.purpose=="activate" else not hex_value(args.evidence)):
        raise ValueError("transaction or independent completion evidence mismatch")
    public=subprocess.run(["openssl","pkey","-in",str(key),"-pubout","-outform","DER"],check=True,capture_output=True,timeout=10).stdout
    key_id=hashlib.sha256(public).hexdigest().upper()[:32]
    payload={"Purpose":"gatewaycore-fleet-tls-v1:"+args.purpose,"Scope":plan["scope"],"Installation":plan["installation"],"Nonce":plan["nonce"],"ActiveDigest":plan["activeDigest"],"CandidateDigest":plan["candidateDigest"],"PeerEvidenceSha256":plan["peerEvidenceSha256"],"EvidenceSha256":args.evidence}
    expiry=int(time.time())+240
    digest=hashlib.sha256(canonical(payload)).hexdigest().upper()
    message="\n".join(["yarp-control-fleet-v2",key_id,str(plan["epoch"]),tx,plan["activeDigest"],str(expiry),digest]).encode()
    der=subprocess.run(["openssl","dgst","-sha256","-sign",str(key)],input=message,check=True,capture_output=True,timeout=10).stdout
    print(json.dumps({"purpose":args.purpose,"evidenceSha256":args.evidence,"keyId":key_id,"sequence":plan["epoch"],"expiresUnixSeconds":expiry,"signature":base64.b64encode(signature_bytes(der)).decode("ascii")},separators=(",",":")))

if __name__=="__main__":
    main()
