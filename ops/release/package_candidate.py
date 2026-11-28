"""Pack self-contained application payload, verify archived hashes and source SHA."""
import argparse
import hashlib
from pathlib import Path
import re
import tarfile
import zipfile

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream,"sha256").hexdigest()

def package(root,rid,sha,out):
    if rid not in ("win-x64","linux-x64") or not re.fullmatch(r"[0-9a-f]{40}",sha):
        raise ValueError("invalid frozen candidate identity")
    if (root/"SOURCE_COMMIT.txt").read_text().strip()!=sha:
        raise ValueError("candidate source mismatch")
    exe="GatewayCoreYarp.exe" if rid=="win-x64" else "GatewayCoreYarp"
    if not (root/"app"/exe).is_file() or not (root/"app"/"GatewayCoreYarp.dll").is_file():
        raise ValueError("shipping apphost or assembly missing")
    files={}
    for path in root.rglob("*"):
        if path.is_symlink(): raise ValueError("symlink in release payload")
        if not path.is_file(): continue
        name=path.relative_to(root).as_posix()
        if (path.suffix.lower() in (".pfx",".p12",".pem",".key",".kdbx") or
            path.name.lower() in ("appsettings.json","admin-users.json","admin-audit.jsonl") or
            any(part in ("data-protection-keys","secrets","obj") for part in path.relative_to(root).parts)):
            raise ValueError("private/config state in candidate payload: "+name)
        files[name]=sha256(path)
    out.mkdir(parents=True,exist_ok=True)
    name="GatewayCore-candidate-"+sha[:12]+"-"+rid
    target=out/(name+(".zip" if rid=="win-x64" else ".tar.gz"))
    if target.exists(): raise ValueError("candidate archive already exists")
    if rid=="win-x64":
        with zipfile.ZipFile(target,"x",compression=zipfile.ZIP_DEFLATED) as archive:
            for member in sorted(files): archive.write(root/member,member)
        with zipfile.ZipFile(target) as archive:
            names=archive.namelist()
            if len(names)!=len(files) or set(names)!=set(files): raise ValueError("archive inventory mismatch")
            for member,expected in files.items():
                with archive.open(member) as stream:
                    if hashlib.file_digest(stream,"sha256").hexdigest()!=expected:
                        raise ValueError("archive payload hash mismatch")
    else:
        with tarfile.open(target,"x:gz") as archive:
            for member in sorted(files): archive.add(root/member,arcname=member,recursive=False)
        with tarfile.open(target,"r:gz") as archive:
            members=archive.getmembers()
            if len(members)!=len(files) or {m.name for m in members}!=set(files):
                raise ValueError("archive inventory mismatch")
            for m in members:
                if not m.isfile(): raise ValueError("archive contains nonregular file")
                with archive.extractfile(m) as stream:
                    if hashlib.file_digest(stream,"sha256").hexdigest()!=files[m.name]:
                        raise ValueError("archive payload hash mismatch")
    digest=sha256(target)
    (out/"SHA256SUMS.txt").write_text(digest+"  "+target.name+"\n",encoding="ascii")
    print("Candidate archive SHA256:",digest,target.name)
    print("PASS: exact candidate archive inventory and per-file SHA256 verified")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--root",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    p.add_argument("--sha",required=True);p.add_argument("--rid",required=True)
    a=p.parse_args()
    package(a.root,a.rid,a.sha,a.out)
