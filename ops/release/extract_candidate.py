"""Verify and extract an internally generated candidate archive into a new directory."""
import argparse
import hashlib
import re
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

def extract(directory,out,sha=None,rid=None):
    if (sha is None)!=(rid is None) or (sha is not None and
            (not re.fullmatch(r"[0-9a-f]{40}",sha) or rid not in ("win-x64","linux-x64"))):
        raise ValueError("invalid expected candidate identity")
    parts=(directory/"SHA256SUMS.txt").read_text(encoding="ascii").split()
    if len(parts)!=2 or Path(parts[1]).name!=parts[1] or "\\" in parts[1]:
        raise ValueError("invalid candidate checksum manifest")
    if not re.fullmatch(r"[0-9a-f]{64}",parts[0]):
        raise ValueError("invalid candidate SHA256")
    if sha is not None:
        expected_name="GatewayCore-candidate-"+sha[:12]+"-"+rid+(".zip" if rid=="win-x64" else ".tar.gz")
        if parts[1]!=expected_name:
            raise ValueError("candidate archive identity mismatch")
    archive=directory/parts[1]
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream,"sha256").hexdigest()!=parts[0]:
            raise ValueError("candidate archive digest mismatch")
    out.mkdir(exist_ok=False)
    def validate(names):
        if len(names)!=len(set(names)):
            raise ValueError("duplicate archive members")
        for name in names:
            path=PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or ":" in name:
                raise ValueError("unsafe archive member")
    if archive.suffix==".zip":
        with zipfile.ZipFile(archive) as z:
            validate(z.namelist())
            z.extractall(out)
    else:
        with tarfile.open(archive,"r:gz") as t:
            members=t.getmembers()
            validate([m.name for m in members])
            if any(not m.isfile() for m in members): raise ValueError("nonregular archive member")
            t.extractall(out,filter="data")
    if not (out/"app"/"GatewayCoreYarp.dll").is_file():
        raise ValueError("extracted executable assembly missing")
    if sha is not None:
        exe="GatewayCoreYarp.exe" if rid=="win-x64" else "GatewayCoreYarp"
        if (not (out/"app"/exe).is_file() or
                not (out/"SOURCE_COMMIT.txt").is_file() or
                (out/"SOURCE_COMMIT.txt").read_text().strip()!=sha):
            raise ValueError("extracted candidate identity mismatch")
        from stage_candidate_handoff import handoff_paths
        if any(not (out/name).is_file() for name in handoff_paths(rid)):
            raise ValueError("extracted candidate handoff incomplete")
        print("PASS: extracted exact candidate source, platform apphost and offline handoff verified")

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--archive-dir",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    p.add_argument("--sha");p.add_argument("--rid",choices=("win-x64","linux-x64"))
    a=p.parse_args();extract(a.archive_dir,a.out,a.sha,a.rid)
