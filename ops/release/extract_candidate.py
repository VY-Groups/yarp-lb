"""Verify and extract an internally generated candidate archive into a new directory."""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

def extract(directory,out):
    parts=(directory/"SHA256SUMS.txt").read_text(encoding="ascii").split()
    if len(parts)!=2 or Path(parts[1]).name!=parts[1] or "\\" in parts[1]:
        raise ValueError("invalid candidate checksum manifest")
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

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--archive-dir",type=Path,required=True);p.add_argument("--out",type=Path,required=True)
    a=p.parse_args();extract(a.archive_dir,a.out)
