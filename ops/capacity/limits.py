#!/usr/bin/env python3
"""Derive strict Kestrel and systemd limits from measured concurrency, never guesses."""
import argparse,json,math,sys
from pathlib import Path
from contract import validate
p=argparse.ArgumentParser()
for flag in ("scenario","profile","out"):p.add_argument("--"+flag,required=True,type=Path)
a=p.parse_args();errors=[]
try:
    s=json.loads(a.scenario.read_text());validate(s)
    profile=json.loads(a.profile.read_text())
    min_connections=math.ceil(1.5*s["peak_concurrent_connections"])
    actual=profile["kestrel_max_concurrent_connections"];limit=profile["limit_nofile"]
    if type(actual) is not int or actual<min_connections:errors.append("KESTREL_TOO_LOW")
    if type(limit) is not int or limit<math.ceil(2.5*actual+4096):errors.append("LIMIT_NOFILE_TOO_LOW")
except (OSError,ValueError,KeyError,TypeError) as e:
    errors.append("REQUIRED_INPUT "+str(e));min_connections=None
result={"decision":"NO-GO" if errors else "GO","min_kestrel":min_connections,
        "min_nofile_for_min_kestrel":math.ceil(2.5*min_connections+4096) if min_connections else None,
        "errors":errors}
a.out.parent.mkdir(parents=True,exist_ok=True);a.out.write_text(json.dumps(result,indent=2))
print(json.dumps(result));sys.exit(bool(errors))
