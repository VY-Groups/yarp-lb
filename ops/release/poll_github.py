#!/usr/bin/env python3
"""GitHub Actions-only auditor, fetches raw workflow runs for exact PR head SHA.

The output remains in GitHub Actions artifact storage. It never alters a
production endpoint or issues a deployment. Requires actions:read token.
"""
import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from assess_ci import evaluate

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--repo",required=True)
    p.add_argument("--sha",required=True)
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--deadline-seconds",type=int,default=900)
    args=p.parse_args()
    if args.deadline_seconds < 0 or args.deadline_seconds > 1100:
        p.error("invalid bounded deadline")
    token=os.environ.get("GITHUB_TOKEN")
    if not token:sys.exit("NO-GO: GitHub Actions token unavailable")
    if "/" not in args.repo:sys.exit("NO-GO: repository malformed")
    url=f"https://api.github.com/repos/{args.repo}/actions/runs?head_sha={args.sha}&per_page=100"
    started=time.monotonic()
    while True:
        request=urllib.request.Request(url,headers={
            "Authorization":"Bearer "+token,
            "Accept":"application/vnd.github+json",
            "User-Agent":"yarp-v01-release-evidence"})
        try:
            with urllib.request.urlopen(request,timeout=20) as response:
                raw=response.read()
            payload=json.loads(raw)
            result=evaluate(payload,args.sha)
        except (OSError,ValueError,TypeError) as exc:
            result={"ci_v01":"NO-GO","production":"NO-GO","errors":[str(exc)]}
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps({"ci_v01":result["ci_v01"],
            "production":result["production"],
            "completed_success":result.get("completed_success"),
            "incomplete_count":len(result.get("incomplete_workflows",[]))}),flush=True)
        if result["ci_v01"] == "GO":return 0
        if result["ci_v01"] == "NO-GO":return 1
        if time.monotonic()-started>=args.deadline_seconds:return 1
        time.sleep(15)

if __name__=="__main__":
    sys.exit(main())
