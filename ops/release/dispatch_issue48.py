"""Dispatch only missing CI workflows for the frozen main revision.
No deployment, tag creation, production release or retry of failed jobs.
"""
import argparse
import json
import os
from pathlib import Path
import re
import time
import urllib.request
from assess_issue48 import audit, fetch

def api(repo,token,path,body=None):
    request=urllib.request.Request("https://api.github.com/repos/"+repo+path,
        headers={"Authorization":"Bearer "+token,"Accept":"application/vnd.github+json",
                 "Content-Type":"application/json","User-Agent":"gatewaycore-frozen-dispatch"},
        data=None if body is None else json.dumps(body).encode("ascii"))
    with urllib.request.urlopen(request,timeout=20) as response:
        return json.load(response) if body is None else response.status

def run(repo,sha,token,out,deadline_seconds=2400):
    if not re.fullmatch(r"[\w.-]+/[\w.-]+",repo,re.ASCII) or not re.fullmatch(r"[0-9a-f]{40}",sha):
        raise ValueError("invalid frozen dispatch identity")
    def check_main():
        if api(repo,token,"/branches/main")["commit"]["sha"]!=sha:
            raise RuntimeError("main changed; frozen candidate must be restarted")
    check_main()
    result=audit(fetch(repo,sha,token),sha,repo)
    if result["ci_candidate"]=="NO-GO":
        raise RuntimeError("failed existing evidence; reconcile rather than automatically rerun")
    for filename,item in result["dp_checks"].items():
        if item["status"]!="MISSING": continue
        # CodeQL starts automatically on every main push; allow it to appear.
        if filename=="codeql.yml": continue
        check_main()
        if api(repo,token,"/actions/workflows/"+filename+"/dispatches",{"ref":"main"})!=204:
            raise RuntimeError("required workflow dispatch rejected")
        print("Dispatched:",filename,flush=True)
    deadline=time.monotonic()+deadline_seconds
    while True:
        check_main()
        result=audit(fetch(repo,sha,token),sha,repo)
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
        if result["ci_candidate"]=="CI-GO":return
        if result["ci_candidate"]=="NO-GO" or time.monotonic()>=deadline:
            raise RuntimeError("required frozen-main CI failed or incomplete")
        time.sleep(20)

if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--repo",required=True);p.add_argument("--sha",required=True)
    p.add_argument("--out",type=Path,required=True)
    a=p.parse_args()
    run(a.repo,a.sha,os.environ["GITHUB_TOKEN"],a.out)
