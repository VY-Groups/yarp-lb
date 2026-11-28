#!/usr/bin/env python3
"""Frozen-main #48 evidence gate. Does not close issues or authorize deployment."""
import argparse
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

from assess_ci import REQUIRED, evaluate

# Match both the committed workflow file and display name. Never substitute
# an old successful PR, similarly named workflow, or skipped check.
BASELINE_PATHS = (
    "capacity-oha-smoke.yml", "onprem-promtool.yml", "workflow-lint.yml",
    "onprem-ops-contract.yml", "docker-0.1-ca.yml", "capacity-contract.yml",
    "docker-0.1-redis.yml", "docker-0.1-integration.yml", "issue24-allocations.yml",
    "control-center-ci.yml", "eod-750mbps-ci-canary.yml", "l7-acceptance.yml",
    "gslb-acceptance.yml", "l4-acceptance.yml", "listener-isolation.yml",
    "windows-ha-10x.yml",
)
BASELINE_REQUIRED = dict(zip(BASELINE_PATHS, REQUIRED, strict=True))
DP_REQUIRED = {
    "windows-scm-acceptance.yml": "Windows SCM Data Protection restart acceptance",
    "windows-fleet-dp.yml": "Windows Data Protection shared fleet certificate acceptance",
    "windows-dpapi-fleet-migration.yml": "Real Windows DPAPI to fleet certificate migration",
    "rhel-ubi9-dp-compat.yml": "RHEL-family UBI9 .NET 10 Data Protection compatibility",
    "linux-dp-fleet-rolling-dr.yml": "Linux Data Protection two-node rolling certificate and lost-key DR",
    "linux-dp-mtls-transfer.yml": "Offline Linux DP pinned mTLS transfer acceptance",
    "linux-dp-quiescence.yml": "Signed Linux DP dual-node writer quiescence acceptance",
    "linux-dp-quorum-authority.yml": "Linux DP independent recovery quorum contracts",
    "linux-dp-wrap-delivery.yml": "Linux DP node-bound wrapping-key delivery",
    "waf-etcd-quorum.yml": "Live three-member etcd quorum fencing CI",
    "security-acceptance.yml": "Security acceptance - mail providers and administrator workflows",
    "e2e-real-control-center.yml": "Real Control Center E2E - browser and API",
    "audit-collector-ci.yml": "Independent audit collector HTTPS acceptance",
    "test-server-install-smoke.yml": "GatewayCore test-server installer smoke",
    "codeql.yml": "CodeQL Advanced",
    "adc-vip-fence-provider.yml": "ADC external VIP fencing provider contracts",
    "adc-vip-host-address.yml": "ADC local VIP address and durable journal",
}

def audit(payload, sha, repo):
    if not re.fullmatch(r"[0-9a-f]{40}",sha) or not re.fullmatch(r"[\w.-]+/[\w.-]+",repo,re.ASCII):
        raise ValueError("invalid exact source or repository")
    if not isinstance(payload.get("workflow_runs"),list):
        raise ValueError("missing workflow evidence")
    runs = [r for r in payload["workflow_runs"] if isinstance(r,dict)
        and r.get("head_sha")==sha and r.get("head_branch")=="main"
        and r.get("event") in ("push","workflow_dispatch")
        and isinstance(r.get("head_repository"),dict)
        and r["head_repository"].get("full_name")==repo]
    baseline=evaluate({"workflow_runs":[r for r in runs
        if r.get("name")==BASELINE_REQUIRED.get(str(r.get("path","")).removeprefix(".github/workflows/"))
        and str(r.get("path","")).startswith(".github/workflows/")]},sha)
    latest={}
    for run in runs:
        path=run.get("path","")
        if not isinstance(path,str) or not path.startswith(".github/workflows/"):
            continue
        filename=path.removeprefix(".github/workflows/")
        required=BASELINE_REQUIRED | DP_REQUIRED
        if filename not in required or run.get("name")!=required[filename]:
            continue
        key=(str(run.get("created_at") or ""),int(run.get("run_attempt") or 1),int(run.get("id") or 0))
        if filename not in latest or key>latest[filename][0]:
            latest[filename]=(key,run)
    checks={}
    for filename in (BASELINE_REQUIRED | DP_REQUIRED):
        item=latest.get(filename,(None,{}))[1]
        checks[filename]={"status":item.get("status","MISSING"),"conclusion":item.get("conclusion"),
            "run_id":item.get("id"),"url":item.get("html_url")}
    pending=[n for n,v in checks.items() if v["status"]!="completed" or v["conclusion"]!="success"]
    failed=any(checks[n]["status"]=="completed" for n in pending)
    decision=("NO-GO" if failed or baseline["ci_v01"]=="NO-GO" else
              "PENDING" if pending or baseline["ci_v01"]!="GO" else "CI-GO")
    return {"source_sha":sha,"repository":repo,"ci_candidate":decision,
            "production":"NO-GO","issue_48_closure":"NOT ASSERTED",
            "baseline":baseline,"dp_checks":checks,"dp_incomplete":pending}

def fetch(repo,sha,token):
    runs=[]
    for page in range(1,21):
        url=f"https://api.github.com/repos/{repo}/actions/runs?head_sha={sha}&per_page=100&page={page}"
        request=urllib.request.Request(url,headers={"Authorization":"Bearer "+token,
            "Accept":"application/vnd.github+json","User-Agent":"gatewaycore-frozen-candidate"})
        with urllib.request.urlopen(request,timeout=20) as response:
            data=json.load(response)
        items=data.get("workflow_runs")
        if not isinstance(items,list): raise ValueError("missing GitHub workflow data")
        runs.extend(items)
        if len(items)<100:
            if type(data.get("total_count")) is not int or len(runs)<data["total_count"]:
                raise ValueError("incomplete workflow pagination")
            return {"workflow_runs":runs}
    raise ValueError("workflow evidence pagination exceeded safety bound")

def main():
    p=argparse.ArgumentParser()
    p.add_argument("--repo",required=True);p.add_argument("--sha",required=True)
    p.add_argument("--out",required=True,type=Path)
    args=p.parse_args()
    try:
        if not re.fullmatch(r"[\w.-]+/[\w.-]+",args.repo,re.ASCII) or not re.fullmatch(r"[0-9a-f]{40}",args.sha):
            raise ValueError("invalid candidate arguments")
        token=os.environ.get("GITHUB_TOKEN")
        if not token: raise ValueError("missing Actions read token")
        result=audit(fetch(args.repo,args.sha,token),args.sha,args.repo)
    except (ValueError,TypeError,OSError) as exc:
        result={"source_sha":args.sha,"ci_candidate":"NO-GO","production":"NO-GO",
                "issue_48_closure":"NOT ASSERTED","error":str(exc)}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    print("Frozen candidate CI decision:",result["ci_candidate"])
    return 0 if result["ci_candidate"]=="CI-GO" else 1

if __name__=="__main__":
    sys.exit(main())
