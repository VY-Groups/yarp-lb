#!/usr/bin/env python3
"""Reject fabricated, missing, duplicate, or mismatched two-VM measurements."""
import argparse
import json
from pathlib import Path


def check(files, sha, strict):
    if len(files) != 2:
        raise ValueError("exactly two independent runner artifacts required")
    reports = [json.loads(Path(f).read_text()) for f in files]
    if {r.get("site") for r in reports} != {"node-a","node-b"}:
        raise ValueError("site IDs must be node-a and node-b")
    if any(r.get("head_sha") != sha or r.get("status") != "PASS" for r in reports):
        raise ValueError("commit mismatch or a runner failed its assertions")
    hosts = [r.get("runner_hostname") for r in reports]
    if len(set(hosts)) != 2 or not all(hosts):
        raise ValueError("two distinct VM hostnames required")
    if any(bool(r.get("strict")) != strict for r in reports):
        raise ValueError("strict mode mismatch")
    for report in reports:
        windows = report.get("windows", [])
        if not windows or report.get("total_requests", 0) <= 0 or report.get("total_errors") != 0:
            raise ValueError("missing HTTP body evidence or failed requests")
        if strict and (len(windows)!=60 or any(w.get("seconds")!=60 or
                     w.get("body_mbps",0)<report["target_body_mbps"] or
                     w.get("p99_ms",1e9)>=report["p99_limit_ms"] for w in windows)):
            raise ValueError("a complete strict per-minute test did not pass")
    return {"two_distinct_cloud_vms": True,
            "sites": {r["site"]: {"hostname":r["runner_hostname"],
                   "requests":r["total_requests"],
                   "minimum_body_mbps":min(w["body_mbps"] for w in r["windows"])}
                   for r in reports},
            "on_prem_hardware_verified": False,
            "actual_network_failover_verified": False,
            "real_customer_traffic_mix_verified": False,
            "decision": "CLOUD_SYNTHETIC_PASS_NOT_PHYSICAL_GO"}


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--a",type=Path,required=True)
    p.add_argument("--b",type=Path,required=True)
    p.add_argument("--sha",required=True)
    p.add_argument("--strict",action="store_true")
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    summary=check([args.a,args.b],args.sha,args.strict)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(summary,indent=2)+"\n")
    print(json.dumps(summary,indent=2))


if __name__=="__main__":
    main()
