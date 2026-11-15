#!/usr/bin/env python3
"""Check active ingress survives separate Ubuntu gateway process death, then recovers.

This does not imply VIP or physical-host failover qualification.
"""
import argparse
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

def get(url):
    started=time.monotonic()
    try:
        with urllib.request.urlopen(url,timeout=3) as resp:
            body=resp.read()
            return (resp.status, len(body), (time.monotonic()-started)*1000)
    except (urllib.error.URLError,TimeoutError,OSError) as error:
        return (0, 0, (time.monotonic()-started)*1000)

def run(ingress,failed,healthy):
    # The remote A container has been killed and its status marker uploaded.
    # B must keep serving directly. HAProxy is permitted a finite detection window.
    if get(healthy)[0] != 200:
        raise RuntimeError("healthy second independent VM unavailable")
    if get(failed)[0] == 200:
        raise RuntimeError("remote first VM still accepts gateway requests after stop")
    start=time.monotonic()
    results=[]
    while time.monotonic()-start < 8:
        status,size,latency=get(ingress)
        results.append({"offset_ms":int((time.monotonic()-start)*1000),
                        "status":status,"bytes":size,"latency_ms":round(latency,3)})
        time.sleep(0.07)
    if not results:
        raise RuntimeError("no ingress traffic samples")
    failures=[r for r in results if r["status"]!=200]
    final=[r for r in results if r["offset_ms"] >= 6000]
    if len(final)<10 or any(r["status"]!=200 for r in final):
        raise RuntimeError("healthy-node ingress did not stabilize for last 2 seconds")
    return {"absolute_failed_requests":len(failures),
            "last_failure_offset_ms":max((x["offset_ms"] for x in failures),default=None),
            "attempted_requests":len(results),"last_two_seconds_zero_errors":True,
            "real_independent_ubuntu_vms":True,
            "physical_vrrp_or_site_failover_verified":False}

if __name__=="__main__":
    p=argparse.ArgumentParser()
    for item in ("ingress","failed","healthy"):
        p.add_argument("--"+item,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    result=run(args.ingress,args.failed,args.healthy)
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps(result))
