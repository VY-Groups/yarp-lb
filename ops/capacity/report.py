#!/usr/bin/env python3
"""Strict >1h mixed-size RPS + body-Gbps gate, zero errors, real per-node telemetry."""
import argparse,csv,datetime as dt,json,math,re,sys
from pathlib import Path
from contract import validate
p=argparse.ArgumentParser()
p.add_argument("--scenario",type=Path,required=True);p.add_argument("--results",type=Path,required=True)
p.add_argument("--gateway-csv",required=True,type=Path);p.add_argument("--out",required=True,type=Path)
args=p.parse_args()
s=json.loads(args.scenario.read_text());errors=[]
try: target=validate(s)
except (KeyError,ValueError,TypeError) as e:
    target={"rps":float("inf"),"gbps":float("inf")};errors.append(str(e))
def stamp(x):
    t=dt.datetime.fromisoformat(x.replace("Z","+00:00"))
    if t.tzinfo is None:raise ValueError("timestamp without timezone")
    return t.timestamp()
def num(x):
    if type(x) not in (int,float) or not math.isfinite(x):raise ValueError("missing/nonfinite real metric")
    return x
all_hosts={};window_rows=[];start=None;end=None
for host in s.get("hosts",[]):
    try:
        folder=args.results/host;m=json.loads((folder/"manifest.json").read_text())
        if m["host_id"]!=host or m["engine"]!="oha" or m["scenario"]!=s:raise ValueError("raw evidence identity/scenario mismatch")
        if len(m["windows"])!=s["windows"]:raise ValueError("missing mandatory windows")
        rows=[];previous_end=None
        for i,w in enumerate(m["windows"]):
            if w["index"]!=i or w["returncode"]!=0 or w["artifact"]!=f"window-{i:03d}.json":raise ValueError("window index/exit mismatch")
            first,last=stamp(w["start_utc"]),stamp(w["end_utc"])
            if last<=first or num(w["wall_seconds"]) < s["window_seconds"]-.5 or abs((last-first)-w["wall_seconds"])>1:
                raise ValueError("invalid window wall duration")
            if previous_end is not None and (first<previous_end-.5 or first-previous_end>5):
                raise ValueError("overlapping/shortened/gapped window")
            previous_end=last
            raw=json.loads((folder/w["artifact"]).read_text());summary=raw["summary"]
            duration=num(summary["total"]);rps=num(summary["requestsPerSec"])
            body=num(summary["totalData"]);pct=raw["latencyPercentiles"]
            p99=num(pct["p99"])*1000;p95=num(pct["p95"])*1000;p50=num(pct["p50"])*1000
            if not(0<=p50<=p95<=p99):raise ValueError("invalid latency ordering")
            codes=raw["statusCodeDistribution"];faults=raw["errorDistribution"]
            if not codes:raise ValueError("missing status distribution")
            count=0;bad=0
            for status,qty in codes.items():
                if not status.isdigit() or type(qty) is not int or qty<0:raise ValueError("invalid HTTP evidence")
                count+=qty
                if int(status) not in s["allowed_status"]:bad+=qty
            for error,qty in faults.items():
                if type(qty) is not int or qty<0:raise ValueError("invalid transport count")
                bad+=qty
            if not count or num(summary["successRate"])!=1 or bad:errors.append(f"{host} window {i}: {bad} HTTP/transport errors or successRate != 1")
            if p99>=s["max_p99_ms"]:errors.append(f"{host} window {i}: p99>=unchanged cap")
            if abs(count/duration-rps)>max(1,rps*.01):errors.append(f"{host} window {i}: count/rps inconsistent")
            mix=raw.get("perProfile")
            if not isinstance(mix,list) or len(mix)!=len(s["response_mix"]):raise ValueError("missing mixed raw subprofiles")
            by={x["name"]:x for x in mix}
            if len(by)!=len(mix) or set(by)!={x["name"] for x in s["response_mix"]}:
                raise ValueError("response_mix identities mismatch")
            if sum(x["count"] for x in mix)!=count or sum(x["body_bytes"] for x in mix)!=body:
                raise ValueError("mixed body/count totals mismatch")
            for configured in s["response_mix"]:
                got=by[configured["name"]]
                if got["url"]!=configured["url"] or got["count"]<=0 or got["body_bytes"]!=got["count"]*configured["response_bytes"]:
                    raise ValueError("response_mix exact path/size evidence invalid")
                if abs(got["count"]/count-configured["weight"])>.035:raise ValueError("response_mix weights differ >3.5pp")
            rows.append({"start":first,"end":last,"rps":rps,"body_gbps":body*8/(duration*1e9),"p99_ms":p99,"errors":bad})
        all_hosts[host]=rows
    except (OSError,KeyError,ValueError,TypeError,ZeroDivisionError) as e:errors.append(f"{host}: missing/unusable generator evidence {e}")
if len(all_hosts)==len(s.get("hosts",[])) and all_hosts:
    start=max(x[0]["start"] for x in all_hosts.values());end=min(x[-1]["end"] for x in all_hosts.values())
    if end-start<3600:errors.append("less than 3600s common wall-time coverage")
    for i in range(s["windows"]):
        windows=[all_hosts[h][i] for h in s["hosts"]]
        if max(x["start"] for x in windows)-min(x["start"] for x in windows)>5:
            errors.append(f"window {i} generator starts differ >5s")
        rps=sum(x["rps"] for x in windows);gbps=sum(x["body_gbps"] for x in windows)
        if rps<target["rps"]:errors.append(f"window {i}: RPS {rps} < {target['rps']}")
        if gbps<target["gbps"]:errors.append(f"window {i}: BODY_GBPS {gbps} < {target['gbps']}")
        window_rows.append({"index":i,"rps":rps,"body_gbps":gbps,"p99_ms":max(x["p99_ms"] for x in windows),
                            "errors":sum(x["errors"] for x in windows)})
else:errors.append("generator evidence incomplete")
telemetry=None
try:
    rows=list(csv.DictReader(args.gateway_csv.open(newline="")))
    if len(rows)<60:raise ValueError("less than 60 genuine host samples")
    node=s["isolated_gateway"]
    if any(x["gateway_node"]!=node for x in rows):raise ValueError("wrong embedded gateway identity")
    if len({(x["process_id"],x["process_start_utc"]) for x in rows})!=1:raise ValueError("process restarted")
    if any("yarp_control_gc_collections_total" not in x["gc_prometheus_raw"] or "yarp_control_gc_heap_bytes" not in x["gc_prometheus_raw"] for x in rows):
        raise ValueError("missing real GC heap/Gen2 metrics")
    times=[stamp(x["timestamp_utc"]) for x in rows]
    if start and (times[0]>start+10 or times[-1]<end-10):raise ValueError("missing telemetry time coverage")
    if any(b-a<=0 or b-a>15 for a,b in zip(times,times[1:])):raise ValueError("telemetry out of order/gaps")
    for key in ("rx_dropped","tx_dropped","process_cpu_seconds"):
        values=[float(x[key]) for x in rows]
        if any(not math.isfinite(x) or x<0 for x in values):raise ValueError("invalid "+key)
        if values[-1]>values[0] and key in ("rx_dropped","tx_dropped"):
            errors.append(f"NIC drops increased: {key}")
    for key in ("rss_bytes","threads"):
        if any(float(x[key])<=0 for x in rows):raise ValueError("missing "+key)
    for metric in ("yarp_logging_dropped_total","yarp_logging_dropped_high_priority_total","yarp_logging_write_errors_total"):
        values=[]
        for row in rows:
            matches=re.findall(r"^"+re.escape(metric)+r" ([0-9.]+)$",row["logs_prometheus_raw"],re.M)
            if len(matches)!=1:raise ValueError("missing/duplicate real metric "+metric)
            values.append(float(matches[0]))
        if any(b<a for a,b in zip(values,values[1:])) or values[-1]!=values[0]:
            errors.append("log drops/writer errors changed: "+metric)
    telemetry={"node":node,"samples":len(rows),"file":str(args.gateway_csv)}
except (OSError,ValueError,KeyError,TypeError,IndexError) as e:errors.append("unusable gateway telemetry: "+str(e))
result={"decision":"NO-GO" if errors else "GO","required_rps":target["rps"],"required_body_gbps":target["gbps"],
        "min_window_rps":min((x["rps"] for x in window_rows),default=None),
        "min_window_body_gbps":min((x["body_gbps"] for x in window_rows),default=None),
        "overlapping_seconds":end-start if start is not None else None,"window_results":window_rows,
        "gateway_telemetry":telemetry,"error_reasons":errors}
args.out.parent.mkdir(parents=True,exist_ok=True)
args.out.write_text(json.dumps(result,indent=2)+"\n")
print(json.dumps({k:v for k,v in result.items() if k!="window_results"},indent=2))
sys.exit(bool(errors))
