"""Measured scenario validation. Never infer site traffic from a 10GbE link label."""
import math
from urllib.parse import urlsplit
MANDATORY=("peak_gbps","peak_rps","peak_concurrent_connections","new_connections_per_second",
           "https_share","link_gbps","server_specs","response_mix","headroom","max_p99_ms",
           "hosts","gateway_nodes","isolated_gateway","window_seconds","windows","http_version",
           "keepalive","baseline_alpn","baseline_keepalive")
def positive(value,name):
    if type(value) not in (int,float) or not math.isfinite(value) or value<=0:
        raise ValueError("REQUIRED_INPUT "+name+" finite positive required")
    return value
def validate(s):
    for key in MANDATORY:
        if key not in s or s[key] is None:raise ValueError("REQUIRED_INPUT "+key+" missing")
    for key in ("peak_gbps","peak_rps","peak_concurrent_connections","new_connections_per_second",
                "link_gbps","max_p99_ms","window_seconds","windows"):
        positive(s[key],key)
    if s["headroom"] not in (0.3,0.5):raise ValueError("headroom unchanged: exactly .30 or .50")
    if s["peak_gbps"]*(1+s["headroom"])>.90*s["link_gbps"]:
        raise ValueError("INFEASIBLE_LINK: peak_gbps including headroom exceeds 90% of isolated link_gbps")
    specs=s["server_specs"]
    if not isinstance(specs,dict):raise ValueError("REQUIRED_INPUT server_specs")
    for key in ("cpu_model","cpu_cores","ram_gb","nic_model","nic_speed_gbps"):
        if key not in specs or specs[key] in ("",None):raise ValueError("REQUIRED_INPUT server_specs."+key)
    for key in ("cpu_cores","ram_gb","nic_speed_gbps"):positive(specs[key],"server_specs."+key)
    if specs["nic_speed_gbps"]<s["link_gbps"]:raise ValueError("INFEASIBLE_LINK: NIC slower than declared link")
    if s["http_version"] not in ("1.1","2") or type(s["keepalive"]) is not bool:
        raise ValueError("REQUIRED_INPUT http_version / keepalive invalid")
    if s["http_version"]=="2" and not s["keepalive"]:raise ValueError("HTTP/2 no-keepalive unsupported by oha")
    if s["baseline_alpn"]!=("h2" if s["http_version"]=="2" else "http/1.1") or s["baseline_keepalive"]!=s["keepalive"]:
        raise ValueError("BASELINE_MISMATCH: HAProxy ALPN/keepalive differs from gateway")
    if type(s["https_share"]) not in (int,float) or not 0<=s["https_share"]<=1:
        raise ValueError("REQUIRED_INPUT https_share fraction 0..1")
    if not isinstance(s["hosts"],list) or not s["hosts"] or len(s["hosts"])!=len(set(s["hosts"])):
        raise ValueError("host identities must be unique")
    if s["gateway_nodes"]!=[s["isolated_gateway"]]:
        raise ValueError("ONE_NODE_REQUIRED: a separate full-hour solo run for each surviving node")
    if s["windows"]*s["window_seconds"]<3600:raise ValueError("strict one-hour coverage missing")
    if s.get("allowed_status") != [200]:raise ValueError("HTTP success status must be 200 only")
    profiles=s["response_mix"]
    if not isinstance(profiles,list) or not profiles:raise ValueError("REQUIRED_INPUT response_mix")
    names=set();w=0;https=0
    for item in profiles:
        for key in ("name","url","response_bytes","weight"):
            if key not in item or item[key] in ("",None):raise ValueError("REQUIRED_INPUT response_mix."+key)
        name=item["name"];url=urlsplit(item["url"])
        if name in names or not name.replace("_","").replace("-","").isalnum():
            raise ValueError("response_mix names must be distinct and simple")
        names.add(name)
        if url.scheme not in ("http","https") or not url.hostname or not url.path.startswith("/"):
            raise ValueError("response_mix absolute HTTP(S) URL required")
        positive(item["response_bytes"],"response_bytes")
        if type(item["response_bytes"]) is not int or item["response_bytes"]>1048576:
            raise ValueError("response_bytes must be integer 1..1048576")
        positive(item["weight"],"weight")
        w+=item["weight"]
        if url.scheme=="https":https+=item["weight"]
    if abs(w-1)>1e-7 or abs(https-s["https_share"])>1e-7:
        raise ValueError("response_mix weights must sum to 1, HTTPS weights to https_share")
    if https and not s.get("tls_ca_file"):raise ValueError("REQUIRED_INPUT tls_ca_file")
    return {"rps":s["peak_rps"]*(1+s["headroom"]), "gbps":s["peak_gbps"]*(1+s["headroom"])}
