#!/usr/bin/env python3
"""Generate a loopback-only HAProxy active-health ingress for TWO real VM nodes."""
import argparse
import ipaddress
from pathlib import Path

def build(a,b):
    a=str(ipaddress.IPv4Address(a)); b=str(ipaddress.IPv4Address(b))
    if a==b:
        raise ValueError("two distinct private peer IPs required")
    if not (ipaddress.ip_address(a).is_private and ipaddress.ip_address(b).is_private):
        raise ValueError("refuse public peer address")
    return f"""global
    log stdout format raw local0
    maxconn 4096
defaults
    mode http
    timeout connect 2s
    timeout client 15s
    timeout server 15s
frontend live_client
    bind 127.0.0.1:19080
    default_backend remote_gateways
backend remote_gateways
    balance roundrobin
    option httpchk GET /gateway/health
    http-check expect status 200
    default-server inter 1000ms fall 2 rise 2
    server remote_a {a}:18080 check
    server local_b {b}:18080 check
"""
if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--a",required=True); p.add_argument("--b",required=True)
    p.add_argument("--out",type=Path,required=True)
    x=p.parse_args()
    x.out.parent.mkdir(parents=True,exist_ok=True)
    x.out.write_text(build(x.a,x.b))
