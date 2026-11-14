#!/usr/bin/env python3
"""Real Apache httpd + Nginx + YARP + Nginx ingress-style forwarding E2E.

Disposable CI only. These are REAL HTTP origin servers; no Python backend
stub, no external business infrastructure or untrusted network endpoints.
This is NOT Kubernetes Ingress Controller or live TLS/CA production acceptance.
"""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
import json
import os
import socket
import subprocess
import tempfile
import time
import uuid
from urllib.error import HTTPError, URLError
from real_control_center import Client, check, gateway, openssl_state, eventually, port

NGINX_IMAGE = "nginx:1.28-alpine"
APACHE_IMAGE = "httpd:2.4-alpine"

def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout.strip()

@contextmanager
def container(image, port_number, local_document_root, target, *, extra=()):
    name="gatewaycore-e2e-"+uuid.uuid4().hex[:10]
    args=["docker","run","--detach","--rm","--name",name]
    args+=list(extra)
    if port_number:
        args+=["--publish",f"127.0.0.1:{port_number}:80"]
    if local_document_root is not None:
        args+=["--mount",f"type=bind,src={local_document_root},dst={target},readonly"]
    args.append(image)
    run(*args)
    try:
        yield name
    finally:
        subprocess.run(["docker","rm","--force",name],capture_output=True,check=False)

def await_http(url, phrase):
    c=Client("")
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        try:
            body=c.request("GET",url)
            if phrase in body:
                return
        except (AssertionError,URLError,ConnectionError):
            pass
        time.sleep(.2)
    raise AssertionError("actual HTTP origin not serving expected fixture at "+url)

def acceptance(root:Path, dll:Path, appdir:Path):
    nginxport, apacheport, gatewayport, ingressport=port(),port(),port(),port()
    while len({nginxport,apacheport,gatewayport,ingressport})<4:
        nginxport, apacheport, gatewayport, ingressport=port(),port(),port(),port()
    nginxroot=root/"nginx-web"
    apacheroot=root/"apache-web"
    nginxroot.mkdir()
    apacheroot.mkdir()
    (nginxroot/"index.html").write_text("NGINX_REAL_ORIGIN_OK")
    (apacheroot/"index.html").write_text("APACHE_REAL_ORIGIN_OK")
    with container(NGINX_IMAGE,nginxport,nginxroot,"/usr/share/nginx/html"), \
         container(APACHE_IMAGE,apacheport,apacheroot,"/usr/local/apache2/htdocs"):
        await_http(f"http://127.0.0.1:{nginxport}/index.html","NGINX_REAL_ORIGIN_OK")
        await_http(f"http://127.0.0.1:{apacheport}/index.html","APACHE_REAL_ORIGIN_OK")
        check(True,"Real Apache httpd and Nginx origin containers healthy")
        openssl_state(root,nginxport)
        with gateway(appdir,dll,root,gatewayport) as gateway_url:
            user=Client(gateway_url)
            user.bootstrap("engine_admin","Test-Password-Long-9341!","engine-admin@example.invalid")
            user.request("POST","/admin/api/users",{
                "username":"second_admin","role":"Administrator",
                "password":"Second-Password-Long-9394!","email":"second-admin@example.invalid"})
            reviewer=Client(gateway_url)
            reviewer.login("second_admin","Second-Password-Long-9394!")
            current=user.request("GET","/admin/api/onboarding")
            plan={"mode":"standalone","controlPlane":"local","dataStore":"local-file",
                  "accessPattern":"segmented",
                  "gateways":[{"id":"gateway-01","hostname":"127.0.0.1","agentUrl":""}],
                  "workloads":[{"id":"nginx-origin","application":"origin-test",
                      "url":f"http://127.0.0.1:{nginxport}/",
                      "zone":"public","hostingEngine":"nginx"},
                     {"id":"apache-origin","application":"origin-test",
                      "url":f"http://127.0.0.1:{apacheport}/",
                      "zone":"public","hostingEngine":"apache"}]}
            user.request("POST","/admin/api/onboarding",{"plan":plan,
                "confirmDesign":True,"expectedRevision":current["revision"]})
            check(True,"Confirmed standalone architecture before changing YARP routing")
            eventually(user,"/fixture/index.html","NGINX_REAL_ORIGIN_OK")
            initial=user.request("GET","/admin/api/state")
            clusters=dict(initial["clusters"])
            clusters["apache-real"]={"LoadBalancingPolicy":"RoundRobin","Destinations":{
                "apache01":{"Address":f"http://127.0.0.1:{apacheport}/"}}}
            routes=dict(initial["routes"])
            routes["apache-real"]={"ClusterId":"apache-real",
                "Match":{"Path":"/apache/{**catch-all}"},
                "Transforms":[{"PathRemovePrefix":"/apache"}]}
            draft={"routes":routes,"clusters":clusters,"disabled":initial["disabled"],
                "revision":initial["revision"]}
            submitted=user.request("POST","/admin/api/change-requests",{
                "reason":"E2E verify real Apache and Nginx origins through approved YARP routing",
                "payload":draft})
            reviewer.request("POST","/admin/api/change-requests/"+submitted["id"]+"/decision",{
                "decision":"approve","reason":"Approved isolated CI HTTP origins for YARP tests"})
            eventually(user,"/apache/index.html","APACHE_REAL_ORIGIN_OK")
            check(True,"Actual YARP hot reload forwarded to real Apache origin")
            # A real Nginx in front of YARP tests an ingress-style proxy chain.
            # It is not a Kubernetes controller and does not imply Ingress API.
            conf=root/"ingress-nginx.conf"
            conf.write_text(f"""events {{ worker_connections 64; }}
http {{
  access_log off;
  server {{
    listen 127.0.0.1:{ingressport};
    server_name localhost;
    location / {{
      proxy_http_version 1.1;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto $scheme;
      proxy_pass http://127.0.0.1:{gatewayport};
    }}
  }}
}}
""")
            with container(NGINX_IMAGE,None,conf,"/etc/nginx/nginx.conf",
                           extra=("--network","host")):
                await_http(f"http://127.0.0.1:{ingressport}/fixture/index.html",
                           "NGINX_REAL_ORIGIN_OK")
                await_http(f"http://127.0.0.1:{ingressport}/apache/index.html",
                           "APACHE_REAL_ORIGIN_OK")
                check(True,"Real Nginx ingress-style proxy forwards through real YARP to Apache and Nginx")
            return {"ApacheHTTP":"pass","NginxHTTP":"pass",
                    "NginxIngressStyle":"pass","KubernetesIngress":"not tested",
                    "originTlsAndHostRewrites":"not tested"}

def main():
    if os.environ.get("CI")!="true" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise SystemExit("Refusing to start origin containers outside disposable GitHub CI")
    appdir=(Path(__file__).resolve().parents[2]/"control-center").resolve()
    dll=appdir/"bin"/"Release"/"net10.0"/"GatewayCoreYarp.dll"
    if not dll.is_file():
        raise SystemExit("Build the shipping application before this test")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-http-origins-") as td:
        report=acceptance(Path(td),dll,appdir)
    print("HTTP_ORIGINS_E2E "+json.dumps(report,sort_keys=True),flush=True)

if __name__=="__main__":
    main()
