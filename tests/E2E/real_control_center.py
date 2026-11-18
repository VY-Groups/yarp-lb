#!/usr/bin/env python3
"""Real-process management/API E2E acceptance on a DISPOSABLE GitHub runner.

Starts shipping ASP.NET Core GatewayCoreYarp.dll (not mocked controller/API),
with Linux production-mode X509-protected Data Protection keys. Uses only
loopback origin servers and ephemeral state. No production hosts or network.
"""
from __future__ import annotations
import argparse
from contextlib import contextmanager
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPCookieProcessor, ProxyHandler, Request, build_opener
)

def check(ok, label):
    if not ok:
        raise AssertionError(label)
    print("PASS: " + label, flush=True)

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("e2e-origin:" + self.path).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        # Headers arrive immediately but the full response stream remains open.
        # This makes the admission E2E prove that a permit covers response-body copy.
        if self.path.startswith("/hold-short"):
            time.sleep(.8)
        elif self.path.startswith("/hold"):
            time.sleep(3.5)
        self.wfile.write(body)
    def log_message(self, *_): pass

class Client:
    def __init__(self, base):
        self.base=base
        self.opener=build_opener(ProxyHandler({}), HTTPCookieProcessor(CookieJar()))
        self.csrf=None
    def request(self, method, path, data=None, *, csrf=True, expect=200):
        headers={"Accept":"application/json"}
        payload=None if data is None else json.dumps(data).encode()
        if method!="GET":
            headers["Content-Type"]="application/json"
            if self.csrf and csrf: headers["X-CSRF-Token"]=self.csrf
            if payload is None: payload=b"{}"
        req=Request(self.base+path, data=payload, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=10) as r:
                status=r.status
                raw=r.read()
                ctype=r.headers.get("Content-Type","")
        except HTTPError as e:
            status=e.code
            raw=e.read()
            ctype=e.headers.get("Content-Type","")
        if status != expect:
            raise AssertionError(f"{method} {path}: expected {expect}, got {status}: {raw[:350]!r}")
        if "json" in ctype:
            return json.loads(raw) if raw else {}
        return raw.decode("utf8","replace")
    def session(self):
        info=self.request("GET","/admin/api/session")
        if info.get("authenticated"): self.csrf=info["csrf"]
        return info
    def login(self, user, password):
        r=self.request("POST","/admin/api/login",{"username":user,"password":password,"provider":"local"})
        check(r["authenticated"] and r["username"]==user,f"real login: {user}")
        check(self.session()["role"]==r["role"],f"role cookie: {user}")
    def bootstrap(self,user,pw,email):
        r=self.request("POST","/admin/api/bootstrap",{"username":user,"password":pw,"email":email})
        check(r["authenticated"],"first admin bootstrap")
        check(self.session()["authenticated"],"secure auth cookie + authenticated session")

@contextmanager
def backend():
    server=ThreadingHTTPServer(("127.0.0.1",0),Origin)
    thread=Thread(target=server.serve_forever,daemon=True)
    thread.start()
    try: yield server.server_address[1]
    finally: server.shutdown();server.server_close();thread.join(timeout=3)

@contextmanager
def gateway(cwd:Path, dll:Path, root:Path, listen_port:int):
    env=os.environ.copy()
    env.pop("YARP_EC2_LAB_MODE",None)
    env.update(
        ASPNETCORE_ENVIRONMENT="Production",
        ASPNETCORE_URLS=f"http://127.0.0.1:{listen_port}",
        YARP_CONTROL_PLANE_DIR=str(root/"state"),
        YARP_RUNTIME_CONFIG_PATH=str(root/"state"/"config"/"appsettings.json"),
        YARP_LINUX_DP_CERT_PFX_PATH=str(root/"secrets"/"dp.pfx"),
        YARP_LINUX_DP_CERT_PASSWORD_FILE=str(root/"secrets"/"dp-password"),
    )
    logs=open(root/"gateway.log","a",encoding="utf8")
    proc=subprocess.Popen(["dotnet",str(dll)],cwd=cwd,env=env,stdout=logs,stderr=subprocess.STDOUT)
    base=f"http://127.0.0.1:{listen_port}"
    try:
        client=Client(base)
        for _ in range(150):
            if proc.poll() is not None:
                break
            try:
                client.request("GET","/gateway/health")
                break
            except (AssertionError,URLError,ConnectionError,TimeoutError):
                time.sleep(.15)
        else: raise AssertionError("real shipping application did not become healthy")
        if proc.poll() is not None: raise AssertionError(f"real shipping application exited: {proc.returncode}")
        yield base
    except Exception:
        logs.flush()
        excerpt=(root/"gateway.log").read_text(encoding="utf8",errors="replace")[-9000:]
        print("GATEWAY LOG (redacted test fixture; no real secrets):\n"+excerpt,flush=True)
        raise
    finally:
        proc.terminate()
        try: proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill();proc.wait(timeout=5)
        logs.close()

def openssl_state(root:Path,origin_port:int):
    state=root/"state"
    config=state/"config"
    keys=state/"data-protection-keys"
    secrets=root/"secrets"
    for p in (state,config,keys,secrets):
        p.mkdir(parents=True,exist_ok=True,mode=0o700)
        p.chmod(0o700)
    (secrets/"dp-password").write_text("temporary-e2e-only-password\n")
    (secrets/"dp-password").chmod(0o600)
    key=secrets/"dp.key"
    cert=secrets/"dp.crt"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","7",
        "-subj","/CN=temporary-gatewaycore-e2e", "-keyout",str(key),"-out",str(cert)],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["openssl","pkcs12","-export","-out",str(secrets/"dp.pfx"),
        "-inkey",str(key),"-in",str(cert),"-passout","file:"+str(secrets/"dp-password")],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for p in (key,cert,secrets/"dp.pfx"): p.chmod(0o600)
    appconfig=config/"appsettings.json"
    appconfig.write_text(json.dumps({"Logging":{"LogLevel":{"Default":"Warning"}},
        "AllowedHosts":"localhost;127.0.0.1",
        "ReverseProxy":{"Routes":{"fixture":{"ClusterId":"fixture",
            "Match":{"Path":"/fixture/{**catch-all}"},
            "Transforms":[{"PathRemovePrefix":"/fixture"}]}},
            "Clusters":{"fixture":{"Destinations":{"origin":{"Address":f"http://127.0.0.1:{origin_port}/"}}}}}
        },indent=2))
    appconfig.chmod(0o600)
    return appconfig

def eventually(client:Client,path:str,expected_text:str,seconds:float=7):
    end=time.monotonic()+seconds
    while time.monotonic()<end:
        try:
            body=client.request("GET",path,expect=200)
            if expected_text in body: return
        except AssertionError: pass
        time.sleep(.2)
    raise AssertionError(f"real YARP did not forward {path} expected={expected_text}")

def response(base:str,path:str):
    req=Request(base+path,headers={"Accept":"text/plain"},method="GET")
    opener=build_opener(ProxyHandler({}))
    try:
        with opener.open(req,timeout=8) as r:
            return r.status,dict(r.headers),r.read().decode("utf8","replace")
    except HTTPError as e:
        return e.code,dict(e.headers),e.read().decode("utf8","replace")

def wait_metric(client:Client,name:str,expected:int,timeout:float=3):
    end=time.monotonic()+timeout
    last_body=""
    while time.monotonic()<end:
        body=client.request("GET","/gateway/metrics")
        last_body=body
        rows=[line for line in body.splitlines() if line.startswith(name+"{") and 'destination="fixture/origin"' in line]
        if rows and int(rows[0].rsplit(" ",1)[1])==expected:
            return
        time.sleep(.02)
    observed=[line for line in last_body.splitlines() if "destination_admission_" in line]
    raise AssertionError(f"metric {name} did not reach {expected}; observed={observed!r}")

def abort_queued_request(base:str,client:Client):
    sock=socket.create_connection(("127.0.0.1",int(base.rsplit(":",1)[1])),timeout=3)
    sock.sendall(b"GET /admit/aborted HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
    wait_metric(client,"yarp_control_destination_admission_queued_requests",1)
    sock.close()
    wait_metric(client,"yarp_control_destination_admission_queued_requests",0)

def verify_destination_admission(base:str,admin:Client,reviewer:Client,initial:dict):
    routes=dict(initial["routes"])
    routes["admission-e2e"]={"ClusterId":"fixture","Match":{"Path":"/admit/{**catch-all}"},
        "Transforms":[{"PathRemovePrefix":"/admit"}]}
    clusters=json.loads(json.dumps(initial["clusters"]))
    invalid=json.loads(json.dumps(clusters))
    invalid["fixture"]["Destinations"]["origin"]["Metadata"]={
        "GatewayCore.Admission.MaxInFlight":"1",
        "GatewayCore.Admission.MaxPending":"4097"}
    invalid_draft={"routes":routes,"clusters":invalid,"disabled":initial["disabled"],"revision":initial["revision"]}
    invalid_request=admin.request("POST","/admin/api/change-requests",{
        "reason":"E2E reject invalid per-destination admission bounds","payload":invalid_draft})
    reviewer.request("POST",f"/admin/api/change-requests/{invalid_request['id']}/decision",{
        "decision":"approve","reason":"Reject invalid queue size in isolated configuration"},expect=400)
    check(admin.request("GET","/admin/api/change-requests/"+invalid_request["id"])["status"]=="Pending",
        "invalid admission bounds fail closed without applying or approving the draft")
    clusters["fixture"]["Destinations"]["origin"]["Metadata"]={
        "GatewayCore.Admission.MaxInFlight":"1",
        "GatewayCore.Admission.MaxPending":"1",
        "GatewayCore.Admission.QueueTimeoutMs":"1500"}
    payload={"routes":routes,"clusters":clusters,"disabled":initial["disabled"],"revision":initial["revision"]}
    pending=admin.request("POST","/admin/api/change-requests",{
        "reason":"E2E exercise bounded destination request admission","payload":payload})
    reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",{
        "decision":"approve","reason":"Approve isolated admission integration fixture"})
    eventually(admin,"/admit/normal","e2e-origin:/normal")
    with ThreadPoolExecutor(max_workers=4) as pool:
        # Keep the first response open long enough to observe its active lease,
        # but below the configured queue timeout so the FIFO waiter can be granted.
        first=pool.submit(response,base,"/admit/hold-short")
        try:
            wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1,timeout=5)
        except AssertionError as error:
            result=first.result(timeout=1) if first.done() else "request still running"
            raise AssertionError(f"first admission request did not hold an observable slot: {result!r}") from error
        second=pool.submit(response,base,"/admit/normal")
        wait_metric(admin,"yarp_control_destination_admission_queued_requests",1)
        status,headers,_=response(base,"/admit/rejected")
        check(status==503 and headers.get("X-GatewayCore-Rejection")=="destination_queue_full",
            "real YARP rejects local overload distinctly when the bounded FIFO is full")
        check(first.result(timeout=5)[0]==200,"first real HTTP request keeps its destination slot until body completion")
        check(second.result(timeout=5)[0]==200,"queued real HTTP request receives the released FIFO slot")

        held=pool.submit(response,base,"/admit/hold")
        wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1)
        timed_out_status,timed_out_headers,_=response(base,"/admit/timeout")
        check(timed_out_status==503 and timed_out_headers.get("X-GatewayCore-Rejection")=="destination_queue_timeout",
            "real YARP removes a waiter at its configured queue timeout")
        check(held.result(timeout=5)[0]==200,"timed-out queue waiter does not cancel the active upstream response")

        held_again=pool.submit(response,base,"/admit/hold")
        wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1)
        abort_queued_request(base,admin)
        check(held_again.result(timeout=5)[0]==200,"client disconnect removes only its queued waiter")
        check(response(base,"/admit/normal")[0]==200,"destination recovers after timeout and client cancellation")

    wait_metric(admin,"yarp_control_destination_admission_queued_requests",0)
    wait_metric(admin,"yarp_control_destination_admission_inflight_requests",0)
    metrics=admin.request("GET","/gateway/metrics")
    check('yarp_control_destination_admission_rejected_total{destination="fixture/origin"} 1' in metrics,
        "destination admission rejection counter is exposed with bounded destination labels")
    check('yarp_control_destination_admission_queue_timeouts_total{destination="fixture/origin"} 1' in metrics,
        "destination admission queue timeout counter is exposed")
    check('yarp_control_destination_admission_waiter_canceled_total{destination="fixture/origin"} 2' in metrics,
        "queue timeout and client disconnect both release bounded waiter reservations")
    check('yarp_control_destination_admission_queue_wait_seconds_count{destination="fixture/origin"} 3' in metrics,
        "bounded-label queue wait summary is exported for dashboards")
    return pending

def acceptance(base:str,origin_port:int):
    anonymous=Client(base)
    check(not anonymous.session()["initialized"],"clean state requires bootstrap")
    check("<html" in anonymous.request("GET","/dashboard"),"real dashboard HTML served")
    check("function" in anonymous.request("GET","/dashboard/app.js"),"real browser JavaScript served")
    check(anonymous.request("GET","/admin/api/users",expect=401)=="","anonymous users endpoint remains 401")
    anonymous.request("POST","/admin/api/users",{"username":"unauth"},expect=401)
    anonymous.request("POST","/admin/api/bootstrap",{"username":"a","password":"weak","email":"invalid"},expect=400)
    anonymous.request("GET","/admin/api/gateway-readiness",expect=401)
    admin=Client(base)
    admin.bootstrap("admin_e2e","Admin-secret-long-4096!","admin@example.invalid")
    admin.request("POST","/admin/api/bootstrap",{"username":"other","password":"Another-very-long-secret!","email":"a@example.invalid"},expect=409)
    check(len(admin.request("GET","/admin/api/users"))==1,"admin user listing")
    admin.request("POST","/admin/api/users",{"username":"operator_e2e","role":"Operator","password":"Operator-secret-long!","email":"operator@example.invalid"},csrf=False,expect=403)
    admin.request("POST","/admin/api/users",{"username":"operator_e2e","role":"Operator","password":"Operator-secret-long!","email":"operator@example.invalid"})
    admin.request("POST","/admin/api/users",{"username":"viewer_e2e","role":"Viewer","password":"Viewer-secret-long-123!","email":"viewer@example.invalid"})
    admin.request("POST","/admin/api/users",{"username":"reviewer_e2e","role":"Administrator","password":"Reviewer-secret-long!","email":"reviewer@example.invalid"})
    check(len(admin.request("GET","/admin/api/users"))==4,"role-based admin user creation")
    operator,viewer,reviewer=[Client(base) for _ in range(3)]
    operator.login("operator_e2e","Operator-secret-long!")
    viewer.login("viewer_e2e","Viewer-secret-long-123!")
    reviewer.login("reviewer_e2e","Reviewer-secret-long!")
    viewer.request("GET","/admin/api/users",expect=403)
    viewer.request("POST","/admin/api/inventory",{"id":"bad"},expect=403)
    operator.request("POST","/admin/api/users",{"username":"bad"},expect=403)
    for client in (admin,operator,viewer):
        readiness=client.request("GET","/admin/api/gateway-readiness")
        check(type(readiness["ready"]) is bool and readiness["scope"]=="Local active destination health",
              "authenticated roles can inspect local readiness without data-listener access")
    check(viewer.request("GET","/admin/api/setup/overview")["verifiedForProduction"] is False,
        "viewer can inspect honest unverified setup")
    admin.request("GET","/admin/api/setup/version")
    initial=admin.request("GET","/admin/api/state")
    check("fixture" in initial["clusters"],"real proxy config inspection")
    eventually(anonymous,"/fixture/check","e2e-origin:/check")
    check("yarp_control_" in anonymous.request("GET","/gateway/metrics"),"real metrics served")
    admin.request("POST","/admin/api/inventory",{"id":"e2e-node","name":"Temporary origin","type":"Application Server","address":"127.0.0.1","notes":"disposable CI"})
    check(any(x["id"]=="e2e-node" for x in viewer.request("GET","/admin/api/inventory")),
        "inventory visible to Viewer")
    operator.request("DELETE","/admin/api/inventory/e2e-node")
    check(not viewer.request("GET","/admin/api/inventory"),"operator inventory delete persisted")
    on=admin.request("GET","/admin/api/onboarding")
    plan={"mode":"standalone","controlPlane":"local","dataStore":"local-file",
        "accessPattern":"segmented","gateways":[{"id":"gateway-01","hostname":"127.0.0.1","agentUrl":""}],
        "workloads":[{"id":"e2e-web","application":"e2e-site",
            "url":f"http://127.0.0.1:{origin_port}/","zone":"public","hostingEngine":"nginx"}]}
    result=admin.request("POST","/admin/api/onboarding/validate",{"plan":plan})
    check(result["issues"]==[],"standalone Nginx origin design validated")
    admin.request("POST","/admin/api/onboarding",{"plan":plan,"confirmDesign":True,
        "expectedRevision":on["revision"]})
    after=admin.request("GET","/admin/api/onboarding")
    check(after["status"]=="design-confirmed" and after["plan"]["workloads"][0]["hostingEngine"]=="nginx",
        "confirmed design persisted without changing live routing")
    admin.request("POST","/admin/api/onboarding",{"plan":plan,"confirmDesign":True,
        "expectedRevision":on["revision"]},expect=409)
    admin.request("POST","/admin/api/setup/freeze",{"frozen":True,
        "reason":"E2E controlled maintenance freeze test"})
    check(admin.request("GET","/admin/api/setup/freeze")["frozen"],"route freeze persisted")
    initial=admin.request("GET","/admin/api/state")
    route={"ClusterId":"fixture","Match":{"Path":"/e2e/{**catch-all}"},
        "Transforms":[{"PathRemovePrefix":"/e2e"}]}
    routes=dict(initial["routes"],**{"e2e":route})
    payload={"routes":routes,"clusters":initial["clusters"],"disabled":initial["disabled"],
        "revision":initial["revision"]}
    change={"reason":"E2E separate administrator approval verification","payload":payload}
    operator.request("POST","/admin/api/change-requests",change,expect=423)
    admin.request("POST","/admin/api/setup/freeze",{"frozen":False,
        "reason":"E2E completed maintenance freeze test"})
    pending=operator.request("POST","/admin/api/change-requests",change)
    check(pending["status"]=="Pending","operator submitted real configuration draft")
    operator.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
        {"decision":"approve","reason":"Operator self approval must be rejected"},expect=403)
    reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
        {"decision":"approve","reason":"Reviewing full E2E local configuration change"})
    approved=admin.request("GET","/admin/api/state")
    check("e2e" in approved["routes"] and approved["revision"]!=initial["revision"],
        "second admin applied approved route with revision bump")
    eventually(anonymous,"/e2e/real-proxy","e2e-origin:/real-proxy")
    rollback_backup=admin.request("GET","/admin/api/backups")[0]
    verify_destination_admission(base,admin,reviewer,approved)
    check(admin.request("GET","/admin/api/change-requests/"+pending["id"])["status"]=="Approved",
        "approved change recorded and auditable")
    admin.request("POST","/admin/api/change-requests",change,expect=200)  # stale drafts may be submitted but not applied
    backups=admin.request("GET","/admin/api/backups")
    check(bool(backups),"rollback backup exists after approval")
    admin.request("POST","/admin/api/restore/"+rollback_backup,{})
    check("e2e" not in admin.request("GET","/admin/api/state")["routes"],
        "authorized restore rolls routing config back")
    check(admin.request("GET","/admin/api/mail")["enabled"] is False,"SMTP starts disabled")
    admin.request("POST","/admin/api/mail/test",{},expect=409)
    admin.request("POST","/admin/api/mail",{"enabled":True,"host":"smtp.invalid","port":587,
        "from":"admin@example.invalid","username":"","password":"","startTls":True},expect=409)
    check(not admin.request("GET","/admin/api/mail")["enabled"],"SMTP verification prerequisite cannot be bypassed")
    anonymous.request("GET","/admin/api/mail",expect=401)
    viewer.request("GET","/admin/api/mail",expect=403)
    operator.request("POST","/admin/api/mail",{"enabled":False},expect=403)
    admin.request("POST","/admin/api/mail",{"enabled":False},csrf=False,expect=403)
    # Every OAuth secret must be restricted to its trusted provider SMTP host.
    oauth={"enabled":False,"host":"attacker.invalid","port":587,
        "from":"admin@example.invalid","username":"admin@example.invalid",
        "password":"","startTls":True,"authMode":"google-oauth",
        "oauthClientId":"ci-client-id","oauthClientSecret":"ci-only-secret",
        "oauthRefreshToken":"ci-only-refresh","oauthTenant":""}
    admin.request("POST","/admin/api/mail",oauth,expect=400)
    oauth["host"]="smtp.gmail.com"
    oauth["oauthClientSecret"]=""
    admin.request("POST","/admin/api/mail",oauth,expect=400)
    oauth["oauthClientSecret"]="ci-only-secret"
    oauth["oauthRefreshToken"]=""
    admin.request("POST","/admin/api/mail",oauth,expect=400)
    check(not admin.request("GET","/admin/api/mail")["oauthClientSecretConfigured"],
        "invalid OAuth settings did not persist OAuth credentials")
    admin.request("GET","/admin/api/directory")
    admin.request("POST","/admin/api/directory",{"enabled":True},expect=400)
    admin.request("GET","/admin/api/fleet")
    admin.request("GET","/admin/api/runtime/destinations")
    check(len(admin.request("GET","/admin/api/audit"))>=5,"real audit trail written")
    admin.request("POST","/admin/api/users/operator_e2e/password",{"password":"New-operator-secret-long!"})
    operator.request("GET","/admin/api/session")  # invalidated cookie
    check(not operator.session()["authenticated"],"password reset immediately invalidates current session")
    operator.request("POST","/admin/api/login",{"username":"operator_e2e","password":"Operator-secret-long!"},expect=401)
    operator.login("operator_e2e","New-operator-secret-long!")
    admin.request("POST","/admin/api/users/viewer_e2e/disable",{})
    check(not viewer.session()["authenticated"],"offboarding immediately invalidates existing viewer session")
    viewer.request("GET","/admin/api/inventory",expect=401)
    admin.request("POST","/admin/api/users/viewer_e2e/enable",{})
    reviewer.request("POST","/admin/api/logout",{})
    check(not reviewer.session()["authenticated"],"logout revokes browser session")
    check("status" in anonymous.request("GET","/gateway/health"),"live traffic remains independent of management login")
    return {"auth":True,"roleIsolation":True,"onboarding":True,"approval":True,"routing":True,
            "rollback":True,"freeze":True,"mailGuard":True,"directoryGuard":True}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("control-center"))
    args=parser.parse_args()
    cwd=args.root.resolve()
    dll=cwd/"bin"/"Release"/"net10.0"/"GatewayCoreYarp.dll"
    if not dll.is_file(): raise SystemExit(f"Build the real application first: {dll}")
    # Explicit CI guard; this harness cannot be pointed at production.
    if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("CI")!="true":
        raise SystemExit("REJECTED: E2E fixture requires disposable GitHub Actions CI")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-real-e2e-") as td, backend() as origin:
        root=Path(td)
        openssl_state(root,origin)
        listen=port()
        with gateway(cwd,dll,root,listen) as base:
            results=acceptance(base,origin)
        # Require the persisted state to survive a genuine process restart.
        with gateway(cwd,dll,root,listen) as base:
            admin=Client(base)
            admin.login("admin_e2e","Admin-secret-long-4096!")
            check(admin.request("GET","/admin/api/onboarding")["status"]=="design-confirmed",
                "topology survives process restart with protected key ring")
            check("e2e" not in admin.request("GET","/admin/api/state")["routes"],
                "approved rollback survives restart")
        print("E2E_SUCCESS "+json.dumps(results,sort_keys=True),flush=True)

if __name__=="__main__":
    main()
