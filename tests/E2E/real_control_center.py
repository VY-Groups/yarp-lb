#!/usr/bin/env python3
"""Real-process management/API E2E acceptance on a DISPOSABLE GitHub runner.

Starts shipping ASP.NET Core GatewayCoreYarp.dll (not mocked controller/API),
with Linux production-mode X509-protected Data Protection keys. Uses only
loopback origin servers and ephemeral state. No production hosts or network.
"""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
from http.cookiejar import CookieJar
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
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

def ensure_http2_test_client():
    # This harness is explicitly restricted to disposable GitHub Actions CI.
    # Keep its protocol-test dependency pinned and self-contained so running
    # the harness does not rely on ambient packages on the runner.
    import importlib.util
    if importlib.util.find_spec("httpx") and importlib.util.find_spec("h2"):
        return
    subprocess.run([sys.executable,"-m","pip","install","--disable-pip-version-check",
        "httpx[http2]==0.28.1"],check=True)

def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

class Origin(BaseHTTPRequestHandler):
    connection_lock = threading.Lock()
    connection_active = 0
    connection_max_active = 0
    replacement_release = threading.Event()
    replacement_attempts = []
    compound_started = threading.Event()
    compound_disconnected = threading.Event()

    @classmethod
    def reset_connection_counts(cls):
        with cls.connection_lock:
            cls.connection_active = 0
            cls.connection_max_active = 0

    def do_GET(self):
        if self.path.startswith("/adc-compression/"):
            body = b"body { color: black; }\n" * 512
            self.send_response(200)
            self.send_header("Content-Type", "text/css")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "private, max-age=60" if self.path.endswith("/private") else "public, max-age=60")
            if self.path.endswith("/cookie"):
                self.send_header("Set-Cookie", "fixture=only; HttpOnly")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/compound-fail":
            self.send_error(503)
            return
        if self.path == "/compound-stall":
            # No response headers: observe the real upstream socket being
            # closed by the gateway deadline or downstream cancellation.
            Origin.compound_started.set()
            self.connection.settimeout(7)
            try:
                if not self.connection.recv(1):
                    Origin.compound_disconnected.set()
            except ConnectionResetError:
                Origin.compound_disconnected.set()
            except (TimeoutError, OSError):
                pass
            return
        if self.path == "/ws-hold":
            key = self.headers.get("Sec-WebSocket-Key", "")
            if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
                self.send_error(400)
                return
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()).decode("ascii")
            self.send_response(101, "Switching Protocols")
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            # Keep the upgraded upstream open until the test client closes it.
            # YARP must hold the selected destination permit for this whole tunnel.
            self.connection.settimeout(8)
            try:
                self.connection.recv(1)
            except (TimeoutError, OSError):
                pass
            return
        tracked = self.path.startswith("/probe-")
        if tracked:
            with Origin.connection_lock:
                Origin.connection_active += 1
                Origin.connection_max_active = max(Origin.connection_max_active, Origin.connection_active)
        body = ("e2e-origin:" + self.path).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            # Headers arrive immediately but the full response stream remains open.
            # This makes the admission E2E prove that a permit covers response-body copy.
            if self.path == "/hold-replacement":
                if not Origin.replacement_release.wait(15):
                    raise TimeoutError("replacement fixture release was not signaled")
            elif self.path.startswith("/hold-short"):
                time.sleep(.8)
            elif self.path.startswith("/hold"):
                time.sleep(3.5)
            elif tracked:
                time.sleep(.4)
            self.wfile.write(body)
        finally:
            if tracked:
                with Origin.connection_lock:
                    Origin.connection_active -= 1
    def do_POST(self):
        if not self.path.startswith("/replacement-"):
            self.send_error(404)
            return
        payload=self.rfile.read(int(self.headers.get("Content-Length","0")))
        with Origin.connection_lock:
            Origin.replacement_attempts.append((self.server.server_address[1],self.path,payload))
        body=f"replacement-origin:{self.server.server_address[1]}".encode()
        self.send_response(200)
        self.send_header("Content-Length",str(len(body)))
        self.end_headers()
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
    def session(self, *, accept_privacy=True):
        info=self.request("GET","/admin/api/session")
        if info.get("authenticated"):
            self.csrf=info["csrf"]
            # Disposable test clients explicitly acknowledge the notice.
            # Never retry a blocked mutation automatically.
            if accept_privacy and not info.get("privacyAccepted"):
                self.request("POST","/admin/api/privacy/accept",{"version":info["privacyVersion"]})
                info=self.request("GET","/admin/api/session")
                check(info["privacyAccepted"],"server confirms explicit privacy acceptance")
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
def gateway(cwd:Path, dll:Path, root:Path, listen_port:int, https_port:int|None=None):
    env=os.environ.copy()
    env.pop("YARP_EC2_LAB_MODE",None)
    urls=[f"http://127.0.0.1:{listen_port}"]
    if https_port is not None:
        urls.append(f"https://127.0.0.1:{https_port}")
    env.update(
        ASPNETCORE_ENVIRONMENT="Production",
        ASPNETCORE_URLS=";".join(urls),
        YARP_CONTROL_PLANE_DIR=str(root/"state"),
        YARP_RUNTIME_CONFIG_PATH=str(root/"state"/"config"/"appsettings.json"),
        YARP_LINUX_DP_CERT_PFX_PATH=str(root/"secrets"/"dp.pfx"),
        YARP_LINUX_DP_CERT_PASSWORD_FILE=str(root/"secrets"/"dp-password"),
    )
    if https_port is not None:
        # Test fixtures may require an independently trusted server TLS
        # certificate. Keep that distinct from the dedicated RSA Data
        # Protection wrapping leaf when a tls.pfx was provisioned.
        tls_pfx = root/"secrets"/"tls.pfx"
        if not tls_pfx.is_file():
            tls_pfx = root/"secrets"/"dp.pfx"
        env.update(
            ASPNETCORE_Kestrel__Certificates__Default__Path=str(tls_pfx),
            ASPNETCORE_Kestrel__Certificates__Default__Password="temporary-e2e-only-password",
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
        "-subj","/CN=temporary-gatewaycore-e2e", "-keyout",str(key),"-out",str(cert),
        # The disposable Data Protection PFX must satisfy the same dedicated
        # encryption leaf profile as production, rather than relying on
        # OpenSSL distribution-specific req defaults.
        "-addext","basicConstraints=critical,CA:FALSE",
        "-addext","keyUsage=critical,keyEncipherment"],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["openssl","pkcs12","-export","-out",str(secrets/"dp.pfx"),
        "-inkey",str(key),"-in",str(cert),"-passout","pass:temporary-e2e-only-password"],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for p in (key,cert,secrets/"dp.pfx"): p.chmod(0o600)

    # Kestrel needs a separate TLS identity with signing usage. Never reuse
    # the encryption-only Data Protection wrapper as a server certificate.
    tls_key=secrets/"tls.key"
    tls_cert=secrets/"tls.crt"
    tls_pfx=secrets/"tls.pfx"
    subprocess.run(["openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","7",
        "-subj","/CN=127.0.0.1", "-keyout",str(tls_key),"-out",str(tls_cert),
        "-addext","subjectAltName=IP:127.0.0.1",
        "-addext","basicConstraints=critical,CA:FALSE",
        "-addext","keyUsage=critical,digitalSignature,keyEncipherment"],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    subprocess.run(["openssl","pkcs12","-export","-out",str(tls_pfx),
        "-inkey",str(tls_key),"-in",str(tls_cert),"-passout","pass:temporary-e2e-only-password"],
        check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for p in (tls_key,tls_cert,tls_pfx): p.chmod(0o600)
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

def response(base:str,path:str,method="GET",payload=None):
    req=Request(base+path,data=payload,headers={"Accept":"text/plain"},method=method)
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

def open_websocket(base:str,path:str):
    sock=socket.create_connection(("127.0.0.1",int(base.rsplit(":",1)[1])),timeout=4)
    key=base64.b64encode(os.urandom(16)).decode("ascii")
    request=(f"GET {path} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\n\r\n")
    sock.sendall(request.encode("ascii"))
    response=b""
    try:
        while b"\r\n\r\n" not in response:
            chunk=sock.recv(4096)
            if not chunk:
                raise AssertionError("WebSocket handshake ended before response headers")
            response+=chunk
            if len(response)>16384:
                raise AssertionError("WebSocket handshake headers exceeded the test bound")
        if not response.startswith(b"HTTP/1.1 101 "):
            raise AssertionError(f"expected WebSocket 101 response, got {response[:300]!r}")
        return sock
    except Exception:
        sock.close()
        raise

def verify_destination_admission(base:str,https_base:str,admin:Client,reviewer:Client,initial:dict):
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

        websocket=open_websocket(base,"/admit/ws-hold")
        try:
            wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1)
            websocket_waiter=pool.submit(response,base,"/admit/normal")
            wait_metric(admin,"yarp_control_destination_admission_queued_requests",1)
            status,headers,_=response(base,"/admit/rejected")
            check(status==503 and headers.get("X-GatewayCore-Rejection")=="destination_queue_full",
                "a live WebSocket tunnel retains its selected backend permit and bounds excess work")
            websocket.close()
            check(websocket_waiter.result(timeout=5)[0]==200,
                "closing a WebSocket tunnel releases its backend permit to the queued request")
        finally:
            websocket.close()
        wait_metric(admin,"yarp_control_destination_admission_inflight_requests",0)
        wait_metric(admin,"yarp_control_destination_admission_queued_requests",0)
        check(response(base,"/admit/normal")[0]==200,
            "destination admission recovers after a WebSocket client disconnect")

        # Exercise the same shipping process over a negotiated HTTP/2 TLS
        # listener. Concurrent requests share one HTTP/2 client pool, while the
        # per-destination request gate continues to bound streams, not sockets.
        import httpx
        # A single transport connection makes this a multiplexing test rather
        # than merely three independent HTTP/2 connections.
        with httpx.Client(http2=True,verify=False,timeout=8.0,trust_env=False,
                          limits=httpx.Limits(max_connections=1,max_keepalive_connections=1)) as h2:
            check(h2.get(https_base+"/gateway/health").http_version=="HTTP/2",
                "TLS listener negotiates real HTTP/2 before admission checks")
            h2_first=pool.submit(h2.get,https_base+"/admit/hold-short")
            wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1)
            h2_second=pool.submit(h2.get,https_base+"/admit/normal")
            wait_metric(admin,"yarp_control_destination_admission_queued_requests",1)
            h2_rejected=h2.get(https_base+"/admit/rejected")
            check(h2_rejected.status_code==503 and h2_rejected.http_version=="HTTP/2" and
                  h2_rejected.headers.get("X-GatewayCore-Rejection")=="destination_queue_full",
                "HTTP/2 multiplexed overload is rejected locally without an upstream replay")
            h2_first_response=h2_first.result(timeout=5)
            h2_second_response=h2_second.result(timeout=5)
            check(h2_first_response.status_code==200 and h2_first_response.http_version=="HTTP/2",
                "HTTP/2 response body retains its selected destination permit through streaming")
            check(h2_second_response.status_code==200 and h2_second_response.http_version=="HTTP/2",
                "queued HTTP/2 stream receives the released FIFO destination permit")

    wait_metric(admin,"yarp_control_destination_admission_queued_requests",0)
    wait_metric(admin,"yarp_control_destination_admission_inflight_requests",0)
    metrics=admin.request("GET","/gateway/metrics")
    check('yarp_control_destination_admission_rejected_total{destination="fixture/origin"} 3' in metrics,
        "destination admission rejection counter is exposed with bounded destination labels")
    check('yarp_control_destination_admission_queue_timeouts_total{destination="fixture/origin"} 1' in metrics,
        "destination admission queue timeout counter is exposed")
    check('yarp_control_destination_admission_waiter_canceled_total{destination="fixture/origin"} 2' in metrics,
        "queue timeout and client disconnect both release bounded waiter reservations")
    check('yarp_control_destination_admission_queue_wait_seconds_count{destination="fixture/origin"} 5' in metrics,
        "bounded-label queue wait summary is exported for dashboards")
    return pending

def verify_queued_destination_replacement(base:str,admin:Client,reviewer:Client,origin_port:int):
    """Keep a real response open, replace the selected destination under the same ID,
    and wait for an in-memory YARP marker before releasing the queued transaction."""
    def apply(address, marker):
        state=admin.request("GET","/admin/api/state")
        clusters=json.loads(json.dumps(state["clusters"]))
        dests=clusters["fixture"]["Destinations"]
        dests["origin"]["Address"]=address
        dests["origin"]["Metadata"]["GatewayCore.Admission.QueueTimeoutMs"]="10000"
        if marker:
            dests["reload-marker"]={"Address":address,"Metadata":{"TrafficState":"draining"}}
        else:
            dests.pop("reload-marker",None)
        pending=admin.request("POST","/admin/api/change-requests",{
            "reason":"E2E replace same destination ID with independent origin",
            "payload":{"routes":state["routes"],"clusters":clusters,
                "disabled":state["disabled"],"revision":state["revision"]}})
        reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",{
            "decision":"approve","reason":"Approve disposable destination replacement fixture"})
    def await_marker(present):
        end=time.monotonic()+5
        while time.monotonic()<end:
            runtime=admin.request("GET","/admin/api/runtime/destinations")
            cluster=next(c for c in runtime["clusters"] if c["clusterId"]=="fixture")
            if any(d["destinationId"]=="reload-marker" for d in cluster["destinations"])==present:
                return
            time.sleep(.03)
        raise AssertionError("YARP in-memory configuration marker did not converge")
    original=f"http://127.0.0.1:{origin_port}/"
    apply(original,False)
    # Verify the extended admission timeout applies through the live config before
    # queueing. A temporary marker round trip fences the asynchronous reload.
    apply(original,True)
    await_marker(True)
    apply(original,False)
    await_marker(False)
    # The YARP model marker precedes asynchronous admission reconciliation.
    # Only an idempotent GET may wait for the matching gate; never retry the
    # transaction POST or the held stream that the fixture is about to test.
    deadline=time.monotonic()+6
    while True:
        status,headers,body=response(base,"/admit/normal")
        if status==200 and body=="e2e-origin:/normal":
            break
        check(status==503 and headers.get("X-GatewayCore-Rejection")=="admission_policy_conflict",
            "unreconciled policy rejects the readiness GET locally")
        if time.monotonic()>=deadline:
            raise AssertionError("destination admission policy did not reconcile")
        time.sleep(.05)
    Origin.replacement_release.clear()
    with Origin.connection_lock:
        Origin.replacement_attempts.clear()
    with backend() as replacement, ThreadPoolExecutor(max_workers=3) as pool:
        try:
            held=pool.submit(response,base,"/admit/hold-replacement")
            wait_metric(admin,"yarp_control_destination_admission_inflight_requests",1)
            transaction=pool.submit(response,base,"/admit/replacement-queued","POST",b"unique-queued")
            wait_metric(admin,"yarp_control_destination_admission_queued_requests",1)
            apply(f"http://127.0.0.1:{replacement}/",True)
            await_marker(True)
            check(not transaction.done(),"same-ID replacement is loaded while original request remains queued")
            Origin.replacement_release.set()
            check(held.result(timeout=6)[0]==200,"original active response completes despite config replacement")
            status,headers,_=transaction.result(timeout=6)
            check(status==503 and headers.get("X-GatewayCore-Rejection")=="destination_unavailable_after_queue",
                "live queued POST is rejected after same-ID destination replacement")
            wait_metric(admin,"yarp_control_destination_admission_inflight_requests",0)
            wait_metric(admin,"yarp_control_destination_admission_queued_requests",0)
            with Origin.connection_lock:
                check(Origin.replacement_attempts==[],"queued POST never reaches old or replacement origin")
            status,_,body=response(base,"/admit/replacement-new","POST",b"unique-new")
            check(status==200 and body==f"replacement-origin:{replacement}",
                "new POST reaches the replacement destination after queue recovery")
            with Origin.connection_lock:
                check(Origin.replacement_attempts==[(replacement,"/replacement-new",b"unique-new")],
                    "only the new transaction reaches the replacement origin exactly once")
        finally:
            Origin.replacement_release.set()
            apply(original,False)
            await_marker(False)

def verify_max_connections_per_server(base:str,admin:Client,reviewer:Client):
    # Exercise YARP's actual outgoing HTTP connection cap independently from the
    # per-destination request gate: the latter is configured above the test load.
    def apply_connection_limit(limit:int):
        state=admin.request("GET","/admin/api/state")
        routes=dict(state["routes"])
        routes["connlimit-e2e"]={"ClusterId":"fixture","Match":{"Path":"/connlimit/{**catch-all}"},
            "Transforms":[{"PathRemovePrefix":"/connlimit"}]}
        clusters=json.loads(json.dumps(state["clusters"]))
        fixture=clusters["fixture"]
        fixture["HttpRequest"]={"Version":"1.1"}
        fixture.setdefault("HttpClient",{})["MaxConnectionsPerServer"]=limit
        destination=fixture["Destinations"]["origin"]
        metadata=destination.get("Metadata",{})
        for key in ("GatewayCore.Admission.MaxInFlight", "GatewayCore.Admission.MaxPending",
                    "GatewayCore.Admission.QueueTimeoutMs"):
            metadata.pop(key,None)
        if metadata:
            destination["Metadata"]=metadata
        else:
            destination.pop("Metadata",None)
        payload={"routes":routes,"clusters":clusters,"disabled":state["disabled"],"revision":state["revision"]}
        pending=admin.request("POST","/admin/api/change-requests",{
            "reason":f"E2E verify upstream HTTP connection cap {limit}","payload":payload})
        reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",{
            "decision":"approve","reason":f"Approved isolated upstream connection cap {limit}"})
        deadline=time.monotonic()+6
        while time.monotonic()<deadline:
            metrics=admin.request("GET","/gateway/metrics")
            admission_rows=[line for line in metrics.splitlines()
                if "yarp_control_destination_admission_" in line and 'destination="fixture/origin"' in line]
            if not admission_rows:
                return
            time.sleep(.05)
        raise AssertionError(f"per-destination admission state was not retired before HTTP connection-cap test: {admission_rows!r}")

    def run_concurrent_probes():
        Origin.reset_connection_counts()
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses=list(pool.map(lambda index: response(base,f"/connlimit/probe-{index}"),range(4)))
        check(all(status==200 and body.startswith("e2e-origin:/probe-") for status,_,body in responses),
            "real YARP forwards all concurrent HTTP/1.1 connection-cap probes")
        with Origin.connection_lock:
            return Origin.connection_max_active

    apply_connection_limit(8)
    unconstrained=run_concurrent_probes()
    check(unconstrained>=2,"backend sees concurrent HTTP/1.1 requests before a one-connection cap")
    apply_connection_limit(1)
    constrained=0
    deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        constrained=run_concurrent_probes()
        if constrained==1:
            break
        time.sleep(.1)
    check(constrained==1,"MaxConnectionsPerServer=1 limits actual concurrent upstream connections to one")

def verify_secure_affinity(base, https_base, admin, operator, reviewer, origin_port):
    """Actual TLS proxy response and tampered-cookie failure-policy checks."""
    import httpx
    def submit(p,expected=200):
        pending=operator.request("POST","/admin/api/change-requests",
            {"reason":"Disposable secure affinity acceptance","payload":p})
        reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
            {"decision":"approve","reason":"Independent secure affinity fixture review"},expect=expected)
    def snapshot():
        state=admin.request("GET","/admin/api/state")
        return {key:state[key] for key in ("routes","clusters","disabled","revision")}
    p=snapshot()
    key="__Host-GatewayCore-affinity-pool"
    p["clusters"]["affinity-pool"]={"LoadBalancingPolicy":"RoundRobin",
        "Destinations":{"origin":{"Address":f"http://127.0.0.1:{origin_port}/"}},
        "Metadata":{"ADC.Persistence.Profile":"SecureCookie"},
        "SessionAffinity":{"Enabled":True,"Policy":"GatewayCoreExpiringCookie","FailurePolicy":"Return503Error",
            "AffinityKeyName":key,"Cookie":{"Path":"/","HttpOnly":True,
                "SecurePolicy":"Always","SameSite":"Lax","MaxAge":"00:30:00"}}}
    p["routes"]["affinity-route"]={"ClusterId":"affinity-pool","Match":{"Path":"/affinity-test/{**catch-all}"}}
    submit(p)
    # Disposable self-signed loopback certificate only.
    with httpx.Client(verify=False,timeout=8.0,trust_env=False) as client:
        url=https_base+"/affinity-test/ready"
        for attempt in range(100):
            response=client.get(url)
            if response.status_code==200: break
            time.sleep(.2)
        check(response.status_code==200,"real HTTPS affinity traffic forwarded")
        check(client.get(base+"/affinity-test/ready").status_code==403,
              "expiring affinity refuses plaintext data traffic")
        header=response.headers.get("set-cookie","").lower()
        check(key.lower()+"=" in header and "secure" in header and "httponly" in header
              and "samesite=lax" in header and "max-age=1800" in header and "domain=" not in header,
              "real encrypted affinity cookie security attributes")
        check(client.get(url).status_code==200,"valid affinity cookie accepted")
        client.cookies.clear()
        check(client.get(url,headers={"Cookie":key+"=tampered"}).status_code==503,
              "invalid affinity returns 503 under fail-closed policy")
        p=snapshot()
        p["clusters"]["affinity-pool"]["SessionAffinity"]["FailurePolicy"]="Redistribute"
        submit(p)
        for attempt in range(100):
            response=client.get(url,headers={"Cookie":key+"=tampered"})
            if response.status_code==200: break
            time.sleep(.2)
        check(response.status_code==200,"redistribution policy accepts traffic with invalid affinity")
        p=snapshot()
        p["clusters"]["affinity-pool"]["SessionAffinity"]["Cookie"]["SecurePolicy"]="None"
        submit(p,expected=400)
        check(admin.request("GET","/admin/api/state")["clusters"]["affinity-pool"]["SessionAffinity"]["Cookie"]["SecurePolicy"]=="Always",
              "insecure reviewed affinity draft rejected")
        p=snapshot()
        p["routes"].pop("affinity-route")
        p["clusters"].pop("affinity-pool")
        submit(p)

def verify_reusable_adc_catalogs(base, admin, operator, reviewer, origin_port):
    """Validate actual approved catalog storage, references and materialized traffic."""
    def payload():
        state=admin.request("GET","/admin/api/state")
        return {key:state[key] for key in ("routes","clusters","disabled","revision")}
    def approve(p, expected=200):
        pending=operator.request("POST","/admin/api/change-requests",
            {"reason":"Disposable ADC catalog acceptance","payload":p})
        reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
            {"decision":"approve","reason":"Independent ADC catalog fixture review"},expect=expected)
    p=payload()
    addr=f"http://127.0.0.1:{origin_port}/"
    active={"Enabled":True,"Path":"/compound-ok","Interval":"00:00:05","Timeout":"00:00:02","Policy":"RiseFall"}
    metadata={"RiseFall.Rise":"2","RiseFall.Fall":"3","ConsecutiveFailuresHealthPolicy.Threshold":"3"}
    p["monitorProfiles"]={"catalog-health":{"Active":active,"Metadata":metadata}}
    p["realServers"]={"catalog-origin":{"Address":addr,"Description":"Disposable origin"}}
    p["serviceGroups"]={"catalog-template":{"Policy":"RoundRobin","MonitorProfile":"catalog-health",
        "Members":{"catalog-origin":{"Weight":"7","TrafficRole":"primary"}}}}
    p["clusters"]["catalog-pool"]={"LoadBalancingPolicy":"RoundRobin",
        "HealthCheck":{"Active":active},"Metadata":metadata,
        "Destinations":{"catalog-origin":{"Address":addr,"Metadata":{"Weight":"7","TrafficRole":"primary"}}}}
    p["routes"]["catalog-route"]={"ClusterId":"catalog-pool","Match":{"Path":"/catalog-test/{**catch-all}"}}
    approve(p)
    state=admin.request("GET","/admin/api/state")
    check(state["monitorProfiles"]==p["monitorProfiles"] and state["realServers"]==p["realServers"]
          and state["serviceGroups"]==p["serviceGroups"],"approved ADC catalog state round trip")
    eventually(Client(base),"/catalog-test/ready","e2e-origin:/catalog-test/ready",seconds=20)
    invalid=payload()
    invalid["realServers"]={}
    approve(invalid,expected=400)
    check("catalog-origin" in admin.request("GET","/admin/api/state")["realServers"],
          "referenced server deletion rejected without changing storage")
    legacy=payload()
    legacy["routes"].pop("catalog-route")
    legacy["clusters"].pop("catalog-pool")
    approve(legacy)
    state=admin.request("GET","/admin/api/state")
    check("catalog-template" in state["serviceGroups"] and "catalog-origin" in state["realServers"]
          and "catalog-health" in state["monitorProfiles"],"legacy draft preserves ADC catalogs")

def verify_compound_probe_endpoint(base, admin, operator, reviewer, viewer, origin_port):
    """Exercise the shipping authenticated probe API, not a mocked handler."""
    def apply(mode, path="/compound-fail"):
        state=admin.request("GET","/admin/api/state")
        clusters=json.loads(json.dumps(state["clusters"]))
        if mode is None:
            clusters.pop("compound-e2e",None)
        else:
            clusters["compound-e2e"]={
                "HealthCheck":{"Active":{"Enabled":False,"Path":"/compound-ok"}},
                "Metadata":{"ADC.Diagnostics.CompoundMode":mode,
                            "ADC.Diagnostics.SecondaryPath":path},
                "Destinations":{"origin":{"Address":f"http://127.0.0.1:{origin_port}/"}}}
        payload={"routes":state["routes"],"clusters":clusters,"disabled":state["disabled"],
                 "revision":state["revision"]}
        pending=operator.request("POST","/admin/api/change-requests",
            {"reason":"Disposable compound diagnostic acceptance","payload":payload})
        reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
            {"decision":"approve","reason":"Independent compound diagnostic fixture approval"})
    def result():
        reply=operator.request("POST","/admin/api/probe",{})
        check("not YARP health state" in reply["type"],"diagnostic scope is explicit in endpoint response")
        return next(r for r in reply["results"] if r["cluster"]=="compound-e2e")
    def checks(row):
        return {r["check"]:(r["passed"],r["httpStatus"]) for r in row["checks"]}
    apply("AND")
    try:
        viewer.request("POST","/admin/api/probe",{},expect=403)
        operator.request("POST","/admin/api/probe",{},csrf=False,expect=403)
        row=result()
        check(row["compoundMode"]=="AND" and row["status"]=="unreachable" and
              checks(row)=={"tcp-connect":(True,None),"http-primary":(True,200),
                            "http-secondary":(False,503)},
              "real endpoint AND rejects failed secondary HTTP")
        apply("OR")
        row=result()
        check(row["compoundMode"]=="OR" and row["status"]=="reachable" and
              checks(row)["http-secondary"]==(False,503),
              "real endpoint OR reports partial success")
        apply("AND","/compound-stall")
        Origin.compound_started.clear()
        Origin.compound_disconnected.clear()
        started=time.monotonic()
        row=result()
        elapsed=time.monotonic()-started
        check(2.5<=elapsed<6 and row["status"]=="unreachable" and
              checks(row)["http-primary"]==(True,200) and
              checks(row)["http-secondary"]==(False,None),
              "real endpoint shared deadline bounds stalled HTTP and reports failed AND")
        check(Origin.compound_disconnected.wait(2),"deadline closes actual upstream socket")
        Origin.compound_started.clear()
        Origin.compound_disconnected.clear()
        # Preserve real session cookie and CSRF token, then disconnect the
        # actual client while the upstream is waiting for response headers.
        req=Request(base+"/admin/api/probe",data=b"{}",method="POST")
        for handler in operator.opener.handlers:
            if isinstance(handler,HTTPCookieProcessor):
                handler.cookiejar.add_cookie_header(req)
        cookie=req.get_header("Cookie")
        check(bool(cookie) and bool(operator.csrf),"cancellation fixture uses authenticated session")
        host=base.split("://",1)[1]
        with socket.create_connection(("127.0.0.1",int(host.rsplit(":",1)[1])),timeout=3) as sock:
            request=(f"POST /admin/api/probe HTTP/1.1\r\nHost: {host}\r\n"
                     f"Cookie: {cookie}\r\nX-CSRF-Token: {operator.csrf}\r\n"
                     "Content-Type: application/json\r\nContent-Length: 2\r\n"
                     "Connection: close\r\n\r\n{}")
            sock.sendall(request.encode("ascii"))
            check(Origin.compound_started.wait(2),"real authenticated request reaches stalled origin")
        check(Origin.compound_disconnected.wait(1.5),
              "client disconnect cancels upstream before the three-second deadline")
        apply("AND","/compound-ok-secondary")
        row=result()
        check(row["status"]=="reachable" and all(v[0] for v in checks(row).values()),
              "real endpoint AND succeeds when every check passes")
    finally:
        apply(None)
    check(not any(r["cluster"]=="compound-e2e" for r in
                  operator.request("POST","/admin/api/probe",{})["results"]),
          "reviewed removal removes compound diagnostic fixture")

def acceptance(base:str,https_base:str,origin_port:int):
    anonymous=Client(base)
    check(not anonymous.session()["initialized"],"clean state requires bootstrap")
    check("<html" in anonymous.request("GET","/dashboard"),"real dashboard HTML served")
    check("Privacy Policy" in anonymous.request("GET","/dashboard/privacy"),"standalone privacy notice is accessible before login")
    anonymous.request("POST","/admin/api/privacy/accept",{"version":"forged"},expect=401)
    check("function" in anonymous.request("GET","/dashboard/app.js"),"real browser JavaScript served")
    check(anonymous.request("GET","/admin/api/users",expect=401)=="","anonymous users endpoint remains 401")
    anonymous.request("POST","/admin/api/users",{"username":"unauth"},expect=401)
    anonymous.request("POST","/admin/api/bootstrap",{"username":"a","password":"weak","email":"invalid"},expect=400)
    anonymous.request("GET","/admin/api/gateway-readiness",expect=401)
    admin=Client(base)
    created=admin.request("POST","/admin/api/bootstrap",{"username":"admin_e2e",
        "password":"Admin-secret-long-4096!","email":"admin@example.invalid"})
    check(created["authenticated"],"first admin bootstrap")
    pending=admin.session(accept_privacy=False)
    check(not pending["privacyAccepted"] and "Privacy Policy" in pending["privacyText"],
          "new authenticated session must acknowledge policy")
    check("\r" not in pending["privacyText"] and
          hashlib.sha256(pending["privacyText"].encode("utf-8")).hexdigest().upper()==pending["privacyVersion"],
          "privacy revision hashes the canonical UTF-8 notice displayed to the user")
    admin.request("GET","/admin/api/state",expect=428)
    admin.request("POST","/admin/api/inventory",{"id":"blocked"},expect=428)
    admin.request("POST","/admin/api/privacy/accept",{"version":pending["privacyVersion"]},csrf=False,expect=403)
    admin.request("POST","/admin/api/privacy/accept",{"version":"stale"},expect=409)
    check(not admin.session(accept_privacy=False)["privacyAccepted"],"invalid acceptance leaves access locked")
    eventually(anonymous,"/fixture/check","e2e-origin:/check")
    check(admin.session()["privacyAccepted"],"explicit current-policy acceptance unlocks management")
    check(not admin.request("GET","/admin/api/inventory"),"blocked pre-acceptance mutation had no effect")
    check(any(row.get("action")=="PRIVACY_POLICY_ACCEPTED" for row in admin.request("GET","/admin/api/audit")),
          "explicit acceptance is recorded in the management audit")
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
    profile=admin.request("GET","/admin/api/organization")
    profile_update={"organizationName":"Disposable E2E Organization","sector":"technology",
        "region":"Lab","notes":"","expectedRevision":profile["revision"]}
    viewer.request("PUT","/admin/api/organization",profile_update,expect=403)
    updated=admin.request("PUT","/admin/api/organization",profile_update)
    admin.request("PUT","/admin/api/organization",profile_update,expect=409)
    audit=admin.request("GET","/admin/api/audit")
    for action,expected in (("ROUTING_CHANGE_FREEZE_ENABLED",True),
                            ("ROUTING_CHANGE_FREEZE_DISABLED",False)):
        matching=[row for row in audit if row["action"]==action]
        check(len(matching)==1 and matching[0]["details"]["current"] is expected,
              "shared audit records exact freeze outcome: "+action)
    matching=[row for row in audit if row["action"]=="ORGANIZATION_PROFILE_UPDATED"]
    check(len(matching)==1 and matching[0]["details"]["revision"]==updated["revision"]
          and matching[0]["details"]["organizationName"]==profile_update["organizationName"],
          "shared audit records exact profile revision; denied and stale updates do not emit success")
    plan={"schemaVersion":1,"payload":payload}
    before_drafts=admin.request("GET","/admin/api/change-requests")
    before_backups=admin.request("GET","/admin/api/backups")
    result=operator.request("POST","/admin/api/gitops/plan",plan)
    check(result["dryRun"] and result["approvalRequired"] and
          result["revision"]==initial["revision"] and result["routes"]["added"]==["e2e"] and
          not result["clusters"]["added"],
          "versioned GitOps plan reports route additions without returning configuration values")
    check(operator.request("POST","/admin/api/gitops/plan",plan)==result,
          "same revision and desired configuration produce identical deterministic plans")
    viewer.request("POST","/admin/api/gitops/plan",plan,expect=403)
    operator.request("POST","/admin/api/gitops/plan",plan,csrf=False,expect=403)
    operator.request("POST","/admin/api/gitops/plan",dict(plan,schemaVersion=2),expect=400)
    bad=json.loads(json.dumps(plan))
    bad["payload"]["routes"]["e2e"]["ClusterId"]="missing-cluster"
    operator.request("POST","/admin/api/gitops/plan",bad,expect=400)
    stale=json.loads(json.dumps(plan))
    stale["payload"]["revision"]="0"*64
    operator.request("POST","/admin/api/gitops/plan",stale,expect=409)
    check(admin.request("GET","/admin/api/state")["revision"]==initial["revision"] and
          admin.request("GET","/admin/api/change-requests")==before_drafts and
          admin.request("GET","/admin/api/backups")==before_backups,
          "planning never modifies configuration, drafts or backups")
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
    operator.request("POST","/admin/api/gitops/plan",plan,expect=409)
    unchanged={"schemaVersion":1,"payload":{key:approved[key] for key in ("routes","clusters","disabled","revision")}}
    unchanged_plan=operator.request("POST","/admin/api/gitops/plan",unchanged)
    check(all(not unchanged_plan[section][kind]
              for section in ("routes","clusters","disabled")
              for kind in ("added","removed","updated")) and
          all(unchanged_plan[section]["unchanged"]==len(approved[section])
              for section in ("routes","clusters","disabled")),
          "fresh post-approval GitOps plan converges to empty diff and old revision is stale")
    rollback_backup=admin.request("GET","/admin/api/backups")[0]
    verify_destination_admission(base,https_base,admin,reviewer,approved)
    verify_queued_destination_replacement(base,admin,reviewer,origin_port)
    verify_max_connections_per_server(base,admin,reviewer)
    check(admin.request("GET","/admin/api/change-requests/"+pending["id"])["status"]=="Approved",
        "approved change recorded and auditable")
    admin.request("POST","/admin/api/change-requests",change,expect=200)  # stale drafts may be submitted but not applied
    backups=admin.request("GET","/admin/api/backups")
    check(bool(backups),"rollback backup exists after approval")
    admin.request("POST","/admin/api/restore/"+rollback_backup,{})
    check("e2e" not in admin.request("GET","/admin/api/state")["routes"],
        "authorized restore rolls routing config back")
    verify_compound_probe_endpoint(base,admin,operator,reviewer,viewer,origin_port)
    verify_reusable_adc_catalogs(base,admin,operator,reviewer,origin_port)
    verify_secure_affinity(base,https_base,admin,operator,reviewer,origin_port)
    # Actual gateway compression negotiation after independent configuration approval.
    import httpx
    snapshot = admin.request("GET","/admin/api/state")
    payload = {key:snapshot[key] for key in ("routes","clusters","disabled","revision")}
    payload["routes"]["compression-fixture"] = {
        "ClusterId":"fixture","Match":{"Path":"/adc-compression/{**catch-all}"},
        "Metadata":{"ADC.Acceleration.PublicHttpCompression":"true","ADC.Traffic.AllowedMethods":"GET,HEAD"}}
    pending = operator.request("POST","/admin/api/change-requests",
        {"reason":"Public HTTP compression fixture","payload":payload})
    reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
        {"decision":"approve","reason":"Independent compression fixture review"})
    with httpx.Client(verify=False,timeout=8,trust_env=False) as compression_client:
        url = base + "/adc-compression/public"
        expected = b"body { color: black; }\n" * 512
        for attempt in range(100):
            response = compression_client.get(url,headers={"Accept-Encoding":"gzip"})
            if response.status_code == 200: break
            time.sleep(.2)
        check(response.status_code==200 and response.headers.get("content-encoding")=="gzip" and
              response.content==expected and "accept-encoding" in response.headers.get("vary","").lower(),
              "real gateway gzip public asset and decoded body")
        denied = compression_client.post(url,content=b"must never reach origin",headers={"Accept-Encoding":"identity"})
        check(denied.status_code==405 and denied.headers.get("allow")=="GET, HEAD" and
              denied.headers.get("cache-control")=="no-store",
              "selected route method policy rejects POST before upstream (fixture origin would return 404)")
        for target, headers in (
            (url, {"Accept-Encoding":"identity"}),
            (url, {"Accept-Encoding":"gzip","Authorization":"Bearer fixture"}),
            (url, {"Accept-Encoding":"gzip","Cookie":"fixture=1"}),
            (url, {"Accept-Encoding":"gzip","Range":"bytes=0-20"}),
            (base+"/adc-compression/private", {"Accept-Encoding":"gzip"}),
            (base+"/adc-compression/cookie", {"Accept-Encoding":"gzip"}),
            (https_base+"/adc-compression/public", {"Accept-Encoding":"gzip"})):
            response = compression_client.get(target,headers=headers)
            check(response.status_code==200 and response.headers.get("content-encoding") is None and
                  response.content==expected, "compression bypass preserves exact upstream body")
    snapshot = admin.request("GET","/admin/api/state")
    payload = {key:snapshot[key] for key in ("routes","clusters","disabled","revision")}
    del payload["routes"]["compression-fixture"]
    pending = operator.request("POST","/admin/api/change-requests",
        {"reason":"Remove compression fixture","payload":payload})
    reviewer.request("POST",f"/admin/api/change-requests/{pending['id']}/decision",
        {"decision":"approve","reason":"Independent compression fixture cleanup"})
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
            "rollback":True,"freeze":True,"mailGuard":True,"directoryGuard":True,"compoundDiagnostics":True}

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
    ensure_http2_test_client()
    with tempfile.TemporaryDirectory(prefix="gatewaycore-real-e2e-") as td, backend() as origin:
        root=Path(td)
        openssl_state(root,origin)
        listen=port()
        https_listen=port()
        with gateway(cwd,dll,root,listen,https_listen) as base:
            results=acceptance(base,f"https://127.0.0.1:{https_listen}",origin)
        # Require the persisted state to survive a genuine process restart.
        with gateway(cwd,dll,root,listen,https_listen) as base:
            admin=Client(base)
            admin.login("admin_e2e","Admin-secret-long-4096!")
            check(admin.request("GET","/admin/api/onboarding")["status"]=="design-confirmed",
                "topology survives process restart with protected key ring")
            check("e2e" not in admin.request("GET","/admin/api/state")["routes"],
                "approved rollback survives restart")
            catalog=admin.request("GET","/admin/api/state")
            check("catalog-template" in catalog["serviceGroups"] and "catalog-origin" in catalog["realServers"]
                  and "catalog-health" in catalog["monitorProfiles"],"approved ADC catalogs survive process restart")
            # Exercise the actual shipping CLI transport against a real trusted
            # HTTPS gateway after restart. No fake cookies or TLS bypass.
            import importlib.util
            spec = importlib.util.spec_from_file_location("adc_diag", cwd / "tools" / "adc_diag.py")
            diag = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(diag)
            diag_base = f"https://127.0.0.1:{https_listen}"
            trusted = str(root / "secrets" / "tls.crt")
            client = diag.Client(diag_base, trusted)
            report = diag.collect(client, "viewer_e2e", "Viewer-secret-long-123!", "local",
                                  prompt=lambda _: "ACCEPT", notice=lambda _: None)
            check(report["inventory"]["serviceGroups"] == len(catalog["serviceGroups"]) and
                  report["inventory"]["clusters"] == len(catalog["clusters"]) and
                  type(report["localCounters"]["totalRequests"]) is int and
                  len(client.jar) == 0 and "catalog-origin" not in json.dumps(report),
                  "operator CLI uses real HTTPS Viewer authorization, privacy, counts and logout")
            declined = diag.Client(diag_base, trusted)
            try:
                diag.collect(declined, "viewer_e2e", "Viewer-secret-long-123!", "local",
                             prompt=lambda _: "DECLINE", notice=lambda _: None)
            except diag.DiagnosticError as error:
                check("declined" in str(error) and len(declined.jar) == 0,
                      "operator CLI decline blocks diagnostics and discards cookies")
            else:
                raise AssertionError("operator CLI accepted declined privacy notice")
            results["operatorDiagnosticsCli"] = True
        print("E2E_SUCCESS "+json.dumps(results,sort_keys=True),flush=True)

if __name__=="__main__":
    main()
