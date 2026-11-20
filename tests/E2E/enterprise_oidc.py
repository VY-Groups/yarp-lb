#!/usr/bin/env python3
"""Real GatewayCore OIDC handler, disposable TLS IdP, independently signed tokens."""
from __future__ import annotations
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookiejar import CookieJar
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import build_opener, ProxyHandler, HTTPSHandler, HTTPCookieProcessor, Request, HTTPRedirectHandler
from unittest.mock import patch
from real_control_center import backend, gateway, openssl_state, port, Client, check

# These Linux-only CI fixtures must exercise the shipping file-based secret
# readers. Use an owner-only RAM-backed directory, never ordinary disk or
# uploaded artifacts, and create each secret file with permissions atomically.
def fixture_secret_directory():
    with open("/proc/mounts", encoding="utf-8") as mounts:
        if not any(line.split()[1:3] == ["/dev/shm", "tmpfs"] for line in mounts):
            raise RuntimeError("CI requires /dev/shm tmpfs for disposable credentials")
    return tempfile.TemporaryDirectory(prefix="gatewaycore-ci-secrets-", dir="/dev/shm")

def write_private_fixture_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    if path.stat().st_mode & 0o777 != 0o600:
        raise RuntimeError("Fixture secret file permissions are not owner-only")

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def cmd(*args, **kwargs):
    return subprocess.run(args,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,**kwargs).stdout

def make_tls(root, name, address):
    key=root/(name+".key")
    cert=root/(name+".crt")
    cmd("openssl","req","-x509","-newkey","rsa:3072","-nodes","-days","7",
        "-subj","/CN="+address,"-addext","subjectAltName=IP:"+address,
        "-addext","basicConstraints=critical,CA:TRUE","-keyout",str(key),"-out",str(cert))
    key.chmod(0o600)
    return key,cert

class Idp:
    def __init__(self, root, gateway_origin, tlskey, cert):
        self.gateway_origin=gateway_origin
        self.secret=secrets.token_hex(32)
        self.client="gateway-test-client"
        self.mode="valid"
        self.auth_override=None
        self.codes={}
        self.exchanges=0
        self.logout_requests=[]
        self.end_session_endpoint=None
        self.insecure_logout_hits=0
        self.signing=root/"jwt.pem"
        cmd("openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out",str(self.signing))
        self.signing.chmod(0o600)
        self.modulus=bytes.fromhex(cmd("openssl","rsa","-in",str(self.signing),"-modulus","-noout").decode().strip().split("=")[1])
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def reply(self, status, content):
                body=json.dumps(content).encode()
                self.send_response(status)
                self.send_header("Content-Type","application/json")
                self.send_header("Content-Length",str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_GET(self):
                parsed=urlsplit(self.path)
                if parsed.path=="/.well-known/openid-configuration":
                    self.reply(200,{"issuer":owner.issuer,"authorization_endpoint":owner.issuer+"/authorize",
                      "token_endpoint":owner.issuer+"/token","jwks_uri":owner.issuer+"/keys",
                      "end_session_endpoint":owner.end_session_endpoint or owner.issuer+"/logout",
                      "response_types_supported":["code"],"subject_types_supported":["public"],
                      "id_token_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"],
                      "token_endpoint_auth_methods_supported":["client_secret_post","client_secret_basic"],
                      "scopes_supported":["openid","profile"]})
                elif parsed.path=="/keys":
                    self.reply(200,{"keys":[{"kty":"RSA","kid":"fixture-1","use":"sig","alg":"RS256",
                        "n":b64url(owner.modulus),"e":"AQAB"}]})
                elif parsed.path=="/authorize":
                    q={k:v[0] for k,v in parse_qs(parsed.query).items()}
                    if (q.get("client_id")!=owner.client or q.get("response_type")!="code" or
                        q.get("redirect_uri")!=owner.gateway_origin+"/admin/oidc/callback" or
                        q.get("code_challenge_method")!="S256" or not q.get("code_challenge") or
                        not q.get("nonce") or not q.get("state") or q.get("acr_values")!="urn:fixture:fido" or
                        q.get("prompt")!="login" or q.get("max_age")!="0"):
                        return self.reply(400,{"error":"invalid_request"})
                    code=secrets.token_urlsafe(24)
                    owner.codes[code]=(q,owner.mode)
                    state=q["state"] if owner.mode!="tampered-state" else "corrupted"
                    location=q["redirect_uri"]+"?"+urlencode({"code":code,"state":state})
                    self.send_response(302)
                    self.send_header("Location",location)
                    self.send_header("Content-Length","0")
                    self.end_headers()
                elif parsed.path=="/logout":
                    q={k:v[0] for k,v in parse_qs(parsed.query).items()}
                    if (q.get("client_id")!=owner.client or
                        q.get("post_logout_redirect_uri")!=owner.gateway_origin+"/admin/oidc/signed-out" or
                        not q.get("state") or "id_token_hint" in q):
                        return self.reply(400,{"error":"invalid_logout_request"})
                    owner.logout_requests.append(q)
                    callback=q["post_logout_redirect_uri"]+"?"+urlencode({"state":q["state"]})
                    self.send_response(302)
                    self.send_header("Location",callback)
                    self.send_header("Content-Length","0")
                    self.end_headers()
                else: self.reply(404,{})
            def do_POST(self):
                if self.path!="/token": return self.reply(404,{})
                n=int(self.headers.get("Content-Length","0"))
                if not 0<n<=8192: return self.reply(400,{"error":"invalid_request"})
                q={k:v[0] for k,v in parse_qs(self.rfile.read(n).decode()).items()}
                expected=owner.codes.pop(q.get("code",""),None)
                credentials=q.get("client_id")==owner.client and q.get("client_secret")==owner.secret
                if self.headers.get("Authorization","").startswith("Basic "):
                    credentials=base64.b64decode(self.headers["Authorization"][6:]).decode()==owner.client+":"+owner.secret
                if not expected or not credentials: return self.reply(400,{"error":"invalid_grant"})
                auth,mode=expected
                if (q.get("grant_type")!="authorization_code" or q.get("redirect_uri")!=auth["redirect_uri"] or
                    b64url(hashlib.sha256(q.get("code_verifier","").encode()).digest())!=auth["code_challenge"]):
                    return self.reply(400,{"error":"invalid_grant"})
                owner.exchanges+=1
                now=int(time.time())
                token={"iss":owner.issuer,"sub":"operator-subject","aud":owner.client,
                    "iat":now,"exp":now+180,"auth_time":now,"nonce":auth["nonce"],
                    "acr":"urn:fixture:fido","amr":["pwd","fido2"],"groups":["gateway-operators"],
                    "roles":["Administrator"],"preferred_username":"recovery"}
                if owner.auth_override is not None: token["auth_time"]=owner.auth_override
                if mode=="issuer": token["iss"]=owner.issuer+"/wrong"
                if mode=="audience": token["aud"]="other-client"
                if mode=="nonce": token["nonce"]="wrong"
                if mode=="mfa": token["amr"]=["pwd","mfa"]
                if mode=="group": token["groups"]=["other"]
                if mode=="expired": token["exp"]=now-600
                unsigned=b64url(json.dumps({"alg":"RS256","kid":"fixture-1","typ":"JWT"}).encode())+"."+b64url(json.dumps(token).encode())
                sig=cmd("openssl","dgst","-sha256","-sign",str(owner.signing),input=unsigned.encode())
                if mode=="signature": sig=bytes(len(sig))
                self.reply(200,{"token_type":"Bearer","access_token":"disposable-fixture","expires_in":180,
                    "id_token":unsigned+"."+b64url(sig)})
            def log_message(self,*_): pass
        self.server=ThreadingHTTPServer(("127.0.0.2",0),Handler)
        self.issuer=f"https://127.0.0.2:{self.server.server_address[1]}"
        class InsecureLogoutHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.insecure_logout_hits+=1
                self.send_response(204)
                self.send_header("Content-Length","0")
                self.end_headers()
            def log_message(self,*_): pass
        self.insecure_server=ThreadingHTTPServer(("127.0.0.2",0),InsecureLogoutHandler)
        self.insecure_logout_endpoint=f"http://127.0.0.2:{self.insecure_server.server_address[1]}/logout"
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert),str(tlskey))
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def logout_notice(self, mode="valid", issued=None):
        stamp=int(time.time()) if issued is None else issued
        token={"iss":self.issuer,"aud":self.client,"sub":"operator-subject","iat":stamp,
            "jti":secrets.token_urlsafe(24),"events":{"http://schemas.openid.net/event/backchannel-logout":{}}}
        if mode=="issuer": token["iss"]=self.issuer+"/wrong"
        if mode=="audience": token["aud"]="wrong-client"
        if mode=="nonce": token["nonce"]="not-a-logout-token"
        if mode=="stale": token["iat"]=stamp-600
        if mode=="events": token["events"]={"unrelated":{}}
        if mode=="subject": token["sub"]="unknown-account"
        if mode=="jti": del token["jti"]
        typ="logout+jwt"
        if mode=="typ-jwt": typ="JWT"
        if mode=="typ-application": typ="application/logout+jwt"
        if mode=="typ-case": typ="Logout+jwt"
        if mode=="typ-other": typ="other"
        header={"alg":"RS256","kid":"fixture-1"}
        if mode!="typ-absent": header["typ"]=typ
        unsigned=b64url(json.dumps(header).encode())+"."+b64url(json.dumps(token).encode())
        sig=cmd("openssl","dgst","-sha256","-sign",str(self.signing),input=unsigned.encode())
        if mode=="signature": sig=bytes(len(sig))
        return unsigned+"."+b64url(sig),stamp

    def __enter__(self):
        self.thread.start()
        self.insecure_thread=threading.Thread(target=self.insecure_server.serve_forever,daemon=True)
        self.insecure_thread.start()
        return self
    def __exit__(self,*_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.insecure_server.shutdown()
        self.insecure_server.server_close()
        self.insecure_thread.join(timeout=5)

def browser(origin,ctx):
    jar=CookieJar()
    client=Client(origin)
    client.opener=build_opener(ProxyHandler({}), HTTPSHandler(context=ctx),HTTPCookieProcessor(jar))
    return client,jar

def backchannel(origin,ctx,token,expect):
    req=Request(origin+"/admin/oidc/backchannel-logout",data=urlencode({"logout_token":token}).encode(),
        headers={"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    opener=build_opener(ProxyHandler({}),HTTPSHandler(context=ctx))
    try:
        with opener.open(req,timeout=8) as res: status=res.status;res.read()
    except HTTPError as e: status=e.code;e.read()
    check(status==expect,f"back-channel logout returned expected HTTP {expect}")

def federated_logout(client):
    csrf=client.csrf
    check(bool(csrf),"federated logout has an authenticated CSRF token")
    req=Request(client.base+"/admin/api/logout",data=urlencode({"csrf":csrf}).encode(),
        headers={"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    with client.opener.open(req,timeout=10) as response:
        status=response.status
        final_url=response.geturl()
        response.read()
    check(status==200 and final_url.endswith("/dashboard"),
        "RP-initiated logout returns through the OIDC signed-out callback")

def csrfless_logout(client):
    req=Request(client.base+"/admin/api/logout",data=urlencode({"csrf":""}).encode(),
        headers={"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    try:
        with client.opener.open(req,timeout=10) as response: status=response.status
    except HTTPError as error:
        status=error.code
        error.read()
    check(status==403,"RP logout without its CSRF token is rejected")

def insecure_logout_endpoint_is_rejected(client,idp):
    req=Request(client.base+"/admin/api/logout",data=urlencode({"csrf":client.csrf}).encode(),
        headers={"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    try:
        with client.opener.open(req,timeout=10) as response:
            status=response.status
            response.read()
    except HTTPError as error:
        status=error.code
        error.read()
    check(status==502 and idp.insecure_logout_hits==0,
        "HTTP end-session metadata fails closed without contacting its endpoint")

def distributed_revocation(cwd,dll):
    with tempfile.TemporaryDirectory(prefix="gatewaycore-oidc-shared-") as td, fixture_secret_directory() as sd, backend() as upstream:
        root=Path(td)
        first,second=root/"first",root/"second"
        for node in (first,second):
            openssl_state(node,upstream)
        key,cert=make_tls(root,"shared-tls","127.0.0.1")
        idp_key,idp_cert=make_tls(root,"shared-idp","127.0.0.2")
        trust=root/"trust.pem"
        trust.write_bytes(cert.read_bytes()+idp_cert.read_bytes())
        ctx=ssl.create_default_context(cafile=str(trust))
        ports=[]
        while len(ports)<5:
            candidate=port()
            if candidate not in ports: ports.append(candidate)
        hp1,tls1,hp2,tls2,redis_port=ports
        origin1,origin2=f"https://127.0.0.1:{tls1}",f"https://127.0.0.1:{tls2}"
        for node,hp,tlsport in ((first,hp1,tls1),(second,hp2,tls2)):
            pfx=node/"secrets"/"dp.pfx"
            cmd("openssl","pkcs12","-export","-out",str(pfx),"-inkey",str(key),"-in",str(cert),
                "-passout","pass:temporary-e2e-only-password")
            pfx.chmod(0o600)
            with gateway(cwd,dll,node,hp,tlsport) as base:
                recovery=Client(base)
                recovery.bootstrap("recovery","Recovery-fixture-password!","recovery@example.invalid")
                recovery.request("POST","/admin/api/users",{"username":"operator",
                    "password":"Operator-fixture-password!","email":"operator@example.invalid","role":"Operator"})
        password=secrets.token_hex(32)
        redis_file=Path(sd)/"redis-connection"
        write_private_fixture_file(redis_file, f"127.0.0.1:{redis_port},ssl=true,sslHost=127.0.0.1,password={password}")
        redis_args=["redis-server","--bind","127.0.0.1","--port","0","--tls-port",str(redis_port),
            "--tls-cert-file",str(cert),"--tls-key-file",str(key),"--tls-ca-cert-file",str(cert),
            "--tls-auth-clients","no","--requirepass",password,"--dir",str(root),
            "--appendonly","yes","--appendfsync","always","--save",""]
        def cli(*args):
            return subprocess.run(["redis-cli","--tls","--cacert",str(cert),"-h","127.0.0.1",
                "-p",str(redis_port),*args],env=dict(os.environ,REDISCLI_AUTH=password),
                check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5).stdout.decode().strip()
        def start_redis():
            proc=subprocess.Popen(redis_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if proc.poll() is not None: raise AssertionError("TLS Redis exited")
                    try:
                        if cli("PING")=="PONG": return proc
                    except (subprocess.SubprocessError,OSError): pass
                    time.sleep(.05)
                raise AssertionError("TLS Redis failed to start")
            except BaseException:
                proc.terminate();proc.wait(timeout=5)
                raise
        def stop_redis(proc):
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=5)
                except subprocess.TimeoutExpired: proc.kill();proc.wait(timeout=5)
        with Idp(root,origin1,idp_key,idp_cert) as idp:
            configs=[]
            secret=Path(sd)/"shared-secret"
            write_private_fixture_file(secret, idp.secret)
            for node,origin in ((first,origin1),(second,origin2)):
                config=node/"oidc.json"
                config.write_text(json.dumps({"Issuer":idp.issuer,"ClientId":idp.client,
                    "ClientSecretFile":str(secret),"ManagementOrigin":origin,"RequiredAcr":"urn:fixture:fido",
                    "RequiredAmr":"fido2","BreakGlassUsername":"recovery","Accounts":[{"Subject":"operator-subject",
                    "Username":"operator","Group":"gateway-operators","Role":"Operator"}]}))
                config.chmod(0o600);configs.append(config)
            cutoff_key="gatewaycore:oidc:cutoff:v1:"+hashlib.sha256(
                (idp.issuer+"\n"+idp.client+"\noperator-subject").encode()).hexdigest().upper()
            redis_proc=start_redis()
            try:
                check(cli("SET",cutoff_key,"0","NX")=="OK","explicit shared cutoff initialization")
                shared={"SSL_CERT_FILE":str(trust),"GATEWAY_OIDC_REVOCATION_REDIS_FILE":str(redis_file)}
                with patch.dict(os.environ,dict(shared,GATEWAY_OIDC_CONFIG_FILE=str(configs[0]))), gateway(cwd,dll,first,hp1,tls1):
                    with patch.dict(os.environ,dict(shared,GATEWAY_OIDC_CONFIG_FILE=str(configs[1]))), gateway(cwd,dll,second,hp2,tls2):
                        idp.gateway_origin=origin1
                        a,_=browser(origin1,ctx);a.request("GET","/admin/oidc/start")
                        idp.gateway_origin=origin2
                        b,_=browser(origin2,ctx);b.request("GET","/admin/oidc/start")
                        check(a.session()["authenticated"] and b.session()["authenticated"],
                            "two independent shipping gateways establish federated sessions")
                        inventory=first/"state"/"inventory.json"
                        a.request("POST","/admin/api/inventory",{"id":"shared-fixture","name":"Shared fixture",
                            "type":"Service","address":"fixture.example.invalid","notes":"no external collector"})
                        before=inventory.read_bytes()
                        notice,stamp=idp.logout_notice()
                        backchannel(origin1,ctx,notice,200)
                        a.request("DELETE","/admin/api/inventory/shared-fixture",expect=401)
                        check(inventory.read_bytes()==before,"revoked federated operator cannot mutate inventory without external collector")
                        check(not a.session()["authenticated"] and not b.session()["authenticated"],
                            "one provider notice revokes both management replicas")
                        idp.auth_override=stamp
                        stale,_=browser(origin2,ctx);stale.request("GET","/admin/oidc/start",expect=403)
                        check(not stale.session()["authenticated"],"shared authority rejects stale callback on other replica")
                        idp.auth_override=None
                        while int(time.time())<=stamp: time.sleep(.05)
                        fresh,_=browser(origin2,ctx);fresh.request("GET","/admin/oidc/start")
                        backchannel(origin2,ctx,notice,200)
                        check(fresh.session()["authenticated"],"late replay on second replica preserves newer authentication")
                        check(cli("GET",cutoff_key)==str(stamp),"shared cutoff persisted monotonically")
                        # Simulate an unsafe stale restore while both running
                        # nodes have observed the newer cutoff. Never permit
                        # fresh login or a replay to repair an older authority.
                        check(cli("SET",cutoff_key,"0")=="OK","stale authority rollback fixture")
                        check(not fresh.session()["authenticated"],"observed cutoff rollback denies existing session")
                        backchannel(origin1,ctx,notice,503)
                        backchannel(origin2,ctx,notice,503)
                        check(cli("GET",cutoff_key)=="0","rejected replay does not overwrite rolled-back cutoff")
                        rollback_browser,_=browser(origin2,ctx)
                        rollback_browser.request("GET","/admin/oidc/start",expect=403)
                        check(not rollback_browser.session()["authenticated"],"rolled-back authority denies fresh callback")
                        # Explicitly restore the exact known good cutoff in the
                        # disposable fixture only; never auto-repair production.
                        check(cli("SET",cutoff_key,str(stamp))=="OK","fixture restores known cutoff")
                        fresh,_=browser(origin2,ctx);fresh.request("GET","/admin/oidc/start")
                        check(fresh.session()["authenticated"],"known cutoff restoration permits fresh authentication")
                        stop_redis(redis_proc)
                        check(not fresh.session()["authenticated"],"authority outage denies existing federated cookie")
                        backchannel(origin1,ctx,notice,503)
                        redis_proc=start_redis()
                        check(cli("GET",cutoff_key)==str(stamp),"authority restart recovers durable cutoff")
                        # Multiplexers reconnect independently. Check that each
                        # actually accepts the same signed, idempotent notice
                        # before attempting a new browser login (no login retry).
                        for origin in (origin1,origin2):
                            deadline=time.monotonic()+15
                            while True:
                                try:
                                    backchannel(origin,ctx,notice,200);break
                                except AssertionError:
                                    if time.monotonic()>=deadline: raise
                                    time.sleep(.25)
                        fresh2,_=browser(origin2,ctx);fresh2.request("GET","/admin/oidc/start")
                        check(fresh2.session()["authenticated"],"fresh authentication after durable authority recovery")
                        cli("DEL",cutoff_key)
                        check(not fresh2.session()["authenticated"],"missing authority record denies cookie")
                        backchannel(origin1,ctx,notice,503)
                        check(cli("EXISTS",cutoff_key)=="0","missing cutoff is never recreated implicitly")
            finally: stop_redis(redis_proc)
    print("DISTRIBUTED_OIDC_REVOCATION_HTTPS_SUCCESS",flush=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("control-center"))
    args=parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("CI")!="true":
        raise SystemExit("Disposable GitHub Actions CI only")
    cwd=args.root.resolve()
    dll=cwd/"bin/Release/net10.0/GatewayCoreYarp.dll"
    with tempfile.TemporaryDirectory(prefix="gatewaycore-oidc-") as td, fixture_secret_directory() as sd, backend() as upstream:
        root=Path(td)
        openssl_state(root,upstream)
        admin_key,admin_cert=make_tls(root,"admin","127.0.0.1")
        idp_key,idp_cert=make_tls(root,"idp","127.0.0.2")
        pfx=root/"secrets"/"dp.pfx"
        cmd("openssl","pkcs12","-export","-out",str(pfx),"-inkey",str(admin_key),"-in",str(admin_cert),
            "-passout","pass:temporary-e2e-only-password")
        pfx.chmod(0o600)
        trust=root/"trusted.pem"
        trust.write_bytes(admin_cert.read_bytes()+idp_cert.read_bytes())
        ctx=ssl.create_default_context(cafile=str(trust))
        hp,tlsport=port(),port()
        while hp==tlsport: tlsport=port()
        origin=f"https://127.0.0.1:{tlsport}"
        with gateway(cwd,dll,root,hp,tlsport) as base:
            recovery=Client(base)
            recovery.bootstrap("recovery","Recovery-fixture-password!","recovery@example.invalid")
            recovery.request("POST","/admin/api/users",{"username":"operator","password":"Operator-fixture-password!",
                "email":"operator@example.invalid","role":"Operator"})
        with Idp(root,origin,idp_key,idp_cert) as idp:
            config=root/"oidc.json"
            secret=Path(sd)/"client-secret"
            write_private_fixture_file(secret, idp.secret)
            # ClientSecretFile is a path reference, not the secret value.
            config.write_text(json.dumps({"Issuer":idp.issuer,"ClientId":idp.client,"ClientSecretFile":str(secret),
                "ManagementOrigin":origin,"RequiredAcr":"urn:fixture:fido","RequiredAmr":"fido2",
                "BreakGlassUsername":"recovery","Accounts":[{"Subject":"operator-subject",
                   "Username":"operator","Group":"gateway-operators","Role":"Operator"}]}))
            for path in (config,secret): path.chmod(0o600)
            with patch.dict(os.environ,{"GATEWAY_OIDC_CONFIG_FILE":str(config),"SSL_CERT_FILE":str(trust)}):
                with gateway(cwd,dll,root,hp,tlsport) as base:
                    a,_=browser(origin,ctx)
                    check(a.request("GET","/admin/api/auth-methods")["enterpriseOidc"],"enterprise SSO announced on management origin")
                    check(Client(base).request("GET","/admin/api/session",expect=403) is not None,"plaintext management fenced")
                    a.request("POST","/admin/api/login",{"username":"operator","password":"Operator-fixture-password!","provider":"local"},expect=403)
                    idp.mode="valid"
                    admin,jar=browser(origin,ctx)
                    admin.request("GET","/admin/oidc/start")
                    user=admin.session()
                    check(user["authenticated"] and user["username"]=="operator" and user["role"]=="Operator",
                        "native OIDC callback completes PKCE, authenticates mapped subject and ignores privileged IdP role")
                    check(idp.exchanges==1 and any(c.name=="GatewayCoreYarpAdmin" and c.secure for c in jar),
                        "real token exchange and secure local session cookie")
                    check(user["federatedOidc"],"authenticated session identifies its federated logout mode")
                    admin.request("GET","/admin/api/users",expect=403)
                    csrfless_logout(admin)
                    check(admin.session()["authenticated"],"CSRF rejection preserves the current federated session")
                    federated_logout(admin)
                    check(len(idp.logout_requests)==1 and
                          idp.logout_requests[0]["client_id"]==idp.client and
                          idp.logout_requests[0]["post_logout_redirect_uri"]==origin+"/admin/oidc/signed-out" and
                          "id_token_hint" not in idp.logout_requests[0],
                          "logout sends registered client and exact callback without persisting ID tokens")
                    check(not admin.session()["authenticated"],"local federated-session logout invalidates browser cookie")
                    for mode in ("tampered-state","nonce","issuer","audience","mfa","group"):
                        idp.mode=mode
                        a,_=browser(origin,ctx)
                        a.request("GET","/admin/oidc/start",expect=403)
                        check(not a.session()["authenticated"],"native OIDC rejects "+mode)
                    # 8 rate-limited starts/login requests are intentional;
                    # restart to exercise signature/lifetime without changing the gate.
                with gateway(cwd,dll,root,hp,tlsport):
                    for mode in ("expired","signature"):
                        idp.mode=mode
                        a,_=browser(origin,ctx)
                        a.request("GET","/admin/oidc/start",expect=403)
                        check(not a.session()["authenticated"],"native OIDC rejects "+mode)
                    idp.mode="valid"
                    original,old_jar=browser(origin,ctx)
                    original.request("GET","/admin/oidc/start")
                    check(original.session()["authenticated"],"real session before provider revocation")
                    for mode in ("issuer","audience","nonce","stale","events","subject","jti","signature",
                                 "typ-jwt","typ-application","typ-case","typ-other"):
                        forged,_=idp.logout_notice(mode)
                        backchannel(origin,ctx,forged,400)
                        check(original.session()["authenticated"],"invalid logout cannot revoke session: "+mode)
                    notice,stamp=idp.logout_notice()
                    audit_path=root/"state"/"admin-audit.jsonl"
                    audit_backup=root/"admin-audit.saved"
                    had_audit=audit_path.exists()
                    if had_audit: audit_path.rename(audit_backup)
                    audit_path.mkdir()
                    try:
                        backchannel(origin,ctx,notice,503)
                    finally:
                        shutil.rmtree(audit_path)
                        if had_audit: audit_backup.rename(audit_path)
                        else: audit_path.touch()
                    backchannel(origin,ctx,notice,200)
                    audit_rows=[json.loads(line) for line in audit_path.read_text(encoding="utf8").splitlines()]
                    recorded=[row for row in audit_rows if row.get("action")=="OIDC_BACKCHANNEL_LOGOUT" and
                              row.get("details",{}).get("revokedBefore")==stamp]
                    check(len(recorded)==1,"retry durably records logout after an audit failure before acknowledging it")
                    check(not original.session()["authenticated"],"valid IdP notice revokes next authenticated request")
                    absent_typ,_=idp.logout_notice("typ-absent",issued=stamp)
                    backchannel(origin,ctx,absent_typ,200)
                    check(not original.session()["authenticated"],"valid logout token without typ is accepted")
                    idp.auth_override=stamp
                    stale,_=browser(origin,ctx)
                    stale.request("GET","/admin/oidc/start",expect=403)
                    check(not stale.session()["authenticated"],"old authentication cannot establish session after provider logout")
                    idp.auth_override=None
                    while int(time.time())<=stamp: time.sleep(.05)
                    fresh,_=browser(origin,ctx)
                    fresh.request("GET","/admin/oidc/start")
                    check(fresh.session()["authenticated"],"fresh authentication after revocation succeeds")
                    backchannel(origin,ctx,notice,200)
                    check(fresh.session()["authenticated"],"replayed logout cannot revoke newer session")
                with gateway(cwd,dll,root,hp,tlsport):
                    check(fresh.session()["authenticated"],"new session survives process restart")
                    backchannel(origin,ctx,notice,200)
                    check(fresh.session()["authenticated"],"persisted cutoff fences logout replay across restart")
                    idp.auth_override=stamp
                    stale,_=browser(origin,ctx)
                    stale.request("GET","/admin/oidc/start",expect=403)
                    check(not stale.session()["authenticated"],"persisted cutoff rejects old authentication after restart")
                    idp.auth_override=None
                # Restart with a fresh discovery cache advertising an HTTP
                # end-session URI. The gateway must refuse it before the
                # browser or server contacts that endpoint.
                idp.end_session_endpoint=idp.insecure_logout_endpoint
                bad_hp,bad_tlsport=port(),port()
                while bad_hp==bad_tlsport: bad_tlsport=port()
                bad_origin=f"https://127.0.0.1:{bad_tlsport}"
                idp.gateway_origin=bad_origin
                oidc_config=json.loads(config.read_text())
                oidc_config["ManagementOrigin"]=bad_origin
                config.write_text(json.dumps(oidc_config))
                config.chmod(0o600)
                with gateway(cwd,dll,root,bad_hp,bad_tlsport):
                    bad_admin,_=browser(bad_origin,ctx)
                    bad_admin.request("GET","/admin/oidc/start")
                    check(bad_admin.session()["authenticated"],
                        "HTTP end-session fixture establishes an otherwise valid OIDC session")
                    insecure_logout_endpoint_is_rejected(bad_admin,idp)
            print("ENTERPRISE_OIDC_HTTPS_SUCCESS",flush=True)
    distributed_revocation(cwd,dll)

if __name__=="__main__": main()
