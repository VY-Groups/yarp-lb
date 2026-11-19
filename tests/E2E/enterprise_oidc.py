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
        self.codes={}
        self.exchanges=0
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
        tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(str(cert),str(tlskey))
        self.server.socket=tls.wrap_socket(self.server.socket,server_side=True)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True)
    def __enter__(self):
        self.thread.start()
        return self
    def __exit__(self,*_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

def browser(origin,ctx):
    jar=CookieJar()
    client=Client(origin)
    client.opener=build_opener(ProxyHandler({}), HTTPSHandler(context=ctx),HTTPCookieProcessor(jar))
    return client,jar

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--root",type=Path,default=Path("control-center"))
    args=parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("CI")!="true":
        raise SystemExit("Disposable GitHub Actions CI only")
    cwd=args.root.resolve()
    dll=cwd/"bin/Release/net10.0/GatewayCoreYarp.dll"
    with tempfile.TemporaryDirectory(prefix="gatewaycore-oidc-") as td, backend() as upstream:
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
            secret=root/"client-secret"
            secret.write_text(idp.secret)
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
                    admin.request("GET","/admin/api/users",expect=403)
                    admin.request("POST","/admin/api/logout",{})
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
            print("ENTERPRISE_OIDC_HTTPS_SUCCESS",flush=True)

if __name__=="__main__": main()
