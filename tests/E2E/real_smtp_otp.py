#!/usr/bin/env python3
"""Real SMTP STARTTLS + authenticated delivery + live GatewayCore OTP login.

Runs only in disposable GitHub CI against a temporary in-process local SMTP
relay with a self-generated CA. Does NOT access Zoho or user mail credentials.
"""
from __future__ import annotations
from contextlib import contextmanager
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import email
import json
import os
import re
import smtplib
import ssl
import subprocess
import tempfile
import time
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import AuthResult, LoginPassword
from real_control_center import Client, check, gateway, openssl_state, port

MAIL_USER="smtp-fixture@example.invalid"
MAIL_PASSWORD="CI-ONLY-test-app-password-not-real"
ADMIN_PASSWORD="Temporary-Admin-Test-Pass-2219!"

class Mailbox:
    def __init__(self):
        self.messages=[]
        self.auth_calls=0
    def authenticate(self,server,session,envelope,mechanism,auth_data):
        # aiosmtpd exposes AUTH after STARTTLS only; never permit plaintext AUTH.
        if not isinstance(auth_data,LoginPassword):
            return AuthResult(success=False)
        self.auth_calls+=1
        ok=(auth_data.login==MAIL_USER.encode() and
            auth_data.password==MAIL_PASSWORD.encode() and
            bool(getattr(session,"ssl",False)))
        return AuthResult(success=ok)
    async def handle_DATA(self,server,session,envelope):
        if not bool(getattr(session,"ssl",False)):
            return "530 Must issue STARTTLS first"
        self.messages.append(email.message_from_bytes(envelope.content))
        return "250 Accepted in disposable CI mailbox"

@contextmanager
def local_smtp(root:Path,port_number:int):
    certdir=root/"smtp-keys"
    certdir.mkdir(mode=0o700)
    ca=certdir/"ca.pem"
    cakey=certdir/"ca.key"
    key=certdir/"server.key"
    csr=certdir/"server.csr"
    leaf=certdir/"server.pem"
    ext=certdir/"server.ext"
    class CRLResponder(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path!="/ca.crl":
                self.send_error(404)
                return
            payload=(certdir/"ca.crl").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type","application/pkix-crl")
            self.send_header("Content-Length",str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        def log_message(self,*_): pass
    responder=ThreadingHTTPServer(("127.0.0.1",0),CRLResponder)
    responder_thread=Thread(target=responder.serve_forever,daemon=True)
    responder_thread.start()
    crlport=responder.server_address[1]
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                   "extendedKeyUsage=serverAuth\n"
                   "keyUsage=digitalSignature,keyEncipherment\n"
                   "basicConstraints=critical,CA:FALSE\n"
                   f"crlDistributionPoints=URI:http://127.0.0.1:{crlport}/ca.crl\n")
    def openssl(*args):
        subprocess.run(["openssl",*args],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    openssl("req","-x509","-newkey","rsa:3072","-nodes","-days","2",
            "-subj","/CN=Temporary GatewayCore CI CA",
            "-keyout",str(cakey),"-out",str(ca))
    openssl("req","-newkey","rsa:3072","-nodes",
            "-subj","/CN=localhost","-keyout",str(key),"-out",str(csr))
    openssl("x509","-req","-in",str(csr),"-CA",str(ca),"-CAkey",str(cakey),
            "-CAcreateserial","-out",str(leaf),"-days","2","-extfile",str(ext))
    # Supply a real signed, short-lived EMPTY CRL so clients can verify
    # revocation instead of requiring an unsafe "ignore revocation" flag.
    (certdir/"index.txt").write_text("")
    (certdir/"serial").write_text("1000\n")
    (certdir/"crlnumber").write_text("1000\n")
    (certdir/"newcerts").mkdir()
    ca_cfg=certdir/"openssl-ca.cnf"
    ca_cfg.write_text(f"""[ca]
default_ca = CA_default
[CA_default]
dir = {certdir}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.pem
private_key = $dir/ca.key
serial = $dir/serial
crlnumber = $dir/crlnumber
default_md = sha256
default_crl_days = 2
policy = policy_any
[policy_any]
commonName = supplied
""")
    openssl("ca","-gencrl","-config",str(ca_cfg),"-out",str(certdir/"ca-crl.pem"),
            "-batch")
    openssl("crl","-in",str(certdir/"ca-crl.pem"),"-outform","DER","-out",
            str(certdir/"ca.crl"))
    key.chmod(0o600)
    cakey.chmod(0o600)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version=ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(leaf),str(key))
    mailbox=Mailbox()
    ctrl=Controller(mailbox,hostname="127.0.0.1",port=port_number,
                    tls_context=context,require_starttls=True,
                    auth_required=True,auth_require_tls=True,
                    authenticator=mailbox.authenticate,ready_timeout=5.0)
    ctrl.start()
    try:
        yield mailbox,ca
    finally:
        ctrl.stop()
        responder.shutdown()
        responder.server_close()
        responder_thread.join(timeout=3)

def plaintext_mail(message):
    parts=[]
    for part in message.walk():
        if part.get_content_maintype()=="text":
            raw=part.get_payload(decode=True)
            if raw is not None:
                parts.append(raw.decode("utf8","replace"))
    return "\n".join(parts)

def acceptance(root:Path):
    appdir=(Path(__file__).resolve().parents[2]/"control-center").resolve()
    dll=appdir/"bin"/"Release"/"net10.0"/"GatewayCoreYarp.dll"
    if not dll.is_file():
        raise AssertionError("Build shipping Control Center before running acceptance")
    gatewayport,mailport,originport=port(),port(),port()
    openssl_state(root,originport)
    with local_smtp(root,mailport) as (mailbox,ca):
        # Probe the fixture with a strict, real Python STARTTLS SMTP client
        # first. This distinguishes fixture defects from product defects.
        with smtplib.SMTP("127.0.0.1",mailport,timeout=8) as client:
            client.ehlo()
            client.starttls(context=ssl.create_default_context(cafile=str(ca)))
            client.ehlo()
            client.login(MAIL_USER,MAIL_PASSWORD)
            check(True,"independent strict client validates TLS and AUTH on local SMTP")
        # .NET reads platform trust; the disposable Ubuntu runner temporarily
        # trusts ONLY our freshly generated CI CA. No certificate bypass.
        # This MUST never run on a user's workstation or physical server.
        trust=Path("/usr/local/share/ca-certificates/gatewaycore-e2e-local.crt")
        subprocess.run(["sudo","install","-m","0644",str(ca),str(trust)],check=True)
        subprocess.run(["sudo","update-ca-certificates"],check=True,
                       stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        previous=os.environ.get("SSL_CERT_FILE")
        os.environ["SSL_CERT_FILE"]=str(ca)
        try:
            with gateway(appdir,dll,root,gatewayport) as base:
                admin=Client(base)
                admin.bootstrap("mail_admin",ADMIN_PASSWORD,"admin@example.invalid")
                admin.request("GET","/admin/api/mail")
                config={
                    "enabled":False,"host":"127.0.0.1","port":mailport,
                    "from":"admin@example.invalid","username":MAIL_USER,
                    "password":MAIL_PASSWORD,"startTls":True
                }
                admin.request("POST","/admin/api/mail",config)
                saved=admin.request("GET","/admin/api/mail")
                check(saved["passwordConfigured"] and not saved["enabled"],
                      "SMTP settings saved with encrypted credential and OTP disabled")
                raw=(root/"state"/"mail-settings.json").read_text()
                check(MAIL_PASSWORD not in raw and MAIL_USER in raw,
                      "SMTP credential encrypted at rest in protected production-mode state")
                # This exercises .NET SmtpClient, authenticated STARTTLS,
                # platform chain/name validation and actual message receipt.
                tested=admin.request("POST","/admin/api/mail/test",{})
                check(tested["tested"] and len(mailbox.messages)==1,
                      "real STARTTLS SMTP delivery accepted and captured by CI mailbox")
                check(mailbox.auth_calls>0,"authenticated SMTP sent after STARTTLS")
                check("SMTP test" in mailbox.messages[-1]["Subject"],
                      "SMTP test message delivered with expected subject")
                # Existing encrypted credential retained; fingerprint must match
                config["password"]=""
                config["enabled"]=True
                admin.request("POST","/admin/api/mail",config)
                check(admin.request("GET","/admin/api/mail")["enabled"],
                      "verified SMTP allows OTP only with same settings")
                admin.request("POST","/admin/api/logout",{})
                request=admin.request("POST","/admin/api/login",{
                    "username":"mail_admin","password":ADMIN_PASSWORD,"provider":"local"})
                check(request.get("otpRequired") and len(mailbox.messages)==2,
                      "login requests real email OTP after authenticated STARTTLS delivery")
                check("sign-in code" in mailbox.messages[-1]["Subject"],
                      "OTP message delivered with expected subject")
                content=plaintext_mail(mailbox.messages[-1])
                codes=re.findall(r"\b[0-9]{6}\b",content)
                check(len(codes)==1,"captured exactly one 6-digit test OTP")
                admin.request("POST","/admin/api/login/verify",{
                    "challengeId":request["challengeId"],"code":"999999" if codes[0]!="999999" else "000000"
                },expect=401)
                admin.request("POST","/admin/api/login/verify",{
                    "challengeId":request["challengeId"],"code":codes[0]
                })
                check(admin.session()["authenticated"],
                      "correct 6-digit OTP completes real cookie login after wrong-code rejection")
                return {"smtpStartTls":"pass","smtpAuthentication":"pass",
                        "smtpCertificateValidation":"pass",
                        "smtpDeliveryLocalCI":"pass","otpSignIn":"pass",
                        "externalZohoDelivery":"NOT VERIFIED"}
        finally:
            if previous is None:
                os.environ.pop("SSL_CERT_FILE",None)
            else:
                os.environ["SSL_CERT_FILE"]=previous
            subprocess.run(["sudo","rm","-f",str(trust)],check=True)
            subprocess.run(["sudo","update-ca-certificates"],check=True,
                           stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)

def main():
    if os.environ.get("CI")!="true" or os.environ.get("GITHUB_ACTIONS")!="true":
        raise SystemExit("Refusing SMTP E2E outside disposable GitHub Actions CI")
    with tempfile.TemporaryDirectory(prefix="gatewaycore-smtp-test-") as td:
        report=acceptance(Path(td))
    print("SMTP_E2E "+json.dumps(report,sort_keys=True),flush=True)

if __name__=="__main__":
    main()
