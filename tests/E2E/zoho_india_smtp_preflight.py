#!/usr/bin/env python3
"""Opt-in, credential-free Zoho India SMTP preflight from an approved test host.

This does NOT authenticate, send mail, use credentials, or validate delivery.
Only run manually on the server that will be able to connect to Zoho.
No TLS bypass and no secrets read from environment or arguments.
"""
import argparse
import json
import smtplib
import ssl
import sys

HOSTS={"smtp.zoho.in","smtppro.zoho.in"}

def main():
    parser=argparse.ArgumentParser(description="Credential-free Zoho India SMTP STARTTLS handshake")
    parser.add_argument("--host",required=True,choices=sorted(HOSTS))
    parser.add_argument("--port",type=int,default=587,choices=[587])
    args=parser.parse_args()
    try:
        with smtplib.SMTP(args.host,args.port,timeout=12) as client:
            code,_=client.ehlo()
            if code!=250 or not client.has_extn("starttls"):
                raise RuntimeError("SMTP server did not advertise required STARTTLS")
            client.starttls(context=ssl.create_default_context())
            code,_=client.ehlo()
            if code!=250:
                raise RuntimeError("SMTP server did not accept post-TLS EHLO")
            auth=client.esmtp_features.get("auth","").split()
            if not auth:
                raise RuntimeError("SMTP server did not advertise authentication after STARTTLS")
            print(json.dumps({"result":"TCP_TLS_EHLO_VERIFIED","host":args.host,"port":args.port,
                "starttls":True,"certificateValidated":True,
                "authAdvertised":True,"authenticated":False,"messageSent":False}))
    except Exception as exc:
        print(json.dumps({"result":"NO_GO","host":args.host,"port":args.port,
                          "errorCategory":type(exc).__name__,
                          "authenticated":False,"messageSent":False}),file=sys.stderr)
        raise SystemExit(1)

if __name__=="__main__":
    main()
