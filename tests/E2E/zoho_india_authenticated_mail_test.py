#!/usr/bin/env python3
"""One-shot Zoho India SMTP delivery acceptance; runs on the operator's host.

Uses a password entered into a non-echoing prompt. Never accepts password as
an argument, writes it to disk, or sends it to GitHub. Only sends to the same
authorized mailbox. This is an optional external integration test, not CI.
"""
import argparse
import getpass
import json
import smtplib
import ssl
import sys
import uuid
from email.message import EmailMessage

ALLOWED_HOSTS = ("smtp.zoho.in", "smtppro.zoho.in")


def main():
    parser = argparse.ArgumentParser(description="One-shot, strict-STARTTLS Zoho India SMTP delivery test")
    parser.add_argument("--host", choices=ALLOWED_HOSTS, required=True,
                        help="Use the exact hostname in Zoho Server Configuration Details")
    parser.add_argument("--username", required=True,
                        help="Full Zoho account address; mail is sent ONLY to this address")
    parser.add_argument("--send-to-self", action="store_true",
                        help="Explicit permission to send a single test message to yourself")
    args = parser.parse_args()

    if not args.send_to_self:
        parser.error("--send-to-self is required; the script never sends mail implicitly")
    email_address = args.username.strip()
    if not email_address or "@" not in email_address or any(c in email_address for c in "\r\n\x00"):
        parser.error("Provide one valid email address")
    if email_address != args.username:
        parser.error("Account address must not contain surrounding whitespace")

    password = getpass.getpass("Zoho app-specific SMTP password (hidden): ")
    if not password:
        raise SystemExit("NO-GO: empty password; no email sent")
    token = uuid.uuid4().hex[:12]
    msg = EmailMessage()
    msg["From"] = email_address
    msg["To"] = email_address
    msg["Subject"] = "GatewayCore authorized SMTP test " + token
    msg.set_content("This is one authorized GatewayCore test message to your own mailbox. Reference " + token)
    try:
        with smtplib.SMTP(args.host, 587, timeout=15) as client:
            client.ehlo()
            if not client.has_extn("STARTTLS"):
                raise RuntimeError("SMTP_STARTTLS_NOT_ADVERTISED")
            # Strict platform-trusted certificate + hostname verification;
            # no insecure SSL context, no fallbacks to plaintext or port 465.
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
            if not client.has_extn("AUTH"):
                raise RuntimeError("SMTP_AUTH_NOT_ADVERTISED")
            client.login(email_address, password)
            refused = client.send_message(msg)
            if refused:
                raise RuntimeError("SMTP_RECIPIENT_REFUSED")
        print(json.dumps({
            "status": "SMTP_ACCEPTED_NOT_INBOX_CONFIRMED",
            "host": args.host, "port": 587, "starttls": True,
            "authenticated": True, "accepted": True, "reference": token,
            "nextStep": "Open mail.zoho.in and check that the matching subject arrived"
        }))
    except (OSError, ssl.SSLError, smtplib.SMTPException, RuntimeError) as exc:
        # Do not print potentially identifying SMTP exception messages or
        # server banners: some servers echo authentication information.
        print(json.dumps({"status": "NO_GO", "stage": type(exc).__name__,
                          "smtpCode": getattr(exc, "smtp_code", None),
                          "authenticated": False, "delivered": False}), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
