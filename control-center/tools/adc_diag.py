#!/usr/bin/env python3
"""Interactive, read-only GatewayCore ADC diagnostics; Python 3 stdlib only."""
import argparse
import getpass
import http.cookiejar
import json
import math
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings

LIMIT = 4 * 1024 * 1024
API = "/admin/api/"


class DiagnosticError(Exception):
    pass


def origin(value):
    try:
        if any(ord(c) < 33 or ord(c) > 126 for c in value) or "\\" in value:
            raise ValueError()
        u = urllib.parse.urlsplit(value)
        if (u.scheme != "https" or not u.hostname or u.username is not None
                or u.password is not None or u.path not in ("", "/")
                or u.query or u.fragment or not (1 <= (u.port or 443) <= 65535)):
            raise ValueError()
        return "https://" + u.netloc
    except ValueError:
        raise DiagnosticError("Use an HTTPS management origin without credentials, path or query.") from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise DiagnosticError("Management redirect refused; use the exact HTTPS origin.")


class Client:
    def __init__(self, url, ca_file=None):
        self.base = origin(url)
        context = ssl.create_default_context(cafile=ca_file)
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(self.jar))

    def request(self, name, payload=None, csrf=None):
        # Fixed destinations only: no user-supplied request paths.
        if name not in {"login", "login/verify", "session", "privacy/accept",
                        "state", "metrics", "virtual-servers", "logout"}:
            raise DiagnosticError("Unknown diagnostic endpoint.")
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(payload).encode("utf-8")
        if csrf is not None:
            headers["X-CSRF-Token"] = csrf
        try:
            req = urllib.request.Request(self.base + API + name, data=body, headers=headers)
            with self.opener.open(req, timeout=15) as response:
                if response.headers.get_content_type() != "application/json":
                    raise DiagnosticError("Unexpected management content type.")
                raw = response.read(LIMIT + 1)
                if len(raw) > LIMIT:
                    raise DiagnosticError("Management response exceeds diagnostic limit.")
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise DiagnosticError("Unexpected management response shape.")
                return result
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            raise DiagnosticError(f"Management API rejected {name} (HTTP {code}).") from None
        except (OSError, ValueError, UnicodeError) as exc:
            raise DiagnosticError("Management request failed (TLS, network or invalid JSON).") from None

    def clear(self):
        self.jar.clear()


def count(mapping, key):
    obj = mapping.get(key)
    if not isinstance(obj, dict):
        raise DiagnosticError("Unexpected configuration snapshot schema.")
    return len(obj)


def number(mapping, key, integer=True):
    value = mapping.get(key)
    if integer:
        if type(value) is not int or value < 0:
            raise DiagnosticError("Unexpected metrics schema.")
    elif type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise DiagnosticError("Unexpected metrics schema.")
    return value


def summarize(state, metrics, virtual):
    # Do not expose route metadata, origins, names, cookies, tokens or secrets.
    keys = ("routes", "clusters", "disabled", "monitorProfiles", "realServers", "serviceGroups")
    inventory = {key: count(state, key) for key in keys}
    services = virtual.get("services")
    if not isinstance(services, list):
        raise DiagnosticError("Unexpected virtual server schema.")
    inventory["virtualServices"] = len(services)
    counters = {key: number(metrics, key) for key in
                ("totalRequests", "success2xx", "clientErrors4xx", "serverErrors5xx")}
    counters["meanDurationMs"] = number(metrics, "meanDurationMs", integer=False)
    total = counters["totalRequests"]
    # Counters are sampled independently; do not invent a consistent rate.
    return {"inventory": inventory, "localCounters": counters,
            "scope": "Configured inventory and local process counters, not fleet health; counters reset on restart.",
            "hasTraffic": total > 0}


def safe_notice(text):
    if not isinstance(text, str) or not text or len(text) > 32000:
        raise DiagnosticError("Missing or invalid privacy notice.")
    return "".join(c if c in "\n\t" or (c.isprintable() and c not in "\x1b") else "?" for c in text)


def collect(client, username, password, provider, prompt=input, secret=getpass.getpass, notice=print):
    csrf = None
    try:
        login = client.request("login", {"username": username, "password": password, "provider": provider})
        if login.get("otpRequired") is True:
            challenge = login.get("challengeId")
            if not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-fA-F]{48}", challenge):
                raise DiagnosticError("Invalid OTP challenge.")
            code = secret("Email OTP: ")
            if not re.fullmatch(r"[0-9]{6}", code):
                raise DiagnosticError("OTP must contain six digits.")
            login = client.request("login/verify", {"challengeId": challenge, "code": code})
        if login.get("authenticated") is not True:
            raise DiagnosticError("Authentication did not complete.")
        session = client.request("session")
        token = session.get("csrf")
        if session.get("authenticated") is not True or not isinstance(token, str) or not token:
            raise DiagnosticError("Authenticated session could not be verified.")
        csrf = token
        if session.get("privacyAccepted") is not True:
            version = session.get("privacyVersion")
            if not isinstance(version, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", version):
                raise DiagnosticError("Invalid privacy notice version.")
            notice(safe_notice(session.get("privacyText")))
            if prompt("Type ACCEPT to acknowledge this notice (anything else declines): ") != "ACCEPT":
                raise DiagnosticError("Privacy notice declined; no diagnostics retrieved.")
            accepted = client.request("privacy/accept", {"version": version}, csrf)
            if accepted.get("accepted") is not True or accepted.get("version") != version:
                raise DiagnosticError("Privacy acknowledgement failed.")
        return summarize(client.request("state"), client.request("metrics"), client.request("virtual-servers"))
    finally:
        try:
            if csrf:
                client.request("logout", {}, csrf)
        except DiagnosticError:
            print("Warning: server logout could not be confirmed; local cookies discarded.", file=sys.stderr)
        finally:
            client.clear()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("origin", help="Exact HTTPS management origin")
    parser.add_argument("--ca-file", help="Optional PEM trust bundle for private CA")
    parser.add_argument("--provider", choices=("local", "directory"), default="local")
    args = parser.parse_args()
    try:
        if not sys.stdin.isatty():
            raise DiagnosticError("Interactive terminal required; credentials are never accepted as arguments.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            client = Client(args.origin, args.ca_file)
            username = input("Username: ")
            password = getpass.getpass("Password: ")
            result = collect(client, username, password, args.provider)
        print(json.dumps(result, indent=2, allow_nan=False))
        return 0
    except (DiagnosticError, getpass.GetPassWarning, EOFError, KeyboardInterrupt, OSError) as exc:
        print(str(exc) if isinstance(exc, DiagnosticError) else "Diagnostics aborted.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
