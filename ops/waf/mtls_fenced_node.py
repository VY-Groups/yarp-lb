#!/usr/bin/env python3
"""Mutually authenticated WAF node-side enforcement, independent of coordinator.

This is an opt-in Python library for a separately provisioned Linux WAF host.
A trusted launcher MUST verify the signed policy and reviewer approvals, pin
the local provider and independent quorum credentials, and approve each TLS
leaf. No loopback/local JSON bypass or unauthenticated management endpoint.
"""
import datetime as dt
import hashlib
import hmac
import http.client
import json
from pathlib import Path
import re
import socket
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

import rollout_controller as local
import etcd_quorum_fence as quorum

HEX = re.compile(r"[A-F0-9]{64}\Z", re.ASCII)
NODE = re.compile(r"[a-z0-9][a-z0-9_-]{1,47}\Z", re.ASCII)
ROUTE = "/v1/fenced-waf-node"
MAX_INPUT = 512
MAX_OUTPUT = 4096


def strict_json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_INPUT:
        raise ValueError("invalid bounded node control request")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate node control field")
            out[key] = value
        return out
    result = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                        parse_constant=lambda _: (_ for _ in ()).throw(
                            ValueError("nonfinite control field")))
    if type(result) is not dict:
        raise ValueError("node control body must be object")
    return result


class FencedAgent:
    """Node MUST reattest the externally held lease immediately at mutation."""

    def __init__(self, node_id, node_ids, revision, policy_sha, ruleset_sha,
                 approved_target, provider, fence, receipt_dir, *, policy_expires_utc=None):
        if (type(node_id) is not str or not NODE.fullmatch(node_id) or
                type(node_ids) is not tuple or len(node_ids) != 2 or
                node_ids != tuple(sorted(node_ids)) or node_id not in node_ids or
                any(type(n) is not str or not NODE.fullmatch(n) for n in node_ids) or
                type(revision) is not int or revision <= 0 or
                type(policy_sha) is not str or not HEX.fullmatch(policy_sha) or
                type(ruleset_sha) is not str or not HEX.fullmatch(ruleset_sha) or
                approved_target not in local.MODES or
                not callable(getattr(fence, "assert_current", None))):
            raise ValueError("unapproved fixed node deployment identity")
        if (policy_expires_utc is not None and
                (type(policy_expires_utc) is not dt.datetime or
                 policy_expires_utc.tzinfo is None or
                 policy_expires_utc <= dt.datetime.now(dt.timezone.utc))):
            raise ValueError("approved policy expiry must be valid UTC")
        self.policy_expires_utc = policy_expires_utc
        self.node_id, self.node_ids = node_id, node_ids
        self.revision, self.policy_sha = revision, policy_sha
        self.ruleset_sha, self.target = ruleset_sha, approved_target
        self.provider, self.fence = provider, fence
        self.dir = local.private_directory(Path(receipt_dir))
        self.lock = threading.Lock()
        # Every independent agent pins its own lease epoch before it starts
        # listening. No controller-supplied static approval can substitute.
        self._attest("preflight")
        before = provider.inspect()
        if (type(before) is not dict or
                before.get("mode") not in local.MODES or
                before["mode"] == approved_target or
                type(before.get("imageId")) is not str or
                not re.fullmatch(r"sha256:[a-f0-9]{64}", before["imageId"]) or
                provider.observed_rule_digest() != ruleset_sha or
                provider.image_and_config(approved_target) != before["imageId"] or
                provider.image_and_config(before["mode"]) != before["imageId"]):
            raise ValueError("unapproved WAF baseline or ruleset")
        self.baseline = before["mode"]
        self.image = before["imageId"]

    def _attest(self, phase):
        if self.fence.assert_current(self.node_ids, self.revision,
                                     self.policy_sha, phase) is not True:
            raise ValueError("independent WAF node fencing authority denied")

    def _runtime(self):
        state = self.provider.inspect()
        if (type(state) is not dict or
                state.get("imageId") != self.image or
                state.get("mode") not in (self.baseline, self.target) or
                self.provider.observed_rule_digest() != self.ruleset_sha):
            raise ValueError("node image or effective CRS changed")
        return state

    def _apply(self, mode):
        if (self.policy_expires_utc is not None and
                dt.datetime.now(dt.timezone.utc) >= self.policy_expires_utc):
            raise ValueError("WAF signed deployment policy expired")
        if mode not in (self.baseline, self.target):
            raise ValueError("unapproved WAF transition")
        stage = ("before-apply-" if mode == self.target else "rollback-") + self.node_id
        self._attest(stage)
        current = self._runtime()
        if current["mode"] == mode:
            raise ValueError("replayed WAF node mutation")
        if self.provider.image_and_config(mode) != self.image:
            raise ValueError("new WAF image differs from signed baseline")
        self.provider.smoke(current["mode"])
        # Smoke may wait for a cold container; do not trust the pre-smoke
        # lease for the later Docker mutation boundary.
        self._attest(stage)
        kind = "activate" if mode == self.target else "rollback"
        name = "rev-" + str(self.revision) + "-" + kind
        intent = self.dir / (name + ".intent")
        committed = self.dir / (name + ".receipt")
        if intent.exists() or intent.is_symlink() or committed.exists() or committed.is_symlink():
            raise ValueError("existing or unresolved WAF node transaction")
        # This record is intentionally honest about hard-kill uncertainty:
        # mutation MAY HAVE STARTED immediately after the fsynced intent.
        event = {"schemaVersion": 1, "nodeId": self.node_id,
                 "nodeIds": list(self.node_ids), "revision": self.revision,
                 "policySha256": self.policy_sha, "rulesetSha256": self.ruleset_sha,
                 "operation": kind, "mutationMayHaveStarted": True}
        local.receipt(intent, event)
        # The fsynced intent is an observable crash boundary. Recheck after
        # durable I/O and immediately before the non-idempotent provider call.
        self._attest(stage)
        self.provider.apply(mode)
        after = self._runtime()
        if after != {"mode": mode, "imageId": self.image}:
            raise ValueError("node mutation failed post-apply image/mode verification")
        self.provider.smoke(mode)
        self._attest(stage)
        local.receipt(committed, {**event, "result": "verified", "mode": mode})
        return {"mode": mode, "imageId": self.image}

    def dispatch(self, payload):
        if set(payload) == {"action"} and payload["action"] in {
                "inspect", "rule-digest"}:
            with self.lock:
                if payload["action"] == "inspect":
                    return self._runtime()
                return self.provider.observed_rule_digest()
        if set(payload) == {"action", "mode"} and payload["mode"] in local.MODES:
            with self.lock:
                action, mode = payload["action"], payload["mode"]
                if action == "config":
                    observed = self.provider.image_and_config(mode)
                    if observed != self.image:
                        raise ValueError("unapproved WAF image configuration")
                    return observed
                if action == "smoke":
                    if mode != self._runtime()["mode"]:
                        raise ValueError("cannot smoke a nonactive WAF mode")
                    self.provider.smoke(mode)
                    return True
                if action == "apply":
                    # Protect this actual host's mutation window against a
                    # second daemon/process, not merely threads in this server.
                    # The lock remains held through Docker apply, verification
                    # and durable receipt; missing lease still fails closed.
                    with local.operator_lock(self.dir):
                        return self._apply(mode)
        raise ValueError("unknown or unapproved node operation")


class BoundedTlsServer(ThreadingHTTPServer):
    """Bound every unauthenticated handshake, never handshake in accept()."""
    request_queue_size = 12
    daemon_threads = True
    allow_reuse_address = False
    max_clients = 8
    handshake_seconds = 4

    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.slots = threading.BoundedSemaphore(self.max_clients)

    def handle_error(self, *_):
        # Generic network failures must not print private operator paths or
        # policy exceptions through BaseServer's default traceback logger.
        pass

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            request.close()
            raise

    def process_request_thread(self, request, client_address):
        secured = None
        try:
            request.settimeout(self.handshake_seconds)
            secured = self.context.wrap_socket(request, server_side=True,
                                               do_handshake_on_connect=False)
            secured.do_handshake()
            secured.settimeout(15)
            super().process_request_thread(secured, client_address)
        except (OSError, ssl.SSLError, TimeoutError):
            if secured is not None:
                secured.close()
            else:
                request.close()
        finally:
            self.slots.release()


class NodeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "GatewayCoreWafNode/1"
    sys_version = ""

    def log_message(self, *_):
        pass

    def _reply(self, status, value):
        raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self):
        peer = self.connection.getpeercert(binary_form=True)
        actual = hashlib.sha256(peer or b"").hexdigest().upper()
        if not peer or not hmac.compare_digest(actual, self.server.client_pin):
            self._reply(403, {"ok": False})
            return
        lengths = self.headers.get_all("Content-Length", [])
        if (self.path != ROUTE or self.headers.get("Transfer-Encoding") is not None or
                self.headers.get("Content-Type") != "application/json" or
                len(lengths) != 1 or not lengths[0].isascii() or
                not lengths[0].isdecimal() or
                not 0 < int(lengths[0]) <= MAX_INPUT):
            self._reply(400, {"ok": False})
            return
        try:
            payload = strict_json(self.rfile.read(int(lengths[0])))
            result = self.server.agent.dispatch(payload)
            self._reply(200, {"ok": True, "nodeId": self.server.agent.node_id, "result": result})
        except Exception:
            # Never reveal a private rule, key path, device identity or payload.
            self._reply(409, {"ok": False})


def serve(agent, bind, port, ca, cert, key, client_pin, *, allow_nonloopback=False):
    if not isinstance(agent, FencedAgent):
        raise ValueError("node agent requires independently fenced runtime")
    if bind != "127.0.0.1" and not allow_nonloopback:
        raise ValueError("node listener outside loopback requires explicit opt-in")
    if type(port) is not int or not 0 <= port <= 65535 or not HEX.fullmatch(client_pin):
        raise ValueError("invalid approved network node identity")
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,
                                     cafile=quorum.canonical_file(ca))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(quorum.canonical_file(cert), quorum.private_key(key))
    srv = BoundedTlsServer((bind, port), NodeHandler)
    srv.context, srv.client_pin, srv.agent = ctx, client_pin, agent
    return srv


class RemoteNodeProvider:
    """The coordinator's no-shell, exact-operation, mutually pinned TLS adapter."""

    def __init__(self, node_id, server_url, server_pin, ca, certificate, key):
        if type(node_id) is not str or not NODE.fullmatch(node_id):
            raise ValueError("approved WAF node ID required")
        self.node_id = node_id
        u = urlsplit(server_url)
        if (u.scheme != "https" or not u.hostname or u.port is None or
                not 0 < u.port <= 65535 or u.username or u.password or
                u.path not in ("", "/") or u.query or u.fragment or
                type(server_pin) is not str or not HEX.fullmatch(server_pin)):
            raise ValueError("approved HTTPS WAF node endpoint required")
        self.host, self.port, self.server_pin = u.hostname, u.port, server_pin
        self.ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                              cafile=quorum.canonical_file(ca))
        self.ctx.check_hostname = True
        self.ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ctx.load_cert_chain(quorum.canonical_file(certificate),
                                 quorum.private_key(key))

    def _call(self, action, mode=None):
        data = {"action": action}
        if mode is not None:
            data["mode"] = mode
        raw = json.dumps(data, separators=(",", ":")).encode("ascii")
        conn = http.client.HTTPSConnection(self.host, self.port, timeout=15,
                                           context=self.ctx)
        try:
            conn.connect()
            peer = conn.sock.getpeercert(binary_form=True) if conn.sock else None
            if not peer or not hmac.compare_digest(
                    hashlib.sha256(peer).hexdigest().upper(), self.server_pin):
                raise ValueError("WAF node TLS leaf pin mismatch")
            conn.request("POST", ROUTE, raw, {"Content-Type": "application/json",
                         "Accept": "application/json", "Connection": "close"})
            resp = conn.getresponse()
            if (resp.status != 200 or
                    resp.getheader("Content-Type") != "application/json" or
                    resp.getheader("Transfer-Encoding") is not None or
                    not (resp.getheader("Content-Length") or "").isdecimal()):
                raise ValueError("remote WAF node refused operation")
            length = int(resp.getheader("Content-Length"))
            if not 0 < length <= MAX_OUTPUT:
                raise ValueError("oversized WAF node response")
            response = resp.read(MAX_OUTPUT + 1)
            if len(response) != length:
                raise ValueError("incomplete WAF node response")
            record = strict_json(response)
            if (set(record) != {"ok", "nodeId", "result"} or
                    record["ok"] is not True or record["nodeId"] != self.node_id):
                raise ValueError("untrusted WAF node response")
            return record["result"]
        finally:
            conn.close()

    def inspect(self):
        data = self._call("inspect")
        if (type(data) is not dict or set(data) != {"mode", "imageId"} or
                data["mode"] not in local.MODES or
                not isinstance(data["imageId"], str) or
                not re.fullmatch(r"sha256:[a-f0-9]{64}", data["imageId"])):
            raise ValueError("invalid remote WAF runtime attestation")
        return data

    def image_and_config(self, mode):
        observed = self._call("config", mode)
        if not isinstance(observed, str) or not re.fullmatch(
                r"sha256:[a-f0-9]{64}", observed):
            raise ValueError("invalid remote WAF configured image")
        return observed

    def observed_rule_digest(self):
        observed = self._call("rule-digest")
        if type(observed) is not str or not HEX.fullmatch(observed):
            raise ValueError("invalid remote WAF rule attestation")
        return observed

    def smoke(self, mode):
        if self._call("smoke", mode) is not True:
            raise ValueError("remote WAF smoke denied")

    def apply(self, mode):
        observed = self._call("apply", mode)
        if type(observed) is not dict or observed.get("mode") != mode:
            raise ValueError("remote WAF mutation not confirmed")
