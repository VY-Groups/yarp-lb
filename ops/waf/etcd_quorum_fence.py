#!/usr/bin/env python3
"""External etcd v3 quorum-backed WAF fencing lease *read/verifier* (#51).

An independent, separately authorized etcd writer must create and renew
a lease-backed key by CAS. This module NEVER creates, renews, deletes or
reassigns a lease. The etcd HTTP/JSON gateway must provide linearizable
reads on a real three-member quorum, with pinned mutual TLS for each member.

Supports the existing two_node_transaction.coordinate(..., fence=...) API.
A lease is pinned for all phases of ONE transaction; a replacement epoch,
expired lease, split-brain read or lost quorum refuses further mutation.
This is not a production-grade authority until real etcd 3-member partition
and remote-node enforcement evidence is independently accepted.
"""
import base64
import hashlib
import hmac
import http.client
import json
import os
import re
import ssl
import stat
import time
from urllib.parse import urlsplit

ALIAS = re.compile(r"[a-z0-9][a-z0-9_-]{2,47}\Z", re.ASCII)
HEX64 = re.compile(r"[A-F0-9]{64}\Z", re.ASCII)
DIGEST = HEX64
ID = re.compile(r"[a-z0-9][a-z0-9_-]{1,47}\Z", re.ASCII)
MAX_REPLY = 16384
MAX_VALUE = 4096
MIN_TTL = 3
MAX_TTL = 120
NONCE = re.compile(r"[a-f0-9]{32}\Z", re.ASCII)


def canonical_file(path):
    if (type(path) is not str or not path.startswith("/") or
            os.path.normpath(path) != path or os.path.realpath(path) != path):
        raise ValueError("independent TLS file path must be canonical and absolute")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError("TLS trust file must be an ordinary single-link inode")
    return path


def private_key(path):
    canonical_file(path)
    info = os.lstat(path)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("etcd mTLS private key must be owner-only")
    return path


def strict_json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_REPLY:
        raise ValueError("invalid bounded etcd response")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate etcd or lease JSON property")
            value[key] = item
        return value
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          ValueError("nonfinite etcd JSON")))


def integer(value):
    if type(value) is int:
        n = value
    elif type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value):
        n = int(value)
    else:
        raise ValueError("invalid etcd quorum integer")
    if not 0 < n <= 2**64-1:
        raise ValueError("etcd authority integer out of bounds")
    return n


def endpoint_parts(endpoint):
    if type(endpoint) is not dict or set(endpoint) != {"url", "leafSha256"}:
        raise ValueError("explicit independent etcd member identity required")
    pin = endpoint["leafSha256"]
    if type(endpoint["url"]) is not str:
        raise ValueError("etcd member endpoint URL must be a string")
    u = urlsplit(endpoint["url"])
    if (type(pin) is not str or not HEX64.fullmatch(pin) or
            u.scheme != "https" or u.username or u.password or
            not u.hostname or u.path not in ("", "/") or u.query or u.fragment or
            u.port is None or u.port <= 0):
        raise ValueError("invalid etcd TLS endpoint or leaf pin")
    return u.hostname, u.port, pin


def valid_value(raw, names, revision, policy_digest):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_VALUE:
        raise ValueError("unbounded etcd WAF lease value")
    value = strict_json(raw)
    if type(value) is not dict or set(value) != {
        "schemaVersion", "kind", "nodeIds", "revision",
        "policySha256", "holder"
    } or type(value["schemaVersion"]) is not int or \
            value["schemaVersion"] != 1 or value["kind"] != "waf" or \
            type(value["nodeIds"]) is not list or value["nodeIds"] != list(names) or \
            type(value["revision"]) is not int or value["revision"] != revision or \
            value["policySha256"] != policy_digest or \
            type(value["holder"]) is not str or not NONCE.fullmatch(value["holder"]):
        raise ValueError("etcd lease is not for the authorized WAF transaction")
    return value["holder"]


class EtcdQuorumFence:
    """A fresh linearizable etcd read + lease TTL from 2 of 3 distinct members."""

    def __init__(self, fleet, endpoints, cluster_id, ca, certificate, key):
        if type(fleet) is not str or not ALIAS.fullmatch(fleet):
            raise ValueError("invalid fixed WAF fleet identity")
        if type(endpoints) is not list or len(endpoints) != 3:
            raise ValueError("three independent etcd members required")
        parsed = [endpoint_parts(x) for x in endpoints]
        if len({(host, port) for host, port, _ in parsed}) != 3 or \
                len({pin for _, _, pin in parsed}) != 3:
            raise ValueError("same etcd member/pin cannot count as quorum twice")
        cluster_id = integer(cluster_id)
        self.fleet = fleet
        self.endpoints = parsed
        self.cluster_id = cluster_id
        self._identity = None
        self.key_name = "/gatewaycore/waf/fence/" + fleet
        self.ca = canonical_file(ca)
        self.cert = canonical_file(certificate)
        self.key = private_key(key)

    def _post(self, endpoint, resource, payload):
        hostname, port, pinned_sha = endpoint
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,
                                             cafile=self.ca)
        context.check_hostname = True
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert, self.key)
        raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("ascii")
        conn = http.client.HTTPSConnection(hostname, port, context=context,
                                           timeout=5)
        try:
            conn.connect()
            peer = conn.sock.getpeercert(binary_form=True) if conn.sock else None
            if not peer or not hmac.compare_digest(
                    hashlib.sha256(peer).hexdigest().upper(), pinned_sha):
                raise ValueError("etcd member certificate does not match approved pin")
            conn.request("POST", resource, raw, {
                "Content-Type": "application/json",
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Connection": "close"
            })
            response = conn.getresponse()
            if response.status != 200 or \
                    response.getheader("Content-Type", "").split(";", 1)[0] != "application/json":
                raise ValueError("etcd quorum HTTP endpoint refused request")
            result = response.read(MAX_REPLY + 1)
            return strict_json(result)
        finally:
            conn.close()

    def _read_member(self, endpoint, names, revision, policy_digest):
        key = base64.b64encode(self.key_name.encode("ascii")).decode("ascii")
        # Default etcd Range is LINEARIZABLE. Explicit false ensures that a
        # serializable/minority-partition read cannot authorize a deployment.
        document = self._post(endpoint, "/v3/kv/range",
                              {"key": key, "serializable": False})
        if type(document) is not dict or type(document.get("kvs")) is not list or \
                len(document["kvs"]) != 1 or integer(document.get("count")) != 1:
            raise ValueError("etcd fencing lease key absent or duplicated")
        header = document.get("header")
        if type(header) is not dict or integer(header.get("cluster_id")) != self.cluster_id:
            raise ValueError("wrong etcd quorum cluster")
        member = integer(header.get("member_id"))
        observed_revision = integer(header.get("revision"))
        kv = document["kvs"][0]
        if type(kv) is not dict:
            raise ValueError("invalid etcd fencing entry")
        if base64.b64decode(kv.get("key", ""), validate=True) != \
                self.key_name.encode("ascii"):
            raise ValueError("untrusted etcd WAF key returned")
        modified = integer(kv.get("mod_revision"))
        if observed_revision < modified or integer(kv.get("version")) < 1:
            raise ValueError("stale etcd quorum metadata")
        lease = integer(kv.get("lease"))
        raw = base64.b64decode(kv.get("value", ""), validate=True)
        holder = valid_value(raw, names, revision, policy_digest)
        ttl = self._post(endpoint, "/v3/lease/timetolive",
                         {"ID": str(lease), "keys": False})
        if type(ttl) is not dict or integer(ttl.get("ID")) != lease:
            raise ValueError("lease expired or TTL response identity mismatch")
        remain = ttl.get("TTL")
        if type(remain) is str and remain.isdecimal():
            remain = int(remain)
        granted = ttl.get("grantedTTL")
        if type(granted) is str and granted.isdecimal():
            granted = int(granted)
        if type(remain) is not int or type(granted) is not int or \
                not MIN_TTL <= remain <= granted <= MAX_TTL:
            raise ValueError("expired, unbounded or nonrenewed etcd lease")
        return member, (self.cluster_id, modified, lease, holder)

    def assert_current(self, names, revision, policy_digest, phase):
        if (type(names) is not tuple or len(names) != 2 or
                names != tuple(sorted(names)) or
                any(type(n) is not str or not ID.fullmatch(n) for n in names) or
                type(revision) is not int or revision < 1 or
                type(policy_digest) is not str or not DIGEST.fullmatch(policy_digest) or
                type(phase) is not str or phase not in {
                    "preflight", "check-"+names[0], "check-"+names[1],
                    "before-journal", "before-apply-"+names[0],
                    "before-apply-"+names[1], "after-apply-"+names[0],
                    "after-apply-"+names[1], "before-receipt",
                    "rollback-"+names[0], "rollback-"+names[1]
                }):
            return False
        accepted = []
        for endpoint in self.endpoints:
            try:
                accepted.append(self._read_member(endpoint, names, revision,
                                               policy_digest))
            except (OSError, ValueError, KeyError, TypeError,
                    http.client.HTTPException, ssl.SSLError, OverflowError):
                continue
        # Never count two endpoints which report the SAME etcd member identity
        # or disagree on the lease key's raft revision/holder/lease ID.
        if len(accepted) < 2 or len({member for member, _ in accepted}) != \
                len(accepted):
            return False
        states = {state for _, state in accepted}
        if len(states) != 1:
            return False
        identity = next(iter(states))
        if self._identity is None:
            if phase != "preflight":
                return False
            self._identity = identity
        return identity == self._identity


# Integration: controller passes an instance to
# two_node_transaction.coordinate(nodes, ..., fence=EtcdQuorumFence(...)).
# The source does NOT create an etcd writer/lease, nor does it make a local
# Docker provider itself require a remote fence before out-of-band mutation.
