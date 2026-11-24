#!/usr/bin/env python3
"""Isolated, independent etcd quorum authority for signed Linux DP recovery.

This module cannot decrypt Data Protection keys or promote a live host.
The separately approved P-256 checkpoint hash is a fixed lease binding;
the actual .NET signed restore verifies the checkpoint and external floor.
The issuer and offline restore verifier require different etcd mTLS RBAC
identities in a real deployment. No local quorum/emergency override.
"""
import base64
import hashlib
import json
import re
import secrets
import xml.etree.ElementTree as XML
import ssl
import time
import http.client
import sys
from pathlib import Path

# Allow the documented "python3 ops/fleet/..." offline invocation without
# relying on an ambient PYTHONPATH or fetching a dependency at runtime.
_REPO_ROOT = str(Path(__file__).resolve().parents[2])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
from ops.waf import etcd_quorum_fence as etcd

MIN_ISSUE_TTL = 60
MAX_ISSUE_TTL = 120
RECOVERY_KIND = "linux-dp"
KEY_PREFIX = "/gatewaycore/linux-dp/recovery/"
PHASES = frozenset(("preflight", "before-transfer", "after-transfer",
                    "before-signed-restore", "after-signed-restore"))


def pinned_identity(sender, receiver, revision, checkpoint_sha):
    if (type(sender) is not str or not etcd.ID.fullmatch(sender) or
            type(receiver) is not str or not etcd.ID.fullmatch(receiver) or
            sender == receiver or type(revision) is not int or revision < 1 or
            type(checkpoint_sha) is not str or
            not etcd.DIGEST.fullmatch(checkpoint_sha)):
        raise ValueError("invalid two-node signed recovery identity")


def as_base64(data):
    return base64.b64encode(data).decode("ascii")


class RecoveryFence:
    def __init__(self, fleet, endpoints, cluster_id, ca, certificate, key,
                 sender, receiver, revision, checkpoint_sha):
        pinned_identity(sender, receiver, revision, checkpoint_sha)
        self.client = etcd.EtcdQuorumFence(fleet, endpoints, cluster_id,
                                           ca, certificate, key)
        self.key_name = KEY_PREFIX + fleet
        self.key = as_base64(self.key_name.encode("ascii"))
        self.sender, self.receiver = sender, receiver
        self.revision, self.checkpoint_sha = revision, checkpoint_sha
        self._identity = None
        self._deadline = None

    def remaining_seconds(self):
        # Only a successful fresh quorum observation can populate this
        # bound. No cached TTL remains usable after a rejected phase.
        return (0.0 if self._deadline is None
                else max(0.0, self._deadline - time.monotonic()))

    def _value(self, raw):
        record = etcd.strict_json(raw)
        if (type(record) is not dict or set(record) != {
                "schemaVersion", "kind", "senderNodeId",
                "receiverNodeId", "revision", "checkpointSha256", "holder"} or
                type(record["schemaVersion"]) is not int or
                record["schemaVersion"] != 1 or
                record["kind"] != RECOVERY_KIND or
                record["senderNodeId"] != self.sender or
                record["receiverNodeId"] != self.receiver or
                type(record["revision"]) is not int or
                record["revision"] != self.revision or
                record["checkpointSha256"] != self.checkpoint_sha or
                type(record["holder"]) is not str or
                not etcd.NONCE.fullmatch(record["holder"])):
            raise ValueError("etcd lease does not authorize this signed recovery")
        return record["holder"]

    def _read_member(self, endpoint):
        doc = self.client._post(endpoint, "/v3/kv/range",
                                {"key": self.key, "serializable": False})
        if (type(doc) is not dict or
                type(doc.get("kvs")) is not list or len(doc["kvs"]) != 1 or
                etcd.integer(doc.get("count")) != 1 or
                type(doc.get("header")) is not dict):
            raise ValueError("signed recovery fence absent or ambiguous")
        header = doc["header"]
        if etcd.integer(header.get("cluster_id")) != self.client.cluster_id:
            raise ValueError("unapproved independent etcd cluster")
        member = etcd.integer(header.get("member_id"))
        if member != endpoint[3]:
            raise ValueError("TLS leaf and approved Raft member disagree")
        seen_revision = etcd.integer(header.get("revision"))
        kv = doc["kvs"][0]
        if (type(kv) is not dict or
                base64.b64decode(kv.get("key", ""), validate=True) !=
                self.key_name.encode("ascii")):
            raise ValueError("unapproved recovery namespace key")
        modified = etcd.integer(kv.get("mod_revision"))
        lease = etcd.integer(kv.get("lease"))
        if seen_revision < modified or etcd.integer(kv.get("version")) < 1:
            raise ValueError("stale recovery Raft metadata")
        holder = self._value(base64.b64decode(kv.get("value", ""), validate=True))
        started = time.monotonic()
        ttl = self.client._post(endpoint, "/v3/lease/timetolive",
                                {"ID": str(lease), "keys": False})
        if type(ttl) is not dict or etcd.integer(ttl.get("ID")) != lease:
            raise ValueError("unapproved recovery TTL binding")
        remain, granted = ttl.get("TTL"), ttl.get("grantedTTL")
        if type(remain) is str and remain.isdecimal():
            remain = int(remain)
        if type(granted) is str and granted.isdecimal():
            granted = int(granted)
        if (type(remain) is not int or type(granted) is not int or
                not etcd.MIN_TTL <= remain <= granted <= etcd.MAX_TTL):
            raise ValueError("expired or unbounded DP recovery lease")
        return (member, (self.client.cluster_id, modified, lease, holder),
                started + remain)

    def current(self, phase):
        self._deadline = None
        if phase not in PHASES:
            return False
        read = []
        for endpoint in self.client.endpoints:
            try:
                read.append(self._read_member(endpoint))
            except (OSError, ssl.SSLError, TimeoutError, http.client.HTTPException):
                continue
            except (TypeError, ValueError, KeyError, OverflowError):
                # A reachable pinned member that contradicts the approved
                # checkpoint, identity or lease is a veto, not a lost vote.
                return False
        if len(read) < 2 or len({item[0] for item in read}) != len(read):
            return False
        identities = {item[1] for item in read}
        if len(identities) != 1:
            return False
        current = time.monotonic()
        if any(not deadline > current + etcd.MIN_TTL
               for _, _, deadline in read):
            return False
        identity = next(iter(identities))
        if self._identity is None:
            if phase != "preflight":
                return False
            self._identity = identity
        if identity != self._identity:
            return False
        self._deadline = min(deadline for _, _, deadline in read)
        return True


class RecoveryLeaseIssuer(RecoveryFence):
    """One-shot CAS only. Never renew, replace or steal an existing lease."""

    def __init__(self, *args, ttl=120, **kwargs):
        super().__init__(*args, **kwargs)
        if type(ttl) is not int or not MIN_ISSUE_TTL <= ttl <= MAX_ISSUE_TTL:
            raise ValueError("invalid approved DP lease bound")
        self.ttl = ttl
        self.phase = "preflight"

    def _empty(self, endpoint):
        doc = self.client._post(endpoint, "/v3/kv/range",
                                {"key": self.key, "serializable": False})
        if type(doc) is not dict or type(doc.get("header")) is not dict:
            raise ValueError("invalid DP recovery lease absence response")
        header = doc["header"]
        if (etcd.integer(header.get("cluster_id")) != self.client.cluster_id or
                etcd.integer(header.get("member_id")) != endpoint[3]):
            raise ValueError("unapproved Raft member identity on lease preflight")
        if (doc.get("count", "0") not in ("0", 0) or
                doc.get("kvs") not in (None, [])):
            raise ValueError("existing DP recovery lease cannot be overwritten")

    def _revoke(self, endpoint, lease):
        try:
            self.client._post(endpoint, "/v3/lease/revoke", {"ID": str(lease)})
        except (OSError, ValueError, TypeError, ssl.SSLError,
                http.client.HTTPException):
            # Explicit operator reconciliation required if revoke fails.
            # Never claim revoked or reissue a conflicting lease.
            pass

    def issue_once(self):
        self.phase = "read-absent-quorum"
        reachable = []
        for endpoint in self.client.endpoints:
            try:
                self._empty(endpoint)
            except (OSError, ssl.SSLError, TimeoutError,
                    http.client.HTTPException):
                continue
            # Any authenticated contradictory member is fatal (no steal).
            reachable.append(endpoint)
        if len(reachable) < 2:
            raise ValueError("authenticated DP recovery quorum unavailable")
        self.phase = "grant-new-lease"
        endpoint = reachable[0]
        grant = self.client._post(endpoint, "/v3/lease/grant",
                                  {"TTL": str(self.ttl)})
        if type(grant) is not dict:
            raise ValueError("etcd lease grant missing")
        self.phase = "validate-lease-grant"
        lease = etcd.integer(grant.get("ID"))
        lifetime = grant.get("TTL")
        if type(lifetime) is str and lifetime.isdecimal():
            lifetime = int(lifetime)
        if type(lifetime) is not int or lifetime != self.ttl:
            self._revoke(endpoint, lease)
            raise ValueError("unexpected etcd recovery TTL grant")
        nonce = secrets.token_hex(16)
        record = {"schemaVersion":1,"kind":RECOVERY_KIND,
                  "senderNodeId":self.sender,"receiverNodeId":self.receiver,
                  "revision":self.revision,
                  "checkpointSha256":self.checkpoint_sha,"holder":nonce}
        value = as_base64(json.dumps(record, sort_keys=True,
                       separators=(",", ":")).encode("ascii"))
        try:
            self.phase = "compare-and-swap"
            txn = self.client._post(endpoint, "/v3/kv/txn", {
                "compare": [{"result":"EQUAL", "target":"CREATE",
                             "key":self.key, "createRevision":"0"}],
                "success": [{"requestPut":{"key":self.key, "value":value,
                                           "lease":str(lease)}}],
                "failure": []})
            self.phase = "validate-cas-header"
            header = txn.get("header") if type(txn) is dict else None
            if (type(header) is not dict or
                    etcd.integer(header.get("cluster_id")) != self.client.cluster_id or
                    etcd.integer(header.get("member_id")) != endpoint[3] or
                    txn.get("succeeded") is not True):
                raise ValueError("DP recovery CAS contested or unverified")
            self.phase = "verify-live-quorum"
            if self.current("preflight") is not True or (
                    self._identity is None or
                    self._identity[2] != lease or
                    self._identity[3] != nonce):
                raise ValueError("issued recovery lease not majority-confirmed")
            self.phase = "complete"
            return {"schemaVersion":1, "kind":RECOVERY_KIND,
                    "senderNodeId":self.sender, "receiverNodeId":self.receiver,
                    "revision":self.revision,
                    "checkpointSha256":self.checkpoint_sha,
                    "leaseId":lease, "raftModRevision":self._identity[1],
                    "holder":nonce, "ttlSeconds":self.ttl}
        except Exception:
            self._revoke(endpoint, lease)
            raise


class RecoveryRevisionPublisher(RecoveryFence):
    """Durable checkpoint publication with an atomic live-epoch CAS.

    A separately authorized publisher may record an externally approved
    recovery checkpoint. This is NOT a service promotion command or proof
    that a signed .NET restore or traffic cutover has completed. The pointer
    is never attached to the short-lived recovery lease. The verifier's
    read-only identity must not have permission to mutate this namespace.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fleet = self.key_name[len(KEY_PREFIX):]
        self.pointer_name = "/gatewaycore/linux-dp/published/" + fleet
        self.pointer_key = as_base64(self.pointer_name.encode("ascii"))

    def _pointer_member(self, endpoint):
        doc = self.client._post(endpoint, "/v3/kv/range",
                                {"key": self.pointer_key, "serializable": False})
        if type(doc) is not dict or type(doc.get("header")) is not dict:
            raise ValueError("untrusted published checkpoint response")
        header = doc["header"]
        if (etcd.integer(header.get("cluster_id")) != self.client.cluster_id or
                etcd.integer(header.get("member_id")) != endpoint[3]):
            raise ValueError("published checkpoint member identity mismatch")
        head_revision = etcd.integer(header.get("revision"))
        if doc.get("count", "0") in ("0", 0) and doc.get("kvs") in (None, []):
            return (endpoint, (0, 0, None))
        if (type(doc.get("kvs")) is not list or len(doc["kvs"]) != 1 or
                etcd.integer(doc.get("count")) != 1):
            raise ValueError("ambiguous published checkpoint")
        kv = doc["kvs"][0]
        if (type(kv) is not dict or
                base64.b64decode(kv.get("key", ""), validate=True) !=
                self.pointer_name.encode("ascii") or
                kv.get("lease", "0") not in ("0", 0)):
            raise ValueError("published checkpoint must be durable and namespaced")
        mod = etcd.integer(kv.get("mod_revision"))
        if mod > head_revision or etcd.integer(kv.get("version")) < 1:
            raise ValueError("stale published checkpoint metadata")
        raw = base64.b64decode(kv.get("value", ""), validate=True)
        record = etcd.strict_json(raw)
        if (type(record) is not dict or set(record) != {
                "schemaVersion", "kind", "revision", "checkpointSha256",
                "senderNodeId", "receiverNodeId", "recoveryModRevision"} or
                type(record["schemaVersion"]) is not int or
                record["schemaVersion"] != 1 or record["kind"] != RECOVERY_KIND):
            raise ValueError("invalid durable recovery pointer")
        pinned_identity(record["senderNodeId"], record["receiverNodeId"],
                        record["revision"], record["checkpointSha256"])
        if (type(record["recoveryModRevision"]) is not int or
                not 0 < record["recoveryModRevision"] < mod):
            raise ValueError("invalid durable recovery epoch")
        return (endpoint, (mod, record["revision"], raw))

    def _pointer_quorum(self):
        reads = []
        for endpoint in self.client.endpoints:
            try:
                reads.append(self._pointer_member(endpoint))
            except (OSError, ssl.SSLError, TimeoutError, http.client.HTTPException):
                continue
        if (len(reads) < 2 or
                len({endpoint[3] for endpoint, _ in reads}) != len(reads) or
                len({value for _, value in reads}) != 1):
            raise ValueError("published recovery pointer lacks consistent quorum")
        return reads[0]

    def publish_once(self):
        """Do not retry ambiguous writes; reconcile the durable pointer first."""
        if not self.current("preflight"):
            raise ValueError("independent recovery publication authority refused")
        endpoint, (prior_mod, prior_revision, _) = self._pointer_quorum()
        if self.revision <= prior_revision:
            raise ValueError("replayed or rolled-back recovery revision refused")
        if not self.current("after-signed-restore") or self.remaining_seconds() <= 5:
            raise ValueError("recovery publication epoch no longer authorized")
        cluster, recovery_mod, lease, holder = self._identity
        record = {"schemaVersion": 1, "kind": RECOVERY_KIND,
                  "revision": self.revision, "checkpointSha256": self.checkpoint_sha,
                  "senderNodeId": self.sender, "receiverNodeId": self.receiver,
                  "recoveryModRevision": recovery_mod}
        raw = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("ascii")
        # These compares and the durable write execute in ONE Raft txn.
        # A revocation/regrant between the last read and the commit cannot
        # authorize the stale holder, even if its local clock still has TTL.
        compares = [
            {"result": "EQUAL", "target": "MOD", "key": self.key,
             "modRevision": str(recovery_mod)},
            {"result": "EQUAL", "target": "LEASE", "key": self.key,
             "lease": str(lease)},
            {"result": "EQUAL", "target": "MOD" if prior_mod else "CREATE",
             "key": self.pointer_key,
             ("modRevision" if prior_mod else "createRevision"): str(prior_mod)}
        ]
        response = self.client._post(endpoint, "/v3/kv/txn", {
            "compare": compares,
            "success": [{"requestPut": {"key": self.pointer_key,
                                        "value": as_base64(raw)}}],
            "failure": []})
        header = response.get("header") if type(response) is dict else None
        if (type(header) is not dict or
                etcd.integer(header.get("cluster_id")) != cluster or
                etcd.integer(header.get("member_id")) != endpoint[3] or
                response.get("succeeded") is not True):
            raise ValueError("recovery publication CAS contested or unverified")
        committed_mod = etcd.integer(header.get("revision"))
        _, confirmed = self._pointer_quorum()
        if confirmed != (committed_mod, self.revision, raw):
            raise ValueError("recovery publication outcome requires reconciliation")
        return record


RUNTIME_PREFIX = "/gatewaycore/linux-dp/runtime-writer/"
RING_PREFIX = "/gatewaycore/linux-dp/runtime-ring/"
MAX_RUNTIME_XML = 8192
_KEY_NAME = re.compile(r"key-([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\.xml\Z")
_DP_NS = "{http://schemas.asp.net/2015/03/dataProtection}"
_ENCRYPTOR = "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor"


def validate_runtime_xml(name, raw):
    """Accept bounded certificate-encrypted key XML, not plaintext or revocations.

    Revocation needs its own coordinated admission policy; it is deliberately
    not enabled by this append-only backend.
    """
    match = _KEY_NAME.fullmatch(name) if type(name) is str else None
    if (not match or type(raw) is not bytes or not 0 < len(raw) <= MAX_RUNTIME_XML
            or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper()
            or b"\x00" in raw):
        raise ValueError("invalid bounded runtime key record")
    try:
        raw.decode("utf-8", "strict")
        root = XML.fromstring(raw)
    except (UnicodeError, XML.ParseError) as exc:
        raise ValueError("malformed runtime encrypted key") from exc
    if root.tag != "key" or root.get("id") != match[1]:
        raise ValueError("runtime key name and XML identity mismatch")
    wraps = []
    for element in root.iter():
        local = element.tag.rsplit("}",1)[-1]
        if local == "masterKey":
            raise ValueError("plaintext runtime key rejected")
        if local == "encryptedSecret":
            if element.tag != _DP_NS + "encryptedSecret":
                raise ValueError("foreign runtime key wrapper")
            decryptor = [p.strip() for p in element.get("decryptorType","").split(",")]
            if decryptor[:2] != [_ENCRYPTOR, "Microsoft.AspNetCore.DataProtection"]:
                raise ValueError("unapproved runtime key wrapper")
            wraps.append(element)
    enc = "{http://www.w3.org/2001/04/xmlenc#}"
    if (len(wraps) != 1 or
            len(wraps[0].findall(".//" + enc + "EncryptedData")) != 1 or
            not wraps[0].findall(".//" + enc + "CipherValue")):
        raise ValueError("missing runtime certificate ciphertext envelope")


class RuntimeWriterLeaseIssuer(RecoveryLeaseIssuer):
    """Separate, bounded runtime-write epoch; no automatic renewal or promotion."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fleet = self.client.fleet
        self.key_name = RUNTIME_PREFIX + fleet
        self.key = as_base64(self.key_name.encode("ascii"))


class RuntimeEncryptedRingWriter(RecoveryFence):
    """Actual encrypted XML append in the SAME Raft transaction as writer fence.

    Dedicated write identity must be restricted to this fleet's runtime ring.
    A runtime epoch is independently provisioned, separate from recovery.
    No local XML write, fallback, lease stealing, or implicit renewal.
    """
    def __init__(self, *args, node_id, **kwargs):
        super().__init__(*args, **kwargs)
        if node_id != self.sender:
            raise ValueError("only the designated runtime writer may append")
        self.key_name = RUNTIME_PREFIX + self.client.fleet
        self.key = as_base64(self.key_name.encode("ascii"))
        self.ring_prefix = RING_PREFIX + self.client.fleet + "/"

    def append_once(self, name, raw):
        validate_runtime_xml(name, raw)
        if not self.current("preflight") or self.remaining_seconds() <= 5:
            raise ValueError("runtime key writer quorum unavailable")
        cluster, modified, lease, _ = self._identity
        item = as_base64((self.ring_prefix + name).encode("ascii"))
        # The mutation itself is fenced, not a local write following a check.
        # Compare CREATE=0 so a stale or competing writer cannot overwrite.
        body = {"compare":[
            {"result":"EQUAL","target":"MOD","key":self.key,
             "modRevision":str(modified)},
            {"result":"EQUAL","target":"LEASE","key":self.key,"lease":str(lease)},
            {"result":"EQUAL","target":"CREATE","key":item,"createRevision":"0"}
        ],"success":[{"requestPut":{"key":item,"value":as_base64(raw)}}],"failure":[]}
        endpoint = self.client.endpoints[0]
        # Deliberately no mutation retry after any ambiguous RPC outcome.
        response = self.client._post(endpoint,"/v3/kv/txn",body)
        header = response.get("header") if type(response) is dict else None
        if (type(header) is not dict or
                etcd.integer(header.get("cluster_id")) != cluster or
                etcd.integer(header.get("member_id")) != endpoint[3] or
                response.get("succeeded") is not True):
            raise ValueError("runtime encrypted key append contested or unverified")
        return etcd.integer(header.get("revision"))


class RuntimeWriterHandoff:
    """Independently authorized atomic epoch replacement, not auto-promotion.

    A designated operator supplies the EXACT old epoch receipt and a new
    approved writer identity. Both old and new verification use the same
    independently pinned cluster and operator credentials. Old app instances
    must retain their old epoch pins: their writes fail after replacement.
    """
    def __init__(self, previous, successor, expected_receipt):
        if (type(previous) is not RuntimeWriterLeaseIssuer or
                type(successor) is not RuntimeWriterLeaseIssuer or
                previous is successor or previous.key != successor.key or
                previous.client.cluster_id != successor.client.cluster_id or
                previous.client.endpoints != successor.client.endpoints or
                successor.revision <= previous.revision or
                type(expected_receipt) is not dict):
            raise ValueError("invalid independent runtime epoch handoff")
        expected = {"schemaVersion": 1, "kind": RECOVERY_KIND,
                    "senderNodeId": previous.sender,
                    "receiverNodeId": previous.receiver,
                    "revision": previous.revision,
                    "checkpointSha256": previous.checkpoint_sha}
        if any(expected_receipt.get(k) != v for k,v in expected.items()):
            raise ValueError("old runtime receipt does not match approved identity")
        holder = expected_receipt.get("holder")
        if type(holder) is not str or not etcd.NONCE.fullmatch(holder):
            raise ValueError("invalid old runtime receipt holder")
        self.expected = (previous.client.cluster_id,
            etcd.integer(expected_receipt.get("raftModRevision")),
            etcd.integer(expected_receipt.get("leaseId")), holder)
        self.previous, self.successor = previous, successor

    def replace_once(self):
        old, new = self.previous, self.successor
        if (not old.current("preflight") or old._identity != self.expected or
                old.remaining_seconds() <= 5 or new._identity is not None):
            raise ValueError("old runtime epoch no longer independently authorized")
        endpoint = new.client.endpoints[0]
        grant = new.client._post(endpoint,"/v3/lease/grant",{"TTL":str(new.ttl)})
        if type(grant) is not dict:
            raise ValueError("runtime handoff lease grant unverified")
        lease = etcd.integer(grant.get("ID"))
        if lease == self.expected[2]:
            raise ValueError("runtime successor cannot reuse old lease")
        lifetime = grant.get("TTL")
        if type(lifetime) is str and lifetime.isdecimal():
            lifetime = int(lifetime)
        if type(lifetime) is not int or lifetime != new.ttl:
            new._revoke(endpoint,lease)
            raise ValueError("invalid runtime successor lease duration")
        nonce = secrets.token_hex(16)
        record = {"schemaVersion":1,"kind":RECOVERY_KIND,
                  "senderNodeId":new.sender,"receiverNodeId":new.receiver,
                  "revision":new.revision,"checkpointSha256":new.checkpoint_sha,
                  "holder":nonce}
        encoded = as_base64(json.dumps(record,sort_keys=True,
                               separators=(",",":")).encode("ascii"))
        # Refresh old authority before mutation. CAS is still necessary:
        # revocation or competing handoff can occur after the refresh.
        if (not old.current("before-transfer") or old._identity != self.expected or
                old.remaining_seconds() <= 5):
            new._revoke(endpoint,lease)
            raise ValueError("old runtime epoch revoked before handoff")
        # The successor is installed and predecessor fenced at the SAME
        # linearization point. No delete/regrant window or forced takeover.
        response = new.client._post(endpoint,"/v3/kv/txn",{
            "compare":[
                {"result":"EQUAL","target":"MOD","key":new.key,
                 "modRevision":str(self.expected[1])},
                {"result":"EQUAL","target":"LEASE","key":new.key,
                 "lease":str(self.expected[2])}],
            "success":[{"requestPut":{"key":new.key,"value":encoded,"lease":str(lease)}}],
            "failure":[]})
        header = response.get("header") if type(response) is dict else None
        if (type(header) is not dict or
                etcd.integer(header.get("cluster_id")) != self.expected[0] or
                etcd.integer(header.get("member_id")) != endpoint[3]):
            raise ValueError("ambiguous runtime handoff: reconcile independently")
        if response.get("succeeded") is False or (
                "succeeded" not in response and response.get("responses",[]) == []):
            new._revoke(endpoint,lease)
            raise ValueError("runtime handoff CAS contested")
        if response.get("succeeded") is not True:
            raise ValueError("ambiguous runtime handoff: reconcile independently")
        mod = etcd.integer(header.get("revision"))
        if (not new.current("preflight") or new._identity !=
                (self.expected[0],mod,lease,nonce)):
            # A committed successor may exist. Never revoke it merely because
            # readback failed; leave bounded expiry and require reconciliation.
            raise ValueError("runtime successor outcome requires reconciliation")
        return dict(record,leaseId=lease,raftModRevision=mod,ttlSeconds=new.ttl)
