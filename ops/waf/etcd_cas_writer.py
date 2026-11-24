#!/usr/bin/env python3
"""No-fallback one-shot etcd v3 CAS lease authority for signed WAF rollout.

Separate from the read-only controller and every node's local quorum
verifier. A privileged operator must independently validate both signed
policy approvals and provision narrow etcd writer RBAC before construction.
No static lease JSON, local election, implicit credential generation,
lease stealing, lease keepalive or automated epoch rollover is provided.
"""
import base64
import hashlib
import hmac
import json
import secrets
import ssl
import http.client

import etcd_quorum_fence as quorum

MAX_TTL = 120
MIN_TTL = 60


class EtcdCasWriter:
    def __init__(self, fleet, endpoints, cluster_id, ca, certificate, key,
                 node_ids, revision, policy_sha, *, ttl=120):
        if (type(node_ids) is not tuple or len(node_ids) != 2 or
                tuple(sorted(node_ids)) != node_ids or
                node_ids[0] == node_ids[1] or
                any(type(n) is not str or not quorum.ID.fullmatch(n)
                    for n in node_ids) or
                type(revision) is not int or revision < 1 or
                type(policy_sha) is not str or not quorum.DIGEST.fullmatch(policy_sha) or
                type(ttl) is not int or not MIN_TTL <= ttl <= MAX_TTL):
            raise ValueError("unapproved bounded WAF lease authority identity")
        self.client = quorum.EtcdQuorumFence(
            fleet, endpoints, cluster_id, ca, certificate, key)
        self.node_ids = node_ids
        self.revision = revision
        self.policy_sha = policy_sha
        self.ttl = ttl
        self.key = base64.b64encode(self.client.key_name.encode("ascii")).decode("ascii")

    def _read_empty_member(self, endpoint):
        result = self.client._post(endpoint, "/v3/kv/range",
                                   {"key": self.key, "serializable": False})
        if type(result) is not dict or type(result.get("header")) is not dict:
            raise ValueError("untrusted etcd linearizable member response")
        header = result["header"]
        if (quorum.integer(header.get("cluster_id")) != self.client.cluster_id or
                quorum.integer(header.get("member_id")) != endpoint[3]):
            raise ValueError("etcd leader/leaf/member trust mismatch")
        # Proto3 omits the zero count and empty repeated kvs. Any present
        # key means a competing authority owns this resource: never revoke,
        # overwrite or steal it.
        if result.get("count", "0") not in ("0", 0) or result.get("kvs") not in (None, []):
            raise ValueError("existing WAF fence authority prevents CAS issue")
        return endpoint

    def _empty_quorum(self):
        accepted = []
        for endpoint in self.client.endpoints:
            try:
                accepted.append(self._read_empty_member(endpoint))
            except (OSError, ssl.SSLError, TimeoutError,
                    http.client.HTTPException):
                # An unreachable member is not a vote, but neither does it
                # authorize a unilateral lease grant.
                continue
            # A REACHABLE TLS-authenticated member contradicting approved
            # identity or ownership is a hard veto, never simply ignored.
        if len(accepted) < 2:
            raise ValueError("independent quorum unavailable for lease CAS")
        return accepted

    def _revoke_best_effort(self, endpoint, lease):
        try:
            self.client._post(endpoint, "/v3/lease/revoke", {"ID": str(lease)})
        except (OSError, ValueError, ssl.SSLError,
                http.client.HTTPException):
            # No false cleanup claim. The bounded TTL is the safety
            # fallback; an operator must inspect unresolved incidents.
            pass

    def issue_once(self):
        """Grant a new lease only against an absent key, verify real quorum."""
        members = self._empty_quorum()
        target = members[0]
        granted = self.client._post(target, "/v3/lease/grant",
                                    {"TTL": str(self.ttl)})
        if type(granted) is not dict:
            raise ValueError("invalid lease grant response")
        lease = quorum.integer(granted.get("ID"))
        granted_ttl = granted.get("TTL")
        if isinstance(granted_ttl, str) and granted_ttl.isdecimal():
            granted_ttl = int(granted_ttl)
        if type(granted_ttl) is not int or granted_ttl != self.ttl:
            self._revoke_best_effort(target, lease)
            raise ValueError("etcd lease granted unexpected duration")
        holder = secrets.token_hex(16)
        value = {
            "schemaVersion": 1, "kind": "waf",
            "nodeIds": list(self.node_ids), "revision": self.revision,
            "policySha256": self.policy_sha, "holder": holder
        }
        encoded = base64.b64encode(json.dumps(value,sort_keys=True,separators=(",",":")
                             ).encode("ascii")).decode("ascii")
        try:
            response = self.client._post(target, "/v3/kv/txn", {
                "compare": [{"result":"EQUAL","target":"CREATE",
                             "key":self.key,"createRevision":"0"}],
                "success": [{"requestPut":{"key":self.key,"value":encoded,
                                           "lease":str(lease)}}],
                "failure": []
            })
            header = response.get("header") if type(response) is dict else None
            if (type(header) is not dict or
                    quorum.integer(header.get("cluster_id")) != self.client.cluster_id or
                    response.get("succeeded") is not True):
                raise ValueError("contested or unverified etcd CAS fence grant")
            # Every successful issue must be backed by CURRENT linearizable
            # observations on at least two real TLS-pinned distinct members.
            # The verifier pins this exact holder/lease for subsequent phases.
            if self.client.assert_current(self.node_ids, self.revision,
                                          self.policy_sha, "preflight") is not True:
                raise ValueError("new WAF lease was not quorum-confirmed")
            bound = self.client._identity
            if (type(bound) is not tuple or len(bound) != 4 or
                    bound[0] != self.client.cluster_id or
                    bound[2] != lease or bound[3] != holder):
                raise ValueError("different WAF authority owned accepted quorum")
            return {"schemaVersion":1, "leaseId":lease, "modRevision":bound[1],
                    "policySha256":self.policy_sha, "revision":self.revision,
                    "nodeIds":list(self.node_ids), "holder":holder,
                    "ttlSeconds":self.ttl}
        except Exception:
            # Revoke only OUR new lease, not any preexisting competing lease.
            # A lost revocation request leaves a bounded expiry incident,
            # not a successful authority receipt.
            self._revoke_best_effort(target, lease)
            raise
