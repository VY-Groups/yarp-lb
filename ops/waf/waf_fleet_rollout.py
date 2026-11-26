#!/usr/bin/env python3
"""Operator-only signed two-node WAF rollout via pinned mTLS and live etcd fencing.

Default is read-only preflight; --execute invokes the existing compensating
transaction. Never creates its own lease, trust anchors or revision floor.
"""
import argparse
import hashlib
import http.client
from pathlib import Path
import subprocess
import sys

import verify_signed_policy as signed
import two_node_transaction as fleet
from etcd_quorum_fence import EtcdQuorumFence
from mtls_fenced_node import RemoteNodeProvider
from waf_node_service import approved_endpoint_file


def approved_policy(args):
    keys = {}
    for record in args.reviewer_key:
        who, sep, path = record.partition("=")
        if not sep or not signed._safe_id(who) or who in keys or not Path(path).is_absolute():
            raise ValueError("invalid independent reviewer mapping")
        keys[who] = Path(path)
    raw = signed._read_file(args.policy)
    policy = signed._json(raw)
    digest = hashlib.sha256(raw).hexdigest().upper()
    if (type(policy) is not dict or policy.get("exceptions") != [] or
            policy.get("mode") not in ("detect", "block")):
        raise ValueError("only signed mode transitions without scoped exceptions are supported")
    revision, verified_digest = signed.verify(
        args.policy, args.approval, keys, args.minimum_revision_file,
        args.observed_ruleset_sha256, policy["mode"],
        shadow_evidence_path=args.shadow_evidence_file, return_digest=True)
    if (verified_digest != digest or revision != policy.get("revision") or
            args.confirm_revision != revision or args.confirm_policy_sha256 != digest):
        raise ValueError("exact signed policy/revision confirmation mismatch")
    return policy["mode"], revision, digest


def preflight(nodes, fence, target, revision, digest, ruleset, receipt):
    ordered = fleet._validate_nodes(nodes)
    names = [name for name, _ in ordered]
    fleet._validate_receipt_paths(receipt)
    fleet._check_fence(fence, names, revision, digest, "operator-preflight")
    states = []
    for name, node in ordered:
        fleet._check_fence(fence, names, revision, digest, "check-" + name)
        states.append(fleet._preflight(node, target, ruleset))
    if states[0] != states[1]:
        raise ValueError("WAF nodes have divergent baseline mode or image")
    fleet._check_fence(fence, names, revision, digest, "operator-preflight-complete")
    return "preflight-only"


def run(args):
    if not sys.platform.startswith("linux"):
        raise ValueError("Linux operator controller required")
    target, revision, digest = approved_policy(args)
    if len(args.node) != 2 or len({row[0] for row in args.node}) != 2:
        raise ValueError("two independently approved WAF node identities required")
    inventory = approved_endpoint_file(args.etcd_members)
    fence = EtcdQuorumFence(inventory["fleet"], inventory["endpoints"],
                           inventory["clusterId"], args.etcd_ca,
                           args.etcd_certificate, args.etcd_private_key)
    nodes = {name: RemoteNodeProvider(name, url, pin, args.node_ca,
             args.node_certificate, args.node_private_key) for name, url, pin in args.node}
    if not args.execute:
        return preflight(nodes, fence, target, revision, digest,
                         args.observed_ruleset_sha256, args.receipt)
    return fleet.coordinate(nodes, target, revision, digest,
                            args.observed_ruleset_sha256, args.receipt, fence=fence)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--approval", type=Path, action="append", required=True)
    parser.add_argument("--reviewer-key", action="append", required=True)
    parser.add_argument("--minimum-revision-file", type=Path, required=True)
    parser.add_argument("--shadow-evidence-file", type=Path)
    parser.add_argument("--observed-ruleset-sha256", required=True)
    parser.add_argument("--confirm-revision", type=int, required=True)
    parser.add_argument("--confirm-policy-sha256", required=True)
    parser.add_argument("--etcd-members", type=Path, required=True)
    parser.add_argument("--etcd-ca", required=True)
    parser.add_argument("--etcd-certificate", required=True)
    parser.add_argument("--etcd-private-key", required=True)
    parser.add_argument("--node", nargs=3, action="append", required=True,
                        metavar=("ID", "HTTPS_URL", "LEAF_SHA256"))
    parser.add_argument("--node-ca", required=True)
    parser.add_argument("--node-certificate", required=True)
    parser.add_argument("--node-private-key", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(args)
        if result == "preflight-only":
            print("PASS: signed WAF fleet preflight only; no changes applied")
        elif result == "applied-uncommitted":
            print("PASS: two nodes verified; independent authority commit still required")
        else:
            raise ValueError("unrecognized fleet outcome")
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RuntimeError,
            subprocess.SubprocessError, http.client.HTTPException):
        print("FAIL: WAF fleet operation refused or failed; inspect private reconciliation evidence",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
