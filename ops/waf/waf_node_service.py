#!/usr/bin/env python3
"""Authorized Linux node daemon for pinned mTLS and separately fenced WAF rollout.

Every service startup independently verifies BOTH P-256 policy approvals,
the external monotonic revision floor, fixed runtime CRS digest and current
three-member etcd lease before accepting any remote request. No implicit
operator enrollment, certificate generation, remote shell or auth bypass.
"""
import argparse
import datetime as dt
import hashlib
import json
from pathlib import Path
import sys

import etcd_quorum_fence as quorum
import mtls_fenced_node as network
import rollout_controller as local
import verify_signed_policy as signed


def approved_endpoint_file(path):
    data = signed._json(signed._read_file(Path(path), limit=4096))
    if type(data) is not dict or set(data) != {"schemaVersion","clusterId","fleet","endpoints"} or (
            type(data["schemaVersion"]) is not int or data["schemaVersion"] != 1 or
            type(data["fleet"]) is not str):
        raise ValueError("independent etcd member inventory malformed")
    endpoints = data["endpoints"]
    if type(endpoints) is not list or len(endpoints) != 3:
        raise ValueError("three independently approved etcd endpoints required")
    for endpoint in endpoints:
        quorum.endpoint_parts(endpoint)
    return data


def build_agent(args):
    # Reject Windows at startup until a real, independently tested Windows
    # Docker/Windows-service adapter and ACL contract are implemented.
    if not sys.platform.startswith("linux"):
        raise ValueError("WAF external node agent currently supports Linux only")
    keys = {}
    for entry in args.reviewer_key:
        who, marker, path = entry.partition("=")
        if (not marker or not signed._safe_id(who) or who in keys or
                not Path(path).is_absolute()):
            raise ValueError("invalid independent P-256 reviewer mapping")
        keys[who] = Path(path)
    raw = signed._read_file(args.policy)
    approved_sha = hashlib.sha256(raw).hexdigest().upper()
    policy = signed._json(raw)
    if type(policy) is not dict or policy.get("exceptions") != []:
        # Current agent deploys only signed mode, never silently ignores an
        # exception whose effective runtime include graph is unverified.
        raise ValueError("signed exceptions require separate node deployment integration")
    if policy.get("mode") not in local.MODES:
        raise ValueError("unsupported signed WAF engine")
    revision = signed.verify(
        args.policy, args.approval, keys, args.minimum_revision_file,
        args.observed_ruleset_sha256, policy["mode"],
        shadow_evidence_path=args.shadow_evidence_file)
    if (signed._read_file(args.policy) != raw or
            policy.get("revision") != revision or
            policy.get("rulesetSha256") != args.observed_ruleset_sha256):
        raise ValueError("signed WAF policy changed during node startup")
    inventory = approved_endpoint_file(args.etcd_members)
    provider = local.DockerComposeProvider(
        args.compose, args.image, args.health_url, project_name=args.project_name)
    current = provider.inspect()
    if (current["imageId"] != provider.image_and_config(current["mode"]) or
            provider.observed_rule_digest() != args.observed_ruleset_sha256):
        raise ValueError("signed WAF baseline does not match running WAF")
    nodes = tuple(sorted((args.node_a, args.node_b)))
    fence = quorum.EtcdQuorumFence(
        inventory["fleet"], inventory["endpoints"], inventory["clusterId"],
        args.etcd_ca, args.etcd_certificate, args.etcd_private_key)
    expiry = signed._utc(policy["expiresAtUtc"])
    return network.FencedAgent(
        args.node_id, nodes, revision, approved_sha,
        args.observed_ruleset_sha256, policy["mode"], provider, fence,
        args.receipt_dir, policy_expires_utc=expiry)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-id", required=True)
    parser.add_argument("--node-a", required=True)
    parser.add_argument("--node-b", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--approval", action="append", type=Path, required=True)
    parser.add_argument("--reviewer-key", action="append", required=True)
    parser.add_argument("--minimum-revision-file", type=Path, required=True)
    parser.add_argument("--shadow-evidence-file", type=Path)
    parser.add_argument("--observed-ruleset-sha256", required=True)
    parser.add_argument("--compose", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--health-url", required=True)
    parser.add_argument("--project-name", required=True)
    parser.add_argument("--receipt-dir", type=Path, required=True)
    parser.add_argument("--etcd-members", type=Path, required=True)
    parser.add_argument("--etcd-ca", required=True)
    parser.add_argument("--etcd-certificate", required=True)
    parser.add_argument("--etcd-private-key", required=True)
    parser.add_argument("--listen", default="127.0.0.1")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--allow-nonloopback", action="store_true")
    parser.add_argument("--controller-client-pin", required=True)
    parser.add_argument("--tls-ca", required=True)
    parser.add_argument("--tls-certificate", required=True)
    parser.add_argument("--tls-private-key", required=True)
    args = parser.parse_args(argv)
    try:
        agent = build_agent(args)
        with network.serve(
            agent, args.listen, args.port, args.tls_ca,
            args.tls_certificate, args.tls_private_key,
            args.controller_client_pin,
            allow_nonloopback=args.allow_nonloopback) as server:
            server.serve_forever(poll_interval=.2)
        return 0
    except (OSError, ValueError, KeyError, TypeError, UnicodeError,
            json.JSONDecodeError):
        # No certificate material, paths, signed policy or raw WAF data
        # leave the operator-private daemon by exception rendering.
        print("FAIL: authenticated WAF node refused startup or service",
              file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
