#!/usr/bin/env python3
"""Fail-closed two-node external WAF transaction core (#51).

This is an offline integration *core*, not a fleet agent or network lease.
A calling controller MUST provide an independently authenticated, renewable
fence and two authenticated, distinct remote node adapters. Without that
fence the core rejects the operation before any mutation. In-process tests
exercise the rollback/journal protocol; they do not satisfy physical #36.

Signatures/CRS provenance are verified separately by verify_signed_policy.py
and each node provider; this function never grants a new policy exception.
"""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import stat

import rollout_controller as local
import mtls_fenced_node as remote

NODE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{1,47}\Z", re.ASCII)
DIGEST = re.compile(r"[0-9A-F]{64}\Z", re.ASCII)


def _current_utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def _validate_nodes(nodes):
    if not isinstance(nodes, dict) or len(nodes) != 2:
        raise ValueError("exactly two separately provisioned WAF nodes required")
    if any(type(name) is not str or not NODE_NAME.fullmatch(name) for name in nodes):
        raise ValueError("untrusted WAF node identity")
    if len({id(node) for node in nodes.values()}) != 2:
        raise ValueError("two independent node adapter instances required")
    ordered = sorted(nodes.items())
    remote_nodes = [(name, node) for name, node in ordered
                    if isinstance(node, remote.RemoteNodeProvider)]
    if remote_nodes:
        if len(remote_nodes) != 2 or any(name != node.node_id
                                        for name, node in remote_nodes):
            raise ValueError("remote WAF identity must match signed node mapping")
        if (len({(node.host, node.port) for _, node in remote_nodes}) != 2 or
                len({node.server_pin for _, node in remote_nodes}) != 2):
            raise ValueError("WAF remote endpoints and TLS identities must be independent")
    if all(isinstance(p, local.DockerComposeProvider) for _, p in ordered):
        # A local Docker lab needs two actually separate Compose projects and
        # health listeners. Do not accept the same WAF under two names.
        if (len({str(p.compose.parent.resolve(strict=True)) for _, p in ordered}) != 2 or
                len({p.health_port for _, p in ordered}) != 2):
            raise ValueError("two WAF adapters reference one local Docker deployment")
    return ordered


def _check_fence(fence, names, revision, policy_digest, phase):
    """An external authority must revalidate a live fencing lease each phase.

    A static signed *document* is NOT an active fencing lease. The production
    implementation must supply a network-authenticated, monotonic authority;
    this core does not invent a local-only or self-signed fallback.
    """
    if fence is None or not callable(getattr(fence, "assert_current", None)):
        raise ValueError("authenticated external fencing authority is required")
    if fence.assert_current(tuple(names), revision, policy_digest, phase) is not True:
        raise ValueError("external WAF fencing authority did not attest current lease")


def _validate_receipt_paths(output):
    if not isinstance(output, Path) or not output.is_absolute():
        raise ValueError("private absolute WAF fleet receipt required")
    local.private_directory(output.parent)
    if output.name in ("", ".", "..") or output.exists() or output.is_symlink():
        raise ValueError("WAF fleet receipt must not already exist")
    journal = output.parent / ("." + output.name + ".intent")
    if journal.exists() or journal.is_symlink():
        raise ValueError("unreconciled or duplicate WAF fleet intent")
    return journal


def _preflight(node, target, ruleset_digest):
    before = node.inspect()
    if (type(before) is not dict or
            before.get("mode") not in local.MODES or
            not re.fullmatch(r"sha256:[a-f0-9]{64}", before.get("imageId", "")) or
            before["mode"] == target or
            node.image_and_config(target) != before["imageId"] or
            node.image_and_config(before["mode"]) != before["imageId"] or
            node.observed_rule_digest() != ruleset_digest):
        raise ValueError("WAF node does not match signed baseline or target image")
    node.smoke(before["mode"])
    return dict(before)


def _same_runtime(node, expected, digest):
    return node.inspect() == expected and node.observed_rule_digest() == digest


def _restore(ordered, before, digest, fence, names, revision, policy_digest):
    """Best effort on *both* nodes; never report success on a partial restore."""
    outcomes = {}
    for name, node in reversed(ordered):
        try:
            _check_fence(fence, names, revision, policy_digest, "rollback-" + name)
            if not _same_runtime(node, before[name], digest):
                node.apply(before[name]["mode"])
            if not _same_runtime(node, before[name], digest):
                raise ValueError("WAF rollback runtime did not match prior pinned baseline")
            node.smoke(before[name]["mode"])
            outcomes[name] = True
        except Exception:
            outcomes[name] = False
    return outcomes


def coordinate(nodes, target, revision, policy_digest, ruleset_digest,
               output, *, fence=None):
    """Coordinate two signed-mode transitions under an injected *live* fence.

    A durable intent is recorded BEFORE the first mutation. Both adapters
    undergo independent preflight and target config checks. Every apply is
    followed by image+mode+observed-CRS verification and benign/malicious
    HTTP smoke. Failure, loss of fence, or missing durable final receipt
    triggers compensating rollback on BOTH nodes; fail even if compensation
    succeeds. The trusted revision floor is NEVER advanced by this core.
    """
    ordered = _validate_nodes(nodes)
    if target not in local.MODES or type(revision) is not int or revision < 1 or \
            type(policy_digest) is not str or not DIGEST.fullmatch(policy_digest) or \
            type(ruleset_digest) is not str or not DIGEST.fullmatch(ruleset_digest):
        raise ValueError("invalid signed WAF fleet target or policy digest")
    names = [name for name, _ in ordered]
    output = Path(output)
    journal = _validate_receipt_paths(output)
    # This lock only serializes this *one* controller. The provided authority
    # MUST do cross-host quorum/epoch fencing; local flock is insufficient.
    with local.operator_lock(output.parent):
        journal = _validate_receipt_paths(output)
        _check_fence(fence, names, revision, policy_digest, "preflight")
        before = {}
        for name, node in ordered:
            _check_fence(fence, names, revision, policy_digest, "check-" + name)
            before[name] = _preflight(node, target, ruleset_digest)
        if len({state["mode"] for state in before.values()}) != 1:
            raise ValueError("split-brain WAF baseline modes; refuse partial activation")
        if len({state["imageId"] for state in before.values()}) != 1:
            raise ValueError("WAF nodes are not on same image digest")
        # No secrets/raw requests/hostnames in durable receipts. A journal
        # left by a hard process kill is intentionally not auto-replayed.
        evidence = {
            "schemaVersion": 1, "scope": "two-node-fenced-WAF-software-candidate",
            "revision": revision, "policySha256": policy_digest,
            "rulesetSha256": ruleset_digest, "nodeIds": names,
            "previousMode": before[names[0]]["mode"],
            "requestedMode": target, "createdAtUtc": _current_utc(),
            "fleetAtomic": False, "trustedRevisionFloorAdvanced": False
        }
        # Exclusive fsync + no-overwrite (same safety contract as receipts).
        _check_fence(fence, names, revision, policy_digest, "before-journal")
        local.receipt(journal, {**evidence, "state": "intent-fsynced-mutation-may-start"})
        mutated = []
        try:
            for name, node in ordered:
                _check_fence(fence, names, revision, policy_digest, "before-apply-" + name)
                # A concurrent or partitioned controller may have changed
                # the other node. Verify all snapshots again before moving.
                for peer_name, peer in ordered:
                    wanted = ({"mode": target, "imageId": before[peer_name]["imageId"]}
                              if peer_name in mutated else before[peer_name])
                    if not _same_runtime(peer, wanted, ruleset_digest):
                        raise ValueError("WAF changed outside fenced transaction")
                # Include node in compensation even if apply throws AFTER a
                # remote mutation. The failure cannot be mistaken for no-op.
                mutated.append(name)
                node.apply(target)
                expected = {"mode": target, "imageId": before[name]["imageId"]}
                if not _same_runtime(node, expected, ruleset_digest):
                    raise ValueError("applied WAF changed image/mode/CRS inventory")
                node.smoke(target)
                _check_fence(fence, names, revision, policy_digest, "after-apply-" + name)
            _check_fence(fence, names, revision, policy_digest, "before-receipt")
            local.receipt(output, {
                **evidence, "result": "applied-uncommitted",
                "nodesVerified": names,
                "rollbackVerified": None,
                "completedAtUtc": _current_utc()
            })
            return "applied-uncommitted"
        except Exception:
            # No success receipt may exist unless it was durably committed.
            # If a write unexpectedly succeeded but threw, we must still
            # treat the outcome as indeterminate and require reconciliation.
            rollback = _restore(ordered, before, ruleset_digest, fence,
                                names, revision, policy_digest)
            error_receipt = output.parent / ("." + output.name + ".failure")
            try:
                local.receipt(error_receipt, {
                    **evidence, "result": "rolled-back" if all(rollback.values())
                    else "rollback-failed", "rollbackVerified": rollback,
                    "completedAtUtc": _current_utc()
                })
            except (OSError, ValueError):
                raise ValueError("fleet WAF outcome indeterminate; private failure audit unavailable") from None
            raise ValueError("fleet WAF transaction failed; inspect private reconciliation evidence") from None
