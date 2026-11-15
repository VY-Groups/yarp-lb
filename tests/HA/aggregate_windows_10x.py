#!/usr/bin/env python3
"""Fail-closed aggregate for ten REAL independent Windows HA matrix artifacts.

This does not re-run or alter individual HA thresholds. Missing data, malformed
run results or a failed child run cannot be hidden by a green matrix check.
"""
import argparse
import json
import math
from pathlib import Path
from typing import Any

EXPECTED = 10
MAX_FAILURE_AFTER_KILL_MS = 2000.0


class EvidenceFailure(ValueError):
    pass


def nonnegative(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (float, int)):
        raise EvidenceFailure(f"{name}: expected numeric field")
    number = float(value)
    if not math.isfinite(number) or number < 0:
        raise EvidenceFailure(f"{name}: must be finite, nonnegative")
    return number


def analyze(root: Path, source_sha: str, run_id: str) -> dict:
    if not source_sha or not run_id:
        raise EvidenceFailure("exact source SHA and Actions run ID are required")
    expected = {f"ha-windows-repeat-{n}" for n in range(1, EXPECTED + 1)}
    actual = {p.name for p in root.iterdir() if p.is_dir()} if root.is_dir() else set()
    if actual != expected:
        raise EvidenceFailure(
            f"Exactly 10 unique HA artifact directories required; missing={sorted(expected-actual)}, unexpected={sorted(actual-expected)}")
    evidence = []
    for n in range(1, EXPECTED + 1):
        folder = root / f"ha-windows-repeat-{n}"
        result_path = folder / "ha-results.json"
        heartbeat_path = folder / "heartbeat-summary.json"
        if not result_path.is_file() or not heartbeat_path.is_file():
            raise EvidenceFailure(f"repeat {n}: missing result or heartbeat evidence")
        try:
            result = json.loads(result_path.read_text(encoding="utf-8-sig"))
            heartbeat = json.loads(heartbeat_path.read_text(encoding="utf-8-sig"))
        except (ValueError, UnicodeError) as exc:
            raise EvidenceFailure(f"repeat {n}: invalid JSON evidence: {exc}") from exc
        if result.get("passed") is not True:
            raise EvidenceFailure(f"repeat {n}: HA acceptance not passed")
        checks = result.get("checks")
        if not isinstance(checks, list):
            raise EvidenceFailure(f"repeat {n}: checks array missing")
        fault = [x["evidence"] for x in checks
                 if isinstance(x, dict) and x.get("description") == "continuous-load-failover"
                 and isinstance(x.get("evidence"), dict)]
        if len(fault) != 1:
            raise EvidenceFailure(f"repeat {n}: precisely one continuous-load-failover evidence required")
        f = fault[0]
        if f.get("faultType") != "gateway-process-kill" or f.get("lastFailureAfterKillUnder2s") is not True:
            raise EvidenceFailure(f"repeat {n}: failed strict kill-window gate")
        before = nonnegative(f.get("beforeRequests"), f"{n}.beforeRequests")
        after = nonnegative(f.get("afterRequests"), f"{n}.afterRequests")
        failed = nonnegative(f.get("afterFailures"), f"{n}.afterFailures")
        if before < 24 or after < 24 or failed > after:
            raise EvidenceFailure(f"repeat {n}: insufficient traffic or impossible failure count")
        last_raw = f.get("lastObservedFailureOffsetMs")
        if failed > 0:
            last = nonnegative(last_raw, f"{n}.lastObservedFailureOffsetMs")
            if last > MAX_FAILURE_AFTER_KILL_MS:
                raise EvidenceFailure(f"repeat {n}: last failure exceeds 2000ms")
        else:
            if last_raw is not None:
                raise EvidenceFailure(f"repeat {n}: zero failures but non-null last-failure offset")
            last = None
        if heartbeat.get("diagnostics_complete") is not True or heartbeat.get("parse_failures"):
            raise EvidenceFailure(f"repeat {n}: heartbeat diagnostics missing/incomplete")
        clocks = heartbeat.get("clocks")
        if not isinstance(clocks, dict) or not all(
            x in clocks for x in ("ha-harness", "backend-a", "backend-b",
                                   "gateway-1", "gateway-2", "health-aware-ingress")
        ):
            raise EvidenceFailure(f"repeat {n}: expected process heartbeat roles absent")
        worst_gap = max(nonnegative(x.get("maximum_gap_ms"), f"{n}.heartbeat_gap")
                        for x in clocks.values())
        prekill_errors = nonnegative(heartbeat.get("prekill_request_failures"),
                                     f"{n}.prekill_request_failures")
        evidence.append({
            "repeat": n,
            "before_requests": int(before),
            "after_requests": int(after),
            "failed_after_kill": int(failed),
            "last_failed_response_after_kill_ms": last,
            "p99_latency_ms": nonnegative(f.get("p99LatencyMs"), f"{n}.p99LatencyMs"),
            "largest_heartbeat_gap_ms": worst_gap,
            "prekill_failures_recorded_not_erased": int(prekill_errors)
        })
    measured = [x["last_failed_response_after_kill_ms"] for x in evidence
                if x["last_failed_response_after_kill_ms"] is not None]
    summary = {
        "result": "TEN_INDEPENDENT_CI_RUNS_PASSED",
        "source_sha": source_sha, "github_run_id": run_id,
        "runs_verified": len(evidence),
        "total_failed_requests_after_kill": sum(x["failed_after_kill"] for x in evidence),
        "worst_recorded_last_failure_after_kill_ms": max(measured) if measured else None,
        "runs_with_no_post_kill_failure": len(evidence) - len(measured),
        "worst_heartbeat_gap_ms": max(x["largest_heartbeat_gap_ms"] for x in evidence),
        "prekill_failures_recorded": sum(x["prekill_failures_recorded_not_erased"] for x in evidence),
        "per_run": evidence,
        "production_physical_ha_certified": False,
        "note": "This verifies one CI execution on ten disposable Windows runners, not physical two-host failure-domain certification. Pre-kill warmup failures are preserved as observed, not silently classified as success."
    }
    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifacts", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        verdict = analyze(args.artifacts, args.sha, args.run_id)
    except (EvidenceFailure, OSError) as exc:
        print(f"NO-GO: {exc}")
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k: v for k, v in verdict.items() if k != "per_run"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
