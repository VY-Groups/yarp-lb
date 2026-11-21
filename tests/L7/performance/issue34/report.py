#!/usr/bin/env python3
"""Validate and summarize paired GatewayCore allocation runs.

This reports isolated CI evidence only; it does not certify production scale.
"""
from __future__ import annotations

import json
import math
import re
import statistics
from pathlib import Path
from typing import Any


T95 = {
    2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447,
    7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201,
    12: 2.179, 13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120,
    17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 21: 2.080,
    22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
    27: 2.052, 28: 2.048, 29: 2.045,
}


def _number(value: Any, path: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{path} must be a finite number")
    return float(value)


def _validate_measurement(measurement: dict[str, Any], path: str) -> None:
    duration = _number(measurement.get("duration_seconds"), path + ".duration_seconds")
    requests = _number(measurement.get("requests"), path + ".requests")
    errors = _number(measurement.get("errors"), path + ".errors")
    failed_rate = _number(measurement.get("failed_rate"), path + ".failed_rate")
    checks_rate = _number(measurement.get("checks_rate"), path + ".checks_rate")
    p95 = _number(measurement.get("p95_ms"), path + ".p95_ms")
    p99 = _number(measurement.get("p99_ms"), path + ".p99_ms")
    if not 30 <= duration <= 115:
        raise ValueError(f"{path}: duration outside existing 30..115 second acceptance")
    if requests < 1000:
        raise ValueError(f"{path}: fewer than 1000 requests")
    if not requests.is_integer() or not errors.is_integer():
        raise ValueError(f"{path}: request and error counters must be whole numbers")
    if errors < 0 or errors > requests or abs(failed_rate - errors / requests) > 1 / requests + 1e-9:
        raise ValueError(f"{path}: error count and failed rate do not match")
    if not 0 <= failed_rate < 0.01:
        raise ValueError(f"{path}: failed rate does not meet existing <1% acceptance")
    if not 0 <= failed_rate <= 1 or not 0 <= checks_rate <= 1:
        raise ValueError(f"{path}: request/check rates must be between 0 and 1")
    if checks_rate <= 0.995:
        raise ValueError(f"{path}: checks rate does not meet existing >99.5% acceptance")
    if p95 < 0 or p99 < p95:
        raise ValueError(f"{path}: p95/p99 latency ordering is invalid")
    if p95 >= 2500 or p99 >= 5000:
        raise ValueError(f"{path}: latency exceeds existing p95/p99 acceptance")
    for key in ("rps", "allocated_bytes", "working_set_delta_bytes", "gc0_delta",
                "gc1_delta", "gc2_delta", "gc_pause_ms_delta", "managed_heap_delta_bytes"):
        _number(measurement.get(key), path + "." + key)
    if measurement["rps"] <= 0:
        raise ValueError(f"{path}: request rate must be positive")
    expected_rps = requests / duration
    # k6's rate uses its active sample window while duration_seconds is the
    # outer process wall time. Allow modest startup/teardown timing skew, but
    # reject rates that cannot describe the recorded request count.
    rps_tolerance = max(1.0, expected_rps * 0.15)
    if abs(measurement["rps"] - expected_rps) > rps_tolerance:
        raise ValueError(f"{path}: request rate does not match request count and duration")
    if measurement["allocated_bytes"] < 0:
        raise ValueError(f"{path}: allocated bytes decreased/reset")
    for key in ("gc0_delta", "gc1_delta", "gc2_delta", "gc_pause_ms_delta"):
        if measurement[key] < 0:
            raise ValueError(f"{path}: {key} decreased/reset")



def _validate_workload(workload: dict[str, Any], path: str) -> None:
    """Refuse incomplete/malformed load metadata before claiming matched runs."""
    required = ("vus", "duration", "payload_bytes", "connection_reuse")
    if any(field not in workload for field in required):
        raise ValueError(f"{path}: missing required workload parameters")
    if type(workload["vus"]) is not int or not 1 <= workload["vus"] <= 10_000:
        raise ValueError(f"{path}: invalid virtual-user count")
    duration = workload["duration"]
    if not isinstance(duration, str) or not re.fullmatch(r"[0-9]{1,3}s", duration) or (
            not 30 <= int(duration[:-1]) <= 115):
        raise ValueError(f"{path}: workload duration outside 30..115 seconds")
    if type(workload["payload_bytes"]) is not int or not 0 <= workload["payload_bytes"] <= 1_048_576:
        raise ValueError(f"{path}: invalid payload byte count")
    if type(workload["connection_reuse"]) is not bool:
        raise ValueError(f"{path}: connection-reuse setting must be boolean")


def _mean_ci(values: list[float]) -> dict[str, float | int]:
    if len(values) < 3:
        raise ValueError("at least three paired rounds are required")
    mean = statistics.fmean(values)
    stddev = statistics.stdev(values)
    # Beyond the 29-DF table, retain the last (slightly conservative)
    # Student-t value rather than silently using a narrower normal interval.
    critical = T95.get(len(values) - 1, T95[29])
    margin = critical * stddev / math.sqrt(len(values))
    return {
        "count": len(values),
        "mean": round(mean, 3),
        "sample_stddev": round(stddev, 3),
        "ci95_low": round(mean - margin, 3),
        "ci95_high": round(mean + margin, 3),
    }


def build_report(records: list[dict[str, Any]], baseline_commit: str,
                 candidate_commit: str) -> dict[str, Any]:
    if len(records) < 6 or len(records) % 2:
        raise ValueError("records must contain before and after samples for at least three rounds")
    by_round: dict[int, dict[str, dict[str, Any]]] = {}
    observed_order: dict[int, list[str]] = {}
    workloads: list[dict[str, Any]] = []
    for index, record in enumerate(records):
        if record.get("revision") not in ("before", "after"):
            raise ValueError(f"records[{index}].revision must be before or after")
        round_number = record.get("round")
        if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number < 1:
            raise ValueError(f"records[{index}].round must be a positive integer")
        expected_commit = baseline_commit if record["revision"] == "before" else candidate_commit
        if record.get("commit") != expected_commit:
            raise ValueError(f"records[{index}] commit does not match its pinned revision")
        workload = record.get("workload")
        if not isinstance(workload, dict):
            raise ValueError(f"records[{index}] is missing matched workload metadata")
        _validate_workload(workload, f"records[{index}].workload")
        workloads.append(workload)
        group = by_round.setdefault(round_number, {})
        observed_order.setdefault(round_number, []).append(record["revision"])
        if record["revision"] in group:
            raise ValueError(f"duplicate {record['revision']} sample in round {round_number}")
        direct = record.get("direct")
        proxy = record.get("proxy")
        if not isinstance(direct, dict) or not isinstance(proxy, dict):
            raise ValueError(f"records[{index}] requires direct and proxy measurements")
        _validate_measurement(direct, f"round{round_number}.{record['revision']}.direct")
        _validate_measurement(proxy, f"round{round_number}.{record['revision']}.proxy")
        if direct["duration_seconds"] <= 0:
            raise ValueError("direct duration must be positive")
        estimated = ((proxy["allocated_bytes"] - direct["allocated_bytes"] *
                      proxy["duration_seconds"] / direct["duration_seconds"]) /
                     proxy["requests"])
        record["estimated_extra_bytes_per_proxy_request"] = round(estimated, 3)
        group[record["revision"]] = record

    rounds = sorted(by_round)
    if rounds != list(range(1, len(rounds) + 1)):
        raise ValueError("round numbers must be contiguous starting at 1")
    if any(workload != workloads[0] for workload in workloads[1:]):
        raise ValueError("before/after samples did not use identical workload settings")
    for number in rounds:
        expected_order = ["before", "after"] if number % 2 == 1 else ["after", "before"]
        if observed_order[number] != expected_order:
            raise ValueError(f"round {number} does not use the required alternating before/after order")
    paired = []
    before_values = []
    after_values = []
    delta_metrics: dict[str, dict[str, list[float]]] = {}
    for number in rounds:
        group = by_round[number]
        if set(group) != {"before", "after"}:
            raise ValueError(f"round {number} is missing a before or after measurement")
        before = group["before"]["estimated_extra_bytes_per_proxy_request"]
        after = group["after"]["estimated_extra_bytes_per_proxy_request"]
        before_values.append(before)
        after_values.append(after)
        paired.append({
            "round": number,
            "before_extra_bytes_per_proxy_request": before,
            "after_extra_bytes_per_proxy_request": after,
            "candidate_minus_baseline_bytes_per_proxy_request": round(after - before, 3),
        })
        for mode in ("direct", "proxy"):
            before_measure = group["before"][mode]
            after_measure = group["after"][mode]
            metrics = delta_metrics.setdefault(mode, {})
            comparisons = {
                "rps": (after_measure["rps"], before_measure["rps"]),
                "p95_ms": (after_measure["p95_ms"], before_measure["p95_ms"]),
                "p99_ms": (after_measure["p99_ms"], before_measure["p99_ms"]),
                "failed_rate": (after_measure["failed_rate"], before_measure["failed_rate"]),
                "allocated_bytes_per_request": (
                    after_measure["allocated_bytes"] / after_measure["requests"],
                    before_measure["allocated_bytes"] / before_measure["requests"]),
                "working_set_delta_bytes": (after_measure["working_set_delta_bytes"],
                                            before_measure["working_set_delta_bytes"]),
                "managed_heap_delta_bytes": (after_measure["managed_heap_delta_bytes"],
                                              before_measure["managed_heap_delta_bytes"]),
                "gc0_delta": (after_measure["gc0_delta"], before_measure["gc0_delta"]),
                "gc1_delta": (after_measure["gc1_delta"], before_measure["gc1_delta"]),
                "gc2_delta": (after_measure["gc2_delta"], before_measure["gc2_delta"]),
                "gc_pause_ms_delta": (after_measure["gc_pause_ms_delta"],
                                      before_measure["gc_pause_ms_delta"]),
            }
            for metric, (after_value, before_value) in comparisons.items():
                metrics.setdefault(metric, []).append(float(after_value) - float(before_value))

    delta = [item["candidate_minus_baseline_bytes_per_proxy_request"] for item in paired]
    summary = _mean_ci(delta)
    summary["interpretation"] = (
        "candidate lower allocation observed with paired 95% interval excluding zero"
        if summary["ci95_high"] < 0 else
        "candidate higher allocation observed with paired 95% interval excluding zero"
        if summary["ci95_low"] > 0 else
        "paired interval includes zero; improvement not established by this sample"
    )
    return {
        "evidence_scope": "single shared GitHub-hosted runner; synthetic HTTP lab only",
        "production_claim": False,
        "baseline_commit": baseline_commit,
        "candidate_commit": candidate_commit,
        "matched_workload": workloads[0],
        "paired_rounds": len(rounds),
        "order_alternated": True,
        "paired_extra_allocation_delta": summary,
        "paired_metric_deltas": {
            mode: {metric: _mean_ci(values) for metric, values in metrics.items()}
            for mode, metrics in delta_metrics.items()
        },
        "mean_baseline_extra_bytes_per_proxy_request": round(statistics.fmean(before_values), 3),
        "mean_candidate_extra_bytes_per_proxy_request": round(statistics.fmean(after_values), 3),
        "paired_rounds_detail": paired,
        "runs": records,
        "limitations": [
            "The allocation estimate includes gateway logging, health, metrics, and other background work.",
            "The single-runner result is not a customer workload or production capacity claim.",
            "Trace artifacts are bounded diagnostic evidence and require separate human attribution.",
        ],
    }


def write_report(path: Path, records_path: Path, baseline_commit: str,
                 candidate_commit: str) -> dict[str, Any]:
    records = json.loads(records_path.read_text(encoding="utf-8"))
    if not isinstance(records, list):
        raise ValueError("run record input must be a JSON array")
    report = build_report(records, baseline_commit, candidate_commit)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report
