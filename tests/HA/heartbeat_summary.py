#!/usr/bin/env python3
"""Diagnostic-only analysis of HA process heartbeats at 100ms intervals.

Do not infer that one missing heartbeat proves a gateway bug or that multiple
missing heartbeats prove GitHub-hosted runner scheduling. Correlate windows and
inspect OS/CLR evidence before making a causal claim. Never change HA status.
"""
import csv
import json
from pathlib import Path
import sys

EXPECTED_EARLY = {
    "ha-harness", "backend-a", "backend-b",
    "gateway-1", "gateway-2", "health-aware-ingress",
}
GAP_MS = 250


def analyze(root: Path) -> dict:
    clocks = {}
    gap_events = []
    failures = []
    for file in sorted(root.glob("heartbeat-*.csv")):
        role = file.stem[len("heartbeat-"):]
        with file.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            expected = {
                "role", "pid", "utc_unix_ms", "monotonic_ticks",
                "stopwatch_frequency", "threadpool_threads",
                "pending_work_items", "cpu_total_ms",
            }
            if not expected.issubset(reader.fieldnames or []):
                failures.append(role + ": heartbeat columns missing")
                continue
            try:
                rows = list(reader)
                for row in rows:
                    if row["role"] != role:
                        raise ValueError("file role differs from sampled role")
                ticks = [int(x["monotonic_ticks"]) for x in rows]
                utc = [int(x["utc_unix_ms"]) for x in rows]
                freq = [int(x["stopwatch_frequency"]) for x in rows]
                if any(v <= 0 for v in freq) or len(set(freq)) != 1:
                    raise ValueError("invalid stopwatch frequency")
                if any(b <= a for a, b in zip(ticks, ticks[1:])):
                    raise ValueError("nonmonotonic heartbeat clock")
                events = []
                for i in range(1, len(rows)):
                    duration = (ticks[i] - ticks[i - 1]) * 1000.0 / freq[i]
                    if duration >= GAP_MS:
                        event = {
                            "role": role,
                            "start_utc_ms": utc[i - 1],
                            "end_utc_ms": utc[i],
                            "duration_ms": round(duration, 2),
                            "start_ticks": ticks[i - 1],
                            "end_ticks": ticks[i],
                            "threadpool_pending_after": int(rows[i]["pending_work_items"]),
                        }
                        events.append(event)
                        gap_events.append(event)
                clocks[role] = {
                    "pid": int(rows[0]["pid"]) if rows else None,
                    "samples": len(rows),
                    "first_utc_ms": utc[0] if rows else None,
                    "last_utc_ms": utc[-1] if rows else None,
                    "maximum_gap_ms": max((e["duration_ms"] for e in events), default=0),
                    "gaps_ge_250ms": len(events),
                    "maximum_threadpool_pending": max(
                        (int(x["pending_work_items"]) for x in rows), default=0),
                    "events": events[:50],
                }
            except (ValueError, KeyError, TypeError) as ex:
                failures.append(f"{role}: {type(ex).__name__}: {ex}")
    missing = sorted(EXPECTED_EARLY - set(clocks))
    samples = []
    timeline = root / "prekill-request-timeline.csv"
    if timeline.exists():
        with timeline.open(newline="", encoding="utf-8-sig") as stream:
            for row in csv.DictReader(stream):
                try:
                    samples.append({
                        "phase": row["phase"],
                        "start_utc_ms": int(row["start_utc_ms"]),
                        "end_utc_ms": int(row["end_utc_ms"]),
                        "status": int(row["status"]),
                        "error": row["error"],
                    })
                except (ValueError, KeyError) as ex:
                    failures.append("invalid request-timeline row: " + str(ex))
                    break
    bad = [x for x in samples if x["status"] != 200 or x["error"]]
    correlations = []
    for event in gap_events:
        overlapping = sorted({
            other["role"] for other in gap_events
            if other["role"] != event["role"] and
            min(other["end_utc_ms"], event["end_utc_ms"]) -
            max(other["start_utc_ms"], event["start_utc_ms"]) >= 100
        })
        if overlapping:
            correlations.append({
                "role": event["role"],
                "overlap_roles": overlapping,
                "interval_utc_ms": [event["start_utc_ms"], event["end_utc_ms"]],
                "hypothesis_only": "multiple-process scheduler/host pause candidate",
            })
    return {
        "diagnostics_complete": not missing and not failures,
        "expected_early_missing": missing,
        "parse_failures": failures,
        "sampling_target_ms": 100,
        "gap_threshold_ms": GAP_MS,
        "clocks": clocks,
        "cross_process_gap_candidates": correlations[:60],
        "prekill_requests_recorded": len(samples),
        "prekill_request_failures": len(bad),
        "prekill_failure_samples": bad[:50],
        "interpretation": (
            "Gaps in harness and multiple child processes suggest a shared host "
            "pause; isolated gaps suggest one process/ThreadPool. Neither alone "
            "proves cause. Missing or failed HA run remains a failure."
        ),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: heartbeat_summary.py <ha-artifact-directory>", file=sys.stderr)
        return 64
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    report = analyze(folder)
    (folder / "heartbeat-summary.json").write_text(json.dumps(report, indent=2))
    print(json.dumps({
        "diagnostics_complete": report["diagnostics_complete"],
        "expected_early_missing": report["expected_early_missing"],
        "parse_failures": report["parse_failures"],
        "roles": {k: {s: v[s] for s in ("samples", "maximum_gap_ms", "gaps_ge_250ms",
                                      "maximum_threadpool_pending")}
                  for k, v in report["clocks"].items()},
        "prekill_requests_recorded": report["prekill_requests_recorded"],
        "prekill_request_failures": report["prekill_request_failures"],
        "correlated_gap_events": len(report["cross_process_gap_candidates"]),
    }, indent=2))
    # Diagnostics never override the separate strict HA test's exit code.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
