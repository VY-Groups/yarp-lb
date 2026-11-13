"""Report process memory and GC trends without claiming a leak or lack of one."""
import json
import os
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
values = []
for line in (directory / "process-samples.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        values.append(json.loads(line))
assert len(values) >= 5, "Not enough memory samples for a soak report"
after_file = directory / "after.json"
end = json.loads(after_file.read_text(encoding="utf-8")) if after_file.exists() else values[-1]
start = json.loads((directory / "before.json").read_text(encoding="utf-8"))
summary = json.loads((directory / "k6-summary.json").read_text(encoding="utf-8"))["metrics"]
# Custom five-minute k6 Trends are absent in older runs. Never infer p99
# drift from a single aggregate value. A run without trends is marked unknown.
five_minute = []
for i in range(48):
    measure = summary.get(f"soak_p99_5m_window_{i}")
    if not measure:
        continue
    p99 = measure.get("p(99)")
    if p99 is None:
        continue
    five_minute.append({"start_minute": i * 5, "p99_ms": round(p99, 3)})
# Strict opt-in gate: the global error percentage can hide a 55-minute outage
# after millions of early successes. Every expected five-minute slice must
# contain requests and meet its own availability threshold.
expected_windows = int(os.environ.get("SOAK_EXPECTED_WINDOWS", "0"))
if expected_windows < 0 or expected_windows > 48:
    raise ValueError("SOAK_EXPECTED_WINDOWS must be 0..48")
availability_windows = []
for i in range(expected_windows):
    m = summary.get(f"soak_failure_rate_5m_window_{i}")
    if m is None:
        availability_windows.append({"start_minute": i * 5, "requests": 0,
                                     "failure_rate": None, "passed": False})
        continue
    count = int(m.get("passes", 0)) + int(m.get("fails", 0))
    rate = m.get("value")
    passed = count > 0 and rate is not None and rate < 0.01
    availability_windows.append({"start_minute": i * 5, "requests": count,
                                 "failure_rate": rate, "passed": passed})
soak_continuity_pass = all(x["passed"] for x in availability_windows) if expected_windows else None
first = five_minute[:3]
last = five_minute[-3:]
early = (sum(x["p99_ms"] for x in first) / len(first)) if first else None
late = (sum(x["p99_ms"] for x in last) / len(last)) if last else None
p99_ratio = round(late / early, 3) if early and late else None
# Five-minute windows are indicative percentiles; no automated leak diagnosis.
memory_quarters = []
chunk = max(1, len(values) // 4)
for idx in range(0, len(values), chunk):
    part = values[idx:idx + chunk]
    if part:
        memory_quarters.append({
            "start_sample": idx,
            "mean_working_set_bytes": round(sum(x["processWorkingSetBytes"] for x in part) / len(part)),
            "gen2_collections_delta": part[-1]["gc2Collections"] - part[0]["gc2Collections"],
        })
report = {
    "expected_five_minute_availability_windows": expected_windows,
    "five_minute_availability": availability_windows,
    "sustained_availability_pass": soak_continuity_pass,
    "five_minute_p99_ms": five_minute,
    "p99_drift_ratio_last_three_vs_first_three": p99_ratio,
    "p99_drift_assessment": "insufficient-window-evidence" if len(five_minute) < 6
        else ("elevated-late-p99-investigate" if p99_ratio is not None and p99_ratio > 1.5
              else "no-large-late-p99-drift-observed"),
    "working_set_quarter_trends": memory_quarters,
    "note": "Loopback/hosted runner only. Working-set trend alone cannot prove a leak.",
    "samples": len(values),
    "final_process_metrics_source": "after-request" if after_file.exists() else "last-valid-sample",
    "server_gc_enabled": end.get("serverGc"),
    "sample_duration_minutes_approx": round((len(values)-1)*0.5, 2),
    "working_set_initial_bytes": start["processWorkingSetBytes"],
    "working_set_final_bytes": end["processWorkingSetBytes"],
    "working_set_peak_sample_bytes": max(x["processWorkingSetBytes"] for x in values),
    "working_set_delta_bytes": end["processWorkingSetBytes"]-start["processWorkingSetBytes"],
    "working_set_first_half_mean_bytes": round(
        sum(x["processWorkingSetBytes"] for x in values[:len(values)//2]) /
        max(len(values)//2,1)),
    "working_set_second_half_mean_bytes": round(
        sum(x["processWorkingSetBytes"] for x in values[len(values)//2:]) /
        max(len(values)-len(values)//2,1)),
    "managed_heap_final_bytes": end["gcManagedHeapBytes"],
    "allocated_bytes_delta": end.get("allocatedBytesTotal",0)-start.get("allocatedBytesTotal",0),
    "cpu_time_delta_ms": round(
        end.get("processCpuTimeMs",0)-start.get("processCpuTimeMs",0),2),
    "thread_pool_threads_final": end.get("threadPoolThreadCount"),
    "gen2_collections_delta": end["gc2Collections"] - start["gc2Collections"],
    "request_count": summary["http_reqs"]["count"],
    "failure_rate": summary["http_req_failed"]["value"],
    "duration_p95_ms": summary["http_req_duration"]["p(95)"],
    "duration_p99_ms": summary["http_req_duration"]["p(99)"],
}
(directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))

if expected_windows and not soak_continuity_pass:
    raise SystemExit("SOAK_SLO_FAIL: missing or failed five-minute availability window")
