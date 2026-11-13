"""Report process memory and GC trends without claiming a leak or lack of one."""
import json
import pathlib
import sys

directory = pathlib.Path(sys.argv[1])
values = []
for line in (directory / "process-samples.jsonl").read_text(encoding="utf-8").splitlines():
    if line.strip():
        values.append(json.loads(line))
assert len(values) >= 5, "Not enough memory samples for a soak report"
end = json.loads((directory / "after.json").read_text(encoding="utf-8"))
start = json.loads((directory / "before.json").read_text(encoding="utf-8"))
summary = json.loads((directory / "k6-summary.json").read_text(encoding="utf-8"))["metrics"]
report = {
    "note": "Loopback/hosted runner only. Working-set trend alone cannot prove a leak.",
    "samples": len(values),
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
