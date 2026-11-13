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
    "working_set_initial_bytes": start["processWorkingSetBytes"],
    "working_set_final_bytes": end["processWorkingSetBytes"],
    "working_set_peak_sample_bytes": max(x["processWorkingSetBytes"] for x in values),
    "managed_heap_final_bytes": end["gcManagedHeapBytes"],
    "gen2_collections_delta": end["gc2Collections"] - start["gc2Collections"],
    "request_count": summary["http_reqs"]["count"],
    "failure_rate": summary["http_req_failed"]["value"],
    "duration_p95_ms": summary["http_req_duration"]["p(95)"],
    "duration_p99_ms": summary["http_req_duration"]["p(99)"],
}
(directory / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
