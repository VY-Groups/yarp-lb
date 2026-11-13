"""Validate that a profiling run generated machine-readable evidence."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
csv_file = root / "runtime-counters.csv"
summary_file = root / "k6-summary.json"
before_file = root / "before.json"
after_file = root / "after.json"
for path in (csv_file, summary_file, before_file, after_file):
    assert path.exists() and path.stat().st_size > 0, f"Missing profile evidence: {path}"
text = csv_file.read_text(encoding="utf-8-sig")
assert len(text.splitlines()) >= 4, "Too few diagnostic-counter samples"
assert "System.Runtime" in text or "cpu" in text.lower(), "No .NET runtime counter evidence"
before, after = (json.loads(x.read_text()) for x in (before_file, after_file))
k6 = json.loads(summary_file.read_text())["metrics"]
report = {
    "lab": "single shared GitHub runner, collector overhead included",
    "samples_line_count": len(text.splitlines()),
    "server_gc_enabled": before.get("serverGc"),
    "working_set_change_bytes": after["processWorkingSetBytes"] - before["processWorkingSetBytes"],
    "process_cpu_time_change_ms": round(after.get("processCpuTimeMs", 0) - before.get("processCpuTimeMs", 0), 2),
    "total_allocated_bytes_change": after.get("allocatedBytesTotal", 0) - before.get("allocatedBytesTotal", 0),
    "k6_requests": k6["http_reqs"]["count"],
    "k6_p95_ms": k6["http_req_duration"]["p(95)"],
    "k6_p99_ms": k6["http_req_duration"]["p(99)"],
}
(root / "profile-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
