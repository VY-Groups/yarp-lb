"""Compare same-run k6 performance phases. Evidence, not a performance guarantee."""
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
phases = ("direct", "proxy-http", "proxy-https", "proxy-https-no-reuse")
def row(name):
    report = json.loads((root / f"{name}.json").read_text(encoding="utf-8"))
    metrics = report["metrics"]
    req = metrics["http_reqs"]["count"]
    dur = metrics["http_req_duration"]
    fail = metrics["http_req_failed"]["value"]
    assert req > 100 and fail < 0.01, (name, req, fail)
    if name.startswith("proxy-https"):
        negotiated = metrics.get("lab_tls_negotiated_responses", {}).get("count", 0)
        assert negotiated >= req * 0.999, (name, "TLS not confirmed for every request", negotiated, req)
    return {
        "requests": int(req),
        "requests_per_second": round(req / 20.0, 2),
        "latency_p95_ms": round(dur["p(95)"], 3),
        "latency_p99_ms": round(dur["p(99)"], 3),
        "failed_rate": round(fail, 6),
        "tls_handshake_avg_ms": round(metrics.get("http_req_tls_handshaking", {}).get("avg", 0), 3),
        "connection_setup_avg_ms": round(metrics.get("http_req_connecting", {}).get("avg", 0), 3),
        "tls_negotiated_responses": int(metrics.get("lab_tls_negotiated_responses", {}).get("count", 0)),
    }

results = {name: row(name) for name in phases}
direct = results["direct"]
for mode in ("proxy-http", "proxy-https", "proxy-https-no-reuse"):
    proxy = results[mode]
    proxy["p95_overhead_vs_direct_ms"] = round(
        proxy["latency_p95_ms"] - direct["latency_p95_ms"], 3
    )
    proxy["throughput_ratio_vs_direct"] = round(
        proxy["requests_per_second"] / direct["requests_per_second"], 3
    )

before = json.loads((root / "before.json").read_text())
after = json.loads((root / "after.json").read_text())
memory = {
    "working_set_bytes_before": before["processWorkingSetBytes"],
    "working_set_bytes_after": after["processWorkingSetBytes"],
    "working_set_delta_bytes": (
        after["processWorkingSetBytes"] - before["processWorkingSetBytes"]
    ),
    "gc_collections_delta": {
        f"gen{i}": after[f"gc{i}Collections"] - before[f"gc{i}Collections"]
        for i in range(3)
    },
}
out = {
    "environment": "shared GitHub-hosted Ubuntu VM, loopback trivial test backends",
    "concurrency": 75,
    "seconds_per_phase": 20,
    "phases_sequential_not_identical_cpu_conditions": True,
    "https_certificate": "ephemeral self-signed loopback lab; insecureSkipTLSVerify test-only",
    "connection_reuse_note": "proxy-https uses keep-alive; proxy-https-no-reuse disables TCP keep-alive per request",
    "benchmarks": results,
    "process_memory": memory,
}
(root / "comparison.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
print(json.dumps(out, indent=2))
