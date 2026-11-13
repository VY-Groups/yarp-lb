"""Contract checks for the soak summary analyzer, no .NET/k6 required."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

script = Path(__file__).with_name("soak_summary.py")
with tempfile.TemporaryDirectory() as folder:
    root = Path(folder)
    vals = []
    for i in range(14):
        vals.append({
            "processWorkingSetBytes": 20000000 + i * 120000,
            "gcManagedHeapBytes": 6000000 + i * 15000,
            "gc2Collections": i // 5,
        })
    (root / "process-samples.jsonl").write_text(
        "\n".join(json.dumps(x) for x in vals), encoding="utf-8"
    )
    (root / "before.json").write_text(
        json.dumps({**vals[0], "allocatedBytesTotal": 10, "processCpuTimeMs": 0}),
        encoding="utf-8",
    )
    (root / "after.json").write_text(
        json.dumps({**vals[-1], "allocatedBytesTotal": 300000, "processCpuTimeMs": 300}),
        encoding="utf-8",
    )
    metrics = {
        "http_reqs": {"count": 20000},
        "http_req_failed": {"value": 0.0},
        "http_req_duration": {"p(95)": 25.0, "p(99)": 65.0},
    }
    for i in range(12):
        metrics[f"soak_p99_5m_window_{i}"] = {"p(99)": 30.0 + i * 2.5}
    (root / "k6-summary.json").write_text(
        json.dumps({"metrics": metrics}), encoding="utf-8"
    )
    result = subprocess.run([sys.executable, str(script), str(root)],
                            capture_output=True, text=True, check=True)
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert report["samples"] == 14
    assert len(report["five_minute_p99_ms"]) == 12
    assert report["p99_drift_ratio_last_three_vs_first_three"] > 1
    assert report["gen2_collections_delta"] == vals[-1]["gc2Collections"]
    assert len(report["working_set_quarter_trends"]) >= 4
    assert "working_set_quarter_trends" in result.stdout

    # Every five-minute slice must have traffic and satisfy availability.
    for i in range(12):
        metrics[f"soak_failure_rate_5m_window_{i}"] = {
            "passes": 0, "fails": 2000, "value": 0.0,
        }
    (root / "k6-summary.json").write_text(json.dumps({"metrics": metrics}), encoding="utf-8")
    strict_env = {**os.environ, "SOAK_EXPECTED_WINDOWS": "12"}
    subprocess.run([sys.executable, str(script), str(root)], env=strict_env,
                   capture_output=True, text=True, check=True)
    strict = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert strict["sustained_availability_pass"] is True
    assert len(strict["five_minute_availability"]) == 12
    metrics["soak_failure_rate_5m_window_7"] = {
        "passes": 800, "fails": 1200, "value": 0.4,
    }
    (root / "k6-summary.json").write_text(json.dumps({"metrics": metrics}), encoding="utf-8")
    failed = subprocess.run([sys.executable, str(script), str(root)], env=strict_env,
                            capture_output=True, text=True)
    assert failed.returncode != 0 and "SOAK_SLO_FAIL" in failed.stderr
    failed_report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert failed_report["sustained_availability_pass"] is False
    del metrics["soak_failure_rate_5m_window_7"]
    (root / "k6-summary.json").write_text(json.dumps({"metrics": metrics}), encoding="utf-8")
    missing = subprocess.run([sys.executable, str(script), str(root)], env=strict_env,
                             capture_output=True, text=True)
    assert missing.returncode != 0, "missing five-minute window must never pass"
    (root / "after.json").unlink()
    subprocess.run([sys.executable, str(script), str(root)],
                   capture_output=True, text=True, check=True)
    fallback_report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert fallback_report["final_process_metrics_source"] == "last-valid-sample"

    del metrics["soak_p99_5m_window_0"]
    for i in range(1, 12):
        del metrics[f"soak_p99_5m_window_{i}"]
    (root / "k6-summary.json").write_text(
        json.dumps({"metrics": metrics}), encoding="utf-8"
    )
    subprocess.run([sys.executable, str(script), str(root)],
                   capture_output=True, text=True, check=True)
    report = json.loads((root / "report.json").read_text(encoding="utf-8"))
    assert report["five_minute_p99_ms"] == []
    assert report["p99_drift_assessment"] == "insufficient-window-evidence"

print("PASS: soak report time-window and legacy-run regression contracts")
