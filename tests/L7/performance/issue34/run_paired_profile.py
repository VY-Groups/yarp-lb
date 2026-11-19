#!/usr/bin/env python3
"""Run paired, same-runner direct/proxy allocation samples and bounded traces."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import statistics
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

from report import build_report


BASE_URL = "http://127.0.0.1"
GATEWAY_PORT = 18080
BACKEND_A_PORT = 18081
BACKEND_B_PORT = 18082
MAX_TRACE_BYTES = 256 * 1024 * 1024


def resolve_checkout(source: Path) -> Path:
    """Make checkout paths absolute before using them with a different cwd."""
    return source.expanduser().resolve(strict=True)


def request_json(url: str, timeout: float = 2.0) -> dict:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as response:
        if response.status != 200:
            raise RuntimeError(f"GET {url} returned HTTP {response.status}")
        value = json.loads(response.read())
    if not isinstance(value, dict):
        raise RuntimeError(f"GET {url} returned non-object JSON")
    return value


def _drain_bounded_log(pipe, path: Path, limit: int = 1024 * 1024) -> None:
    written = 0
    truncated = False
    with path.open("wb") as output:
        while True:
            chunk = pipe.read(64 * 1024)
            if not chunk:
                break
            remaining = limit - written
            if remaining > 0:
                output.write(chunk[:remaining])
                written += min(len(chunk), remaining)
            if len(chunk) > max(remaining, 0):
                truncated = True
        if truncated:
            output.write(f"\n[process log truncated at {limit} bytes; stream fully drained]\n".encode())


def wait_for(label: str, callback, processes: list[subprocess.Popen],
             log_paths: dict[int, Path] | None = None,
             log_threads: dict[int, threading.Thread] | None = None,
             timeout: float = 90.0):
    deadline = time.monotonic() + timeout
    last_error = "not ready"
    while time.monotonic() < deadline:
        for process in processes:
            if process.poll() is not None:
                thread = (log_threads or {}).get(process.pid)
                if thread is not None:
                    thread.join(timeout=1)
                log_path = (log_paths or {}).get(process.pid)
                tail = ""
                if log_path is not None and log_path.is_file():
                    tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
                details = f"; see {log_path}" if log_path else ""
                if tail:
                    details += "\n" + tail
                raise RuntimeError(f"{label}: lab process exited with {process.returncode}{details}")
        try:
            value = callback()
            if value:
                return value
        except Exception as exc:  # readiness polling intentionally retries transient connection errors
            last_error = str(exc)
        time.sleep(0.25)
    raise TimeoutError(f"timed out waiting for {label}: {last_error}")


def stop_processes(processes: list[subprocess.Popen]) -> None:
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def write_lab_config(gateway_bin: Path) -> Path:
    config = {
        "ReverseProxy": {
            "Routes": {
                "api": {"ClusterId": "api", "Match": {"Path": "/api/{**catch-all}"}},
            },
            "Clusters": {
                "api": {
                    "LoadBalancingPolicy": "WeightedRandom",
                    "HealthCheck": {
                        "AvailableDestinationsPolicy": "HealthyAndUnknown",
                        "Active": {
                            "Enabled": True,
                            "Interval": "00:00:01",
                            "Timeout": "00:00:01",
                            "Policy": "ConsecutiveFailures",
                            "Path": "/health/ready",
                        },
                    },
                    "Metadata": {"ConsecutiveFailuresHealthPolicy.Threshold": "1"},
                    "Destinations": {
                        "A": {"Address": f"{BASE_URL}:{BACKEND_A_PORT}/", "Metadata": {"Weight": "70"}},
                        "B": {"Address": f"{BASE_URL}:{BACKEND_B_PORT}/", "Metadata": {"Weight": "30"}},
                    },
                },
            },
        },
    }
    path = gateway_bin / "issue34-lab.json"
    staged = path.with_suffix(".json.next")
    staged.write_text(json.dumps(config), encoding="utf-8")
    staged.replace(path)
    return path


class Lab:
    def __init__(self, source: Path, output: Path):
        # Processes run with their own binary directory as cwd. Keep DLL paths
        # absolute so a relative CLI checkout path is not resolved twice.
        self.source = resolve_checkout(source)
        self.output = output
        self.processes: list[subprocess.Popen] = []
        self.log_threads: dict[int, threading.Thread] = {}
        self.log_paths: dict[int, Path] = {}
        self.env = os.environ.copy()
        gateway_bin = self.source / "tests/L7/GatewayLab/bin/Release/net10.0"
        backend_bin = self.source / "tests/L7/BackendLab/bin/Release/net10.0"
        for binary in (gateway_bin / "GatewayLab.dll", backend_bin / "BackendLab.dll"):
            if not binary.is_file():
                raise FileNotFoundError(f"missing built lab binary: {binary}")
        self.env["YARP_LAB_CONFIG_FILE"] = str(write_lab_config(gateway_bin))
        self.env["YARP_LAB_HTTP_PORT"] = str(GATEWAY_PORT)
        self.env["YARP_LAB_TLS_PORT"] = "18443"
        try:
            self._start(["dotnet", str(backend_bin / "BackendLab.dll"), str(BACKEND_A_PORT), "A"],
                        backend_bin, "backend-a")
            self._start(["dotnet", str(backend_bin / "BackendLab.dll"), str(BACKEND_B_PORT), "B"],
                        backend_bin, "backend-b")
            wait_for("backend readiness", lambda: (
                request_json(f"{BASE_URL}:{BACKEND_A_PORT}/health/ready").get("ready") is True and
                request_json(f"{BASE_URL}:{BACKEND_B_PORT}/health/ready").get("ready") is True),
                self.processes, self.log_paths, self.log_threads)
            self._start(["dotnet", str(gateway_bin / "GatewayLab.dll")], gateway_bin, "gateway")
            wait_for("gateway listener", lambda: request_json(f"{BASE_URL}:{GATEWAY_PORT}/lab/stats"),
                     self.processes, self.log_paths, self.log_threads)
            wait_for("gateway active health", lambda: request_json(f"{BASE_URL}:{GATEWAY_PORT}/api/identity"),
                     self.processes, self.log_paths, self.log_threads)
        except Exception:
            self.close()
            raise

    def _start(self, command: list[str], cwd: Path, label: str) -> None:
        log_path = self.output / f"{label}.log"
        process = subprocess.Popen(command, cwd=cwd, env=self.env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        thread = threading.Thread(target=_drain_bounded_log,
                                  args=(process.stdout, log_path), daemon=True)
        thread.start()
        self.processes.append(process)
        self.log_threads[process.pid] = thread
        self.log_paths[process.pid] = log_path

    def stats(self) -> dict:
        return request_json(f"{BASE_URL}:{GATEWAY_PORT}/lab/stats")

    def close(self) -> None:
        stop_processes(self.processes)
        for thread in self.log_threads.values():
            thread.join(timeout=2)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def run_k6(workspace: Path, script: Path, output: Path, mode: str, vus: int,
           duration: str, payload_bytes: int) -> tuple[dict, float]:
    summary = output.with_suffix(".json")
    relative_summary = summary.resolve().relative_to(workspace.resolve()).as_posix()
    relative_script = script.resolve().relative_to(workspace.resolve()).as_posix()
    command = [
        "docker", "run", "--rm", "--network", "host",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-e", f"MODE={mode}", "-e", f"VUS={vus}", "-e", f"DURATION={duration}",
        "-e", f"PAYLOAD_BYTES={payload_bytes}", "-e", "NO_REUSE=0",
        "-v", f"{workspace.resolve()}:/workspace", "-w", "/workspace",
        "grafana/k6:0.55.0", "run", f"--summary-export=/workspace/{relative_summary}",
        f"/workspace/{relative_script}",
    ]
    started = time.monotonic()
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=125, check=False)
    elapsed = time.monotonic() - started
    output.write_text(result.stdout, encoding="utf-8")
    if result.returncode != 0:
        raise RuntimeError(f"k6 {mode} failed (exit {result.returncode}); see {output}")
    metrics = json.loads(summary.read_text(encoding="utf-8"))["metrics"]
    return metrics, elapsed


def measurement(metrics: dict, elapsed: float, before: dict, after: dict) -> dict:
    requests = int(metrics["http_reqs"]["count"])
    failure = metrics["http_req_failed"]
    checks = metrics["checks"]
    record = {
        "duration_seconds": elapsed,
        "requests": requests,
        "errors": int(failure.get("fails", round(float(failure["value"]) * requests))),
        "failed_rate": float(failure["value"]),
        "checks_rate": float(checks["value"]),
        "rps": float(metrics["http_reqs"]["rate"]),
        "p95_ms": float(metrics["http_req_duration"]["p(95)"]),
        "p99_ms": float(metrics["http_req_duration"]["p(99)"]),
        "allocated_bytes": int(after["allocatedBytesTotal"] - before["allocatedBytesTotal"]),
        "working_set_delta_bytes": int(after["processWorkingSetBytes"] - before["processWorkingSetBytes"]),
        "gc0_delta": int(after["gc0Collections"] - before["gc0Collections"]),
        "gc1_delta": int(after["gc1Collections"] - before["gc1Collections"]),
        "gc2_delta": int(after["gc2Collections"] - before["gc2Collections"]),
        "gc_pause_ms_delta": round(float(after["gcPauseTimeMs"] - before["gcPauseTimeMs"]), 3),
        "managed_heap_delta_bytes": int(after["gcManagedHeapBytes"] - before["gcManagedHeapBytes"]),
        "gateway_pid": int(before["processId"]),
    }
    if before["processId"] != after["processId"]:
        raise ValueError("gateway restarted during the workload")
    return record


def trace_revision(source: Path, workspace: Path, output: Path, load_script: Path,
                   revision: str, commit: str, dotnet_trace: str, vus: int,
                   payload_bytes: int, trace_seconds: int) -> dict:
    trace_dir = output / "traces"
    trace_dir.mkdir(parents=True, exist_ok=True)
    trace_path = trace_dir / f"{revision}-gc-verbose.nettrace"
    trace_log = trace_dir / f"{revision}-dotnet-trace.log"
    trace_metadata = trace_dir / f"{revision}-metadata.json"
    with Lab(source, trace_dir) as lab:
        pid = lab.stats()["processId"]
        command = [dotnet_trace, "collect", "--process-id", str(pid), "--profile", "gc-verbose",
                   "--buffersize", "64", "--duration", f"00:00:00:{trace_seconds:02d}",
                   "--output", str(trace_path)]
        with trace_log.open("w", encoding="utf-8") as log:
            trace = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, text=True)
            time.sleep(3)
            if trace.poll() is not None:
                raise RuntimeError(f"dotnet-trace exited early for {revision}; see {trace_log}")
            k6_metrics, _ = run_k6(workspace, load_script, trace_dir / f"{revision}-trace-load.log",
                                   "proxy", vus, f"{trace_seconds - 5}s", payload_bytes)
            if int(k6_metrics["http_reqs"]["count"]) < 1000:
                raise ValueError(f"{revision} trace workload was too small")
            try:
                trace.wait(timeout=trace_seconds + 30)
            except subprocess.TimeoutExpired:
                trace.kill()
                trace.wait(timeout=5)
                raise TimeoutError(f"dotnet-trace exceeded bounded duration for {revision}")
            if trace.returncode != 0:
                raise RuntimeError(f"dotnet-trace failed for {revision}; see {trace_log}")
        if not trace_path.is_file() or trace_path.stat().st_size <= 0:
            raise RuntimeError(f"dotnet-trace output missing for {revision}")
        if trace_path.stat().st_size > MAX_TRACE_BYTES:
            raise RuntimeError(f"trace exceeds the 256 MiB artifact limit: {trace_path.stat().st_size}")
    metadata = {
        "revision": revision,
        "commit": commit,
        "trace_profile": "gc-verbose (GC collections and sampled object allocations with stacks)",
        "duration_seconds": trace_seconds,
        "eventpipe_buffer_mib": 64,
        "trace_size_bytes": trace_path.stat().st_size,
        "gateway_process_id": int(pid),
        "trace_workload": {"vus": vus, "duration": f"{trace_seconds - 5}s",
                           "payload_bytes": payload_bytes, "k6_image": "grafana/k6:0.55.0"},
        "synthetic_lab_only": True,
        "sensitive_customer_data": False,
        "analysis_note": "Allocation stacks need separate human attribution; this is not production evidence.",
    }
    trace_metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def run_revision(source: Path, workspace: Path, output: Path, script: Path,
                 revision: str, commit: str, round_number: int, vus: int,
                 duration: str, payload_bytes: int, warmup: str) -> dict:
    run_dir = output / f"round-{round_number:02d}-{revision}"
    run_dir.mkdir(parents=True, exist_ok=True)
    with Lab(source, run_dir) as lab:
        # JIT and active-health warmup are excluded from reported measurements.
        run_k6(workspace, script, run_dir / "warmup.log", "proxy", vus, warmup, payload_bytes)
        samples = {}
        for mode in ("direct", "proxy"):
            before = lab.stats()
            metrics, elapsed = run_k6(workspace, script, run_dir / f"{mode}.log", mode,
                                      vus, duration, payload_bytes)
            after = lab.stats()
            samples[mode] = measurement(metrics, elapsed, before, after)
            if mode == "direct":
                time.sleep(2)
        return {
            "round": round_number,
            "revision": revision,
            "commit": commit,
            "workload": {
                "vus": vus,
                "duration": duration,
                "payload_bytes": payload_bytes,
                "warmup": warmup,
                "connection_reuse": True,
                "direct_backend_mix": "70/30",
                "k6_image": "grafana/k6:0.55.0",
                "runner_image": "ubuntu-24.04",
            },
            "measurement_order": ["direct", "proxy"],
            "direct": samples["direct"],
            "proxy": samples["proxy"],
        }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline-dir", type=Path, required=True)
    parser.add_argument("--candidate-dir", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-commit", required=True)
    parser.add_argument("--candidate-commit", required=True)
    parser.add_argument("--load-script", type=Path, required=True)
    parser.add_argument("--dotnet-trace", required=True)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--vus", type=int, default=75)
    parser.add_argument("--duration", default="45s")
    parser.add_argument("--warmup", default="10s")
    parser.add_argument("--trace-seconds", type=int, default=25)
    parser.add_argument("--payload-bytes", type=int, default=0)
    return parser.parse_args()


def verify_checkout(source: Path, expected_commit: str) -> None:
    result = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"],
                            check=True, capture_output=True, text=True)
    actual = result.stdout.strip().lower()
    if actual != expected_commit.lower():
        raise ValueError(f"checkout {source} is {actual}, expected pinned commit {expected_commit}")


def main() -> int:
    args = parse_args()
    if args.rounds < 3 or not 1 <= args.vus <= 5000 or args.trace_seconds < 10:
        raise ValueError("need >=3 rounds, 1..5000 VUs, and trace duration >=10s")
    for source in (args.baseline_dir, args.candidate_dir):
        if not source.is_dir():
            raise FileNotFoundError(f"checkout does not exist: {source}")
    args.baseline_dir = resolve_checkout(args.baseline_dir)
    args.candidate_dir = resolve_checkout(args.candidate_dir)
    verify_checkout(args.baseline_dir, args.baseline_commit)
    verify_checkout(args.candidate_dir, args.candidate_commit)
    args.output.mkdir(parents=True, exist_ok=True)
    script = args.load_script.resolve()
    records = []
    for number in range(1, args.rounds + 1):
        order = ("before", "after") if number % 2 == 1 else ("after", "before")
        for revision in order:
            source = args.baseline_dir if revision == "before" else args.candidate_dir
            commit = args.baseline_commit if revision == "before" else args.candidate_commit
            records.append(run_revision(
                source, args.workspace, args.output, script, revision, commit,
                number, args.vus, args.duration, args.payload_bytes, args.warmup))
        raw_path = args.output / "paired-runs.json"
        raw_path.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    report = build_report(records, args.baseline_commit, args.candidate_commit)
    report_path = args.output / "paired-report.json"
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    traces = []
    traces.append(trace_revision(args.baseline_dir, args.workspace, args.output, script,
                                "before", args.baseline_commit, args.dotnet_trace,
                                args.vus, args.payload_bytes, args.trace_seconds))
    traces.append(trace_revision(args.candidate_dir, args.workspace, args.output, script,
                                "after", args.candidate_commit, args.dotnet_trace,
                                args.vus, args.payload_bytes, args.trace_seconds))
    (args.output / "trace-index.json").write_text(json.dumps(traces, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"paired_report": str(report_path), "trace_index": str(args.output / "trace-index.json"),
                      "rounds": args.rounds,
                      "allocation_delta": report["paired_extra_allocation_delta"]}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ISSUE34_PROFILE_FAILED: {exc}", file=sys.stderr)
        raise
