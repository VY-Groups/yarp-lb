#!/usr/bin/env python3
"""Read-only EC2 traffic functional tests for the REAL Control Center YARP binary.

No EC2 credentials, SSH, remote mutations or synthetic GatewayLab executable.
Every HTTP test request is CSV-logged; all tests enforce per-test and run caps.
A 15-second curl maximum applies to every HTTP request to the EC2 backends.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from urllib.request import build_opener, ProxyHandler

HOST_A = "ec2-3-108-65-15.ap-south-1.compute.amazonaws.com"
HOST_B = "ec2-65-0-11-186.ap-south-1.compute.amazonaws.com"
GATEWAY = "http://127.0.0.1:18088"
BODY_PATTERN = re.compile(r"\bbackend\s+([a-zA-Z0-9_.-]+)\s+(\S+)", re.I)
CSV_FIELDS = ["timestamp", "client_address", "status", "backend", "latency_ms", "error"]
REQUEST_CAP = 8000
TEST_CAP = 1000
MAX_CONCURRENCY = 8
MAX_REQUEST_SECONDS = 15
WEIGHT_TEST_SIZE = 1000


class Failure(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise Failure(reason)


class Budget:
    def __init__(self, initial: int = 0):
        self.total = initial
        self.by_test: dict[str, int] = defaultdict(int)

    def consume(self, test: str) -> None:
        if self.total + 1 > REQUEST_CAP or self.by_test[test] + 1 > TEST_CAP:
            raise Failure(f"REQUEST_CAP_EXCEEDED: total <= {REQUEST_CAP}, test <= {TEST_CAP}: {test}")
        self.total += 1
        self.by_test[test] += 1


def prerequisites() -> tuple[str, str]:
    a = os.environ.get("BACKEND_A_HOST", "")
    b = os.environ.get("BACKEND_B_HOST", "")
    require(os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("CI") == "true",
            "Requires disposable GitHub Actions runner")
    require(a == HOST_A and b == HOST_B, "BACKEND_A_HOST / BACKEND_B_HOST variables missing or not the two allowlisted hosts")
    require(a != b, "BACKEND_A_HOST and BACKEND_B_HOST must differ")
    return a, b


def curl(url: str, client: str = "127.0.0.1", xff: str | None = None,
         allow_selfsigned: bool = False) -> dict:
    argv = [
        "curl", "--silent", "--show-error", "--noproxy", "*", "--http1.1",
        "--max-time", str(MAX_REQUEST_SECONDS), "--connect-timeout", "5",
        "--proto", "=http,https", "--interface", client,
        "--write-out", "\n__EC2_META__%{http_code}|%{time_total}\n",
    ]
    if xff is not None:
        argv.extend(["--header", "X-Forwarded-For: " + xff])
    if allow_selfsigned:
        argv.append("--insecure")  # Direct backend negative control only.
    argv.append(url)
    started = datetime.now(timezone.utc).isoformat()
    start = time.monotonic()
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=MAX_REQUEST_SECONDS + 2,
                              check=False)
        output = proc.stdout.decode("utf-8", "replace")
        if "\n__EC2_META__" in output:
            body, meta = output.rsplit("\n__EC2_META__", 1)
            status_raw, elapsed = meta.strip().split("|", 1)
            status = int(status_raw)
            latency = round(float(elapsed) * 1000, 2)
        else:
            body, status, latency = output, 0, round((time.monotonic() - start) * 1000, 2)
        match = BODY_PATTERN.search(body[:16384])
        hostname = match.group(1) if match else ""
        err = proc.stderr.decode("utf-8", "replace")[:300]
        if proc.returncode != 0:
            err = f"curl exit {proc.returncode}: {err}"
        if status != 200 and not err:
            err = f"HTTP {status}"
        return dict(timestamp=started, client_address=client, status=status,
                    backend=hostname, latency_ms=latency, error=err)
    except (subprocess.TimeoutExpired, ValueError, OSError) as ex:
        return dict(timestamp=started, client_address=client, status=0,
                    backend="", latency_ms=round((time.monotonic() - start) * 1000, 2),
                    error=f"{type(ex).__name__}: {str(ex)[:220]}")


def csv_output(out: Path, name: str, rows: list[dict]) -> None:
    with (out / f"{name}.csv").open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, CSV_FIELDS)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in CSV_FIELDS})


def identity_ok(row: dict, names: set[str]) -> bool:
    return row["status"] == 200 and row["backend"] in names and not row["error"]


def request_many(test: str, budget: Budget, out: Path, url: str, count: int,
                 *, clients: list[str] | None = None, rate: float | None = None,
                 xff: str | None = None) -> list[dict]:
    require(1 <= count <= TEST_CAP, f"{test}: invalid request count")
    rows: list[dict] = []
    start = time.monotonic()
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
        futures = []
        for i in range(count):
            if rate is not None:
                target = start + i / rate
                delay = target - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
            budget.consume(test)
            source = clients[i] if clients is not None else "127.0.0.1"
            futures.append(pool.submit(curl, url, source, xff))
        for future in futures:
            rows.append(future.result())
    csv_output(out, test, rows)
    return rows


def distribution(rows: list[dict], names: dict[str, str],
                 low: float, high: float, label: str) -> dict:
    valid = set(names.values())
    failed = [row for row in rows if not identity_ok(row, valid)]
    counts = Counter(row["backend"] for row in rows)
    a = counts[names["A"]]
    b = counts[names["B"]]
    require(not failed, f"{label}: {len(failed)} failed/invalid responses; see CSV")
    require(low * len(rows) <= a <= high * len(rows),
            f"{label}: A received {a}/{len(rows)}, outside {low:.0%}–{high:.0%}")
    require(a + b == len(rows), f"{label}: unidentified backend responses")
    return {"requests": len(rows), "A": a, "B": b, "share_A": round(a / len(rows), 4),
            "p99_latency_ms": sorted(r["latency_ms"] for r in rows)[
                max(0, int(len(rows) * .99) - 1)]}


def config(backends: dict[str, str], policy="WeightedRandom",
           weights: dict[str, int] | None = None, active=False) -> dict:
    dest = {}
    for key, address in backends.items():
        dest[key] = {"Address": address, "Metadata": {
            "Weight": str((weights or {}).get(key, 1))
        }}
    cluster = {
        "LoadBalancingPolicy": policy,
        "Destinations": dest,
        "HealthCheck": {
            "AvailableDestinationsPolicy": "HealthyAndUnknown",
            "Active": {
                "Enabled": active,
                "Interval": "00:00:01",
                "Timeout": "00:00:03",
                "Policy": "ConsecutiveFailures",
                "Path": "/",
            },
        },
        "Metadata": {"ConsecutiveFailuresHealthPolicy.Threshold": "1"},
        # Concurrency is limited by the harness, never by unverified
        # request-header/HTTP2 configuration properties in a release build.
    }
    return {"ReverseProxy": {
        "Routes": {"ec2": {"ClusterId": "ec2", "Match": {"Path": "/ec2/{**catch-all}"},
                           "Transforms": [{"PathRemovePrefix": "/ec2"}]}},
        "Clusters": {"ec2": cluster},
    }}


def write_config(path: Path, settings: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(settings, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # Product uses reloadOnChange on this exact real file.


def metrics() -> str:
    try:
        opener = build_opener(ProxyHandler({}))
        with opener.open(GATEWAY + "/gateway/metrics", timeout=4) as response:
            require(response.status == 200, "Gateway metrics unreachable")
            return response.read(50000).decode("utf-8", "replace")
    except Exception as ex:
        raise Failure(f"Real Control Center loopback metrics unavailable: {ex}") from ex


def visible_destinations() -> set[str]:
    return set(re.findall(r'yarp_control_destination_active_health\{destination="ec2/([^"]+)"\}', metrics()))


def loaded_runtime() -> dict:
    opener = build_opener(ProxyHandler({}))
    with opener.open(GATEWAY + "/gateway/ec2-lab/loaded-config", timeout=3) as response:
        require(response.status == 200, "Read-only runtime load-balancing state unavailable")
        return json.loads(response.read(16384))


def wait_configuration(expect: set[str], timeout: float = 12,
                       expected_policy: str | None = None,
                       expected_weights: dict[str, str] | None = None) -> None:
    until = time.monotonic() + timeout
    observed: dict = {}
    while time.monotonic() < until:
        try:
            observed = loaded_runtime()
            actual = set(observed.get("destinations", {}))
            if actual == expect and (expected_policy is None or
                    observed.get("policy") == expected_policy) and (
                    expected_weights is None or
                    observed.get("destinations") == expected_weights):
                return
        except Exception:
            pass
        time.sleep(.25)
    raise Failure("Live in-memory YARP config did not converge in 12 seconds: "
                  f"wanted IDs {sorted(expect)}, policy={expected_policy}, "
                  f"weights={expected_weights}; observed={observed}")


class Gateway:
    def __init__(self, dll: Path, root: Path, out: Path, insecure: bool = False,
                 ack: bool = False):
        self.dll, self.root, self.out = dll, root, out
        self.insecure, self.ack = insecure, ack
        self.process = None
        self.logfile = None
        self.log_path = out / ("gateway-relaxed.log" if ack else
                               "gateway-without-ack.log" if insecure else "gateway-strict.log")

    def start(self) -> None:
        env = os.environ.copy()
        env.update({
            "ASPNETCORE_URLS": GATEWAY,
            "YARP_EC2_LAB_MODE": "1",
            "YARP_EC2_LAB_PRIVATE_DIR": str((self.out / "control-plane-private").resolve()),
        })
        env.pop("YARP_EC2_LAB_ALLOW_INSECURE_BACKEND_TLS", None)
        env.pop("YARP_EC2_LAB_TLS_RISK_ACK", None)
        if self.insecure:
            env["YARP_EC2_LAB_ALLOW_INSECURE_BACKEND_TLS"] = "1"
        if self.ack:
            env["YARP_EC2_LAB_TLS_RISK_ACK"] = "1"
        self.logfile = self.log_path.open("ab")
        self.process = subprocess.Popen(
            ["dotnet", str(self.dll)], cwd=self.root, env=env,
            stdout=self.logfile, stderr=subprocess.STDOUT, start_new_session=True)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise Failure(f"Real gateway exited on startup ({self.process.returncode}); see {self.log_path}")
            try:
                opener = build_opener(ProxyHandler({}))
                with opener.open(GATEWAY + "/gateway/health", timeout=1.5) as reply:
                    if reply.status == 200:
                        return
            except Exception:
                pass
            time.sleep(.2)
        raise Failure(f"Real gateway did not start: {self.log_path}")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=4)
        if self.logfile:
            self.logfile.flush()
            self.logfile.close()


def backend_addresses(a: str, b: str, scheme="http") -> dict[str, str]:
    return {"A": f"{scheme}://{a}/", "B": f"{scheme}://{b}/"}


def preflight(out: Path) -> dict:
    a, b = prerequisites()
    rows: list[dict] = []
    names: dict[str, str] = {}
    for key, host in (("A", a), ("B", b)):
        tests = [curl(f"http://{host}/") for _ in range(5)]
        rows.extend(tests)
        found = {x["backend"] for x in tests if x["status"] == 200 and x["backend"]}
        require(len(found) == 1 and all(x["status"] == 200 and x["backend"] for x in tests),
                f"BACKEND_UNREACHABLE: {host}: expected five HTTP 200 pages formatted 'backend <hostname> <time>'; got {[(x['status'], x['error']) for x in tests]}")
        names[key] = found.pop()
    require(names["A"] != names["B"], "BACKEND_UNREACHABLE: two EC2 hosts return the same backend identity")
    csv_output(out, "T0_preflight", rows)
    document = {"hosts": {"A": a, "B": b}, "identities": names, "requests_used": 10,
                "verified_at": datetime.now(timezone.utc).isoformat()}
    (out / "preflight.json").write_text(json.dumps(document, indent=2))
    return document


def run(out: Path, root: Path, dll: Path) -> None:
    a, b = prerequisites()
    info = json.loads((out / "preflight.json").read_text())
    require(info["hosts"] == {"A": a, "B": b}, "Backend variables changed after preflight")
    names = info["identities"]
    expected = set(names.values())
    config_path = root / "appsettings.json"
    budget = Budget(initial=info["requests_used"])
    results: list[dict] = []
    gateway: Gateway | None = None

    def record(test: str, details: dict) -> None:
        results.append({"test": test, "status": "PASS", **details})
        print("PASS", test, json.dumps(details, sort_keys=True), flush=True)

    def apply(cfg: dict, destinations: set[str]) -> None:
        write_config(config_path, cfg)
        cluster = cfg["ReverseProxy"]["Clusters"]["ec2"]
        loaded_weights = {
            key: val["Metadata"]["Weight"]
            for key, val in cluster["Destinations"].items()
        }
        wait_configuration(destinations, expected_policy=cluster["LoadBalancingPolicy"],
                           expected_weights=loaded_weights)

    def assert_all(rows: list[dict], label: str) -> None:
        invalid = [x for x in rows if not identity_ok(x, expected)]
        require(not invalid, f"{label}: {len(invalid)} non-200 or malformed backend responses")

    try:
        write_config(config_path, config(backend_addresses(a, b)))
        gateway = Gateway(dll, root, out)
        gateway.start()
        wait_configuration({"A", "B"})
        rows = request_many("T1_equal", budget, out, GATEWAY + "/ec2/", 1000)
        record("T1_equal", distribution(rows, names, .45, .55, "T1 equal weights"))

        for label, weight, bounds in (
                ("T2_70_30", 70, (.65, .75)),
                ("T2_90_10", 90, (.87, .93))):
            apply(config(backend_addresses(a, b), weights={"A": weight, "B": 100-weight}),
                  {"A", "B"})
            rows = request_many(label, budget, out, GATEWAY + "/ec2/", 1000)
            record(label, distribution(rows, names, *bounds, label))

        # Bind actual TCP local source address. X-Forwarded-For must not affect it.
        ips = [f"127.0.0.{n}" for n in range(2, 42)]
        apply(config(backend_addresses(a, b), policy="SourceIpHash"), {"A", "B"})
        initial: dict[str, str] = {}
        first: list[dict] = []
        for ip in ips:
            for _ in range(10):
                budget.consume("T3_hash_initial")
                row = curl(GATEWAY + "/ec2/", client=ip)
                first.append(row)
                assert_all([row], "T3 initial")
                if ip in initial:
                    require(row["backend"] == initial[ip], f"T3: source IP {ip} changed destinations")
                else:
                    initial[ip] = row["backend"]
        csv_output(out, "T3_hash_initial", first)
        counts = Counter(initial.values())
        require(11 <= counts[names["A"]] <= 29 and 11 <= counts[names["B"]] <= 29,
                f"T3: 40 source IP split out of 11–29 bounds: {dict(counts)}")
        xff_rows = []
        for ip in ips:
            budget.consume("T3_xff_spoof")
            row = curl(GATEWAY + "/ec2/", client=ip, xff="203.0.113.29")
            xff_rows.append(row)
            assert_all([row], "T3 spoof")
            require(row["backend"] == initial[ip],
                    f"T3: spoofed X-Forwarded-For altered {ip} affinity")
        csv_output(out, "T3_xff_spoof", xff_rows)

        apply(config({"A": f"http://{a}/"}, policy="SourceIpHash"), {"A"})
        removed = []
        for ip in ips:
            for _ in range(3):
                budget.consume("T3_remove_B")
                row = curl(GATEWAY + "/ec2/", client=ip)
                removed.append(row)
                assert_all([row], "T3 remove B")
                require(row["backend"] == names["A"], f"T3: source {ip} not rehomed to A")
        csv_output(out, "T3_remove_B", removed)
        apply(config(backend_addresses(a, b), policy="SourceIpHash"), {"A", "B"})
        restored = []
        for ip in ips:
            for _ in range(3):
                budget.consume("T3_restore_B")
                row = curl(GATEWAY + "/ec2/", client=ip)
                restored.append(row)
                assert_all([row], "T3 restore B")
                require(row["backend"] == initial[ip],
                        f"T3: original hash mapping for {ip} was not restored")
        csv_output(out, "T3_restore_B", restored)
        record("T3_affinity", {"source_addresses": len(ips), "A_addresses": counts[names["A"]],
                "B_addresses": counts[names["B"]], "rehome_failures": 0,
                "restore_failures": 0, "xff_spoof_moved": 0})

        modes = [
            ("T4_connection_refused", "http://127.0.0.1:9/", 10),
            ("T4_blackhole_timeout", f"http://{a}:81/", 15),
            ("T4_invalid_protocol", f"http://{a}:22/", 15),
        ]
        for label, bad, deadline in modes:
            apply(config({**backend_addresses(a,b), "bad": bad},
                         active=True), {"A","B","bad"})
            start = time.monotonic()
            before = []
            with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
                futures = []
                for i in range(300):  # <=20 requests/s before health ejection
                    elapsed = time.monotonic() - start
                    if elapsed >= deadline:
                        break
                    health = metrics()
                    if re.search(r'yarp_control_destination_active_health\{destination="ec2/bad"\}\s+-1', health):
                        break
                    target = start + i / 20
                    if target > time.monotonic():
                        time.sleep(target - time.monotonic())
                    budget.consume(label)
                    futures.append(pool.submit(curl, GATEWAY + "/ec2/"))
                detected = time.monotonic() - start
                for future in futures:
                    before.append(future.result())
            require(detected <= deadline + 0.5 and
                    re.search(r'yarp_control_destination_active_health\{destination="ec2/bad"\}\s+-1', metrics()),
                    f"{label}: unhealthy destination not ejected within {deadline}s (observed {detected:.2f}s)")
            csv_output(out, label + "_before", before)
            after = request_many(label, budget, out, GATEWAY + "/ec2/", 300)
            assert_all(after, f"{label}: 300 after ejection")
            # Re-include pre-ejection failures in the test's own CSV.
            csv_output(out, label, before + after)
            record(label, {"ejection_seconds": round(detected, 2),
                           "failures_before_ejection": sum(not identity_ok(x, expected) for x in before),
                           "post_ejection_requests": 300, "post_ejection_failures": 0})

        # TLS verification ON: self-signed EC2 HTTPS servers should be rejected.
        apply(config(backend_addresses(a, b, "https"), active=False), {"A","B"})
        strict = request_many("T5_tls_strict", budget, out, GATEWAY + "/ec2/", 8)
        require(all(x["status"] in (502,503) and not x["backend"] for x in strict),
                f"T5: unexpected accepted TLS identity / unexpected HTTP response {[(x['status'],x['backend']) for x in strict]}")
        gateway.stop()
        strict_logs = gateway.log_path.read_text(errors="replace")
        require(re.search(r"certificate|Ssl|AuthenticationException|SecureChannel", strict_logs, re.I),
                "T5: strict upstream TLS failures are not visible in gateway logs")
        record("T5_tls_strict", {"rejected_requests": len(strict),
                                "certificate_failure_logged": True})

        # Invalid relaxation: same explicit flag, but no independent risk ack.
        gateway = Gateway(dll, root, out, insecure=True, ack=False)
        try:
            gateway.start()
            with ThreadPoolExecutor(max_workers=2) as pool:
                negative = []
                for _ in range(2):
                    budget.consume("T5_tls_no_ack")
                    negative.append(pool.submit(curl, GATEWAY + "/ec2/"))
                no_ack = [f.result() for f in negative]
            csv_output(out, "T5_tls_no_ack", no_ack)
            require(all(x["status"] != 200 for x in no_ack),
                    "T5: TLS relaxation was enabled without required risk acknowledgment")
        except Failure as ex:
            if "gateway" not in str(ex).lower() and "start" not in str(ex).lower():
                raise
        finally:
            gateway.stop()
        negative_log = gateway.log_path.read_text(errors="replace")
        require("risk acknowledgment" in negative_log,
                "T5: missing risk acknowledgment did not cause explicit startup/config error")
        record("T5_tls_no_ack", {"unexpected_successes": 0,
                                 "risk_guard_message_seen": True})

        gateway = Gateway(dll, root, out, insecure=True, ack=True)
        gateway.start()
        wait_configuration({"A","B"})
        relaxed = request_many("T5_tls_relaxed", budget, out, GATEWAY + "/ec2/", 1000)
        record("T5_tls_relaxed", distribution(relaxed, names, .45, .55, "T5 explicit self-signed TLS"))
        gateway.stop()
        require("WARNING: CI-ONLY loopback EC2 TLS" in gateway.log_path.read_text(errors="replace"),
                "T5: explicit TLS relaxation warning not written to logs")

        # T6: requested 20 requests/sec *60s == 1200, incompatible with
        # strict <=1000/test. Preserve cap: 16/s *60s = 960. Switch at t=20.
        write_config(config_path, config(backend_addresses(a,b)))
        gateway = Gateway(dll, root, out)
        gateway.start()
        wait_configuration({"A","B"})
        t0 = time.monotonic()
        rows = []
        futures = []
        with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
            for i in range(960):
                target = t0 + i / 16.0
                delay = target - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                elapsed = time.monotonic() - t0
                if i == 320:
                    apply(config(backend_addresses(a,b), weights={"A":90,"B":10}), {"A","B"})
                budget.consume("T6_weight_change")
                futures.append((elapsed, pool.submit(curl, GATEWAY+"/ec2/")))
            for when, future in futures:
                row = future.result()
                row["scheduled_seconds"] = when
                rows.append(row)
        csv_output(out, "T6_weight_change", rows)
        assert_all(rows, "T6 live weight switch")
        last = [x for x in rows if x["scheduled_seconds"] >= 30]
        share = sum(x["backend"] == names["A"] for x in last) / len(last)
        require(.85 <= share <= .95,
                f"T6 last-30-second heavy-backend share {share:.3f} not in [0.85,0.95]")
        record("T6_weight_change", {"duration_seconds": 60,
                "actual_rate_rps": 16, "requests": len(rows),
                "heavy_share_last_30s": round(share, 4),
                "failures": 0, "live_reload": True})

        record("suite_budget", {"total_requests": budget.total,
                "per_test_max": max(budget.by_test.values()), "max_concurrency": MAX_CONCURRENCY,
                "not_tested": ["real backend crash/recovery", "gateway failover",
                               "performance", "multi-host HA"]})
    except Exception as exc:
        results.append({"test":"failure", "status":"FAIL", "reason":str(exc)})
        raise
    finally:
        if gateway is not None:
            gateway.stop()
        summary = {
            "tests": results,
            "request_budget_used": budget.total,
            "per_test_counts": dict(budget.by_test),
            "not_tested": ["real backend crash/recovery","gateway failover",
                           "performance","multi-host HA"],
            "note": "Test-only. Latency recorded but never used for pass/fail. All traffic was initiated from one GitHub runner."
        }
        (out/"summary.json").write_text(json.dumps(summary, indent=2))
        lines = ["### EC2-backed Control Center functional tests",
                 "| Test | Result | Measurement |", "|---|---|---|"]
        for result in results:
            details = result.get("reason", "") if result["status"] == "FAIL" else \
                ", ".join(f"{k}={v}" for k,v in result.items() if k not in ("status","test"))
            lines.append(f"| {result['test']} | {result['status']} | {str(details)[:220].replace('|','/')} |")
        lines.append(f"\nRequested request budget: used **{budget.total}/8000**; "
                     "concurrency <=8, each request timeout <=15 seconds.")
        lines.append("\nNOT TESTED: real backend crash/recovery, gateway failover, "
                     "performance, multi-host HA.")
        markdown = "\n".join(lines) + "\n"
        (out/"job-summary.md").write_text(markdown, encoding="utf-8")
        if os.getenv("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
                fh.write(markdown)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--dll", type=Path)
    args = parser.parse_args()
    require(args.preflight != args.run, "Choose exactly one of --preflight or --run")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    try:
        if args.preflight:
            doc = preflight(out)
            print("PASS EC2 preflight", json.dumps(doc, sort_keys=True))
        else:
            require(args.root is not None and args.dll is not None,
                    "--root and --dll required for real Control Center run")
            run(out, args.root.resolve(), args.dll.resolve())
    except Exception as exc:
        print("FAIL:", exc, file=sys.stderr)
        (out/"fatal.txt").write_text(f"{type(exc).__name__}: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
