#!/usr/bin/env python3
"""Exact-commit CI software-readiness gate. NEVER a production release gate.

Passes only when all required workflows completed SUCCESS on exactly the same
head SHA. No CI result can substitute for physical 10GbE/HA/PKI acceptance.
"""
import argparse
import json
import sys
from pathlib import Path

REQUIRED = (
    "v0.1 real oha JSON and fixed-body smoke (CI only)",
    "On-prem Prometheus rules contract (synthetic CI)",
    "v0.1 GitHub Actions definitions lint",
    "On-prem operations source contract",
    "v0.1 synthetic OCSP CRL contract",
    "v0.1 capacity strict measured input contracts",
    "v0.1 Docker Redis TLS Sentinel prototype",
    "v0.1 disposable Docker integration (real Control Center)",
    "Issue 24 - direct vs proxy allocation comparison",
    "Control Center 0.1 - complete application source checks",
    "v0.1 EOD 750 Mbps single-gateway diagnostic (nonproduction)",
    "YARP 0.1 - L7 build and traffic acceptance",
    "v0.1 real-socket listener isolation and actual metrics",
    "Windows HA 10-run stability gate",
)

def evaluate(response, sha):
    if not isinstance(sha, str) or len(sha) != 40 or any(c not in '0123456789abcdef' for c in sha):
        raise ValueError("Expected exact 40-digit lowercase commit SHA")
    runs = response.get("workflow_runs")
    if not isinstance(runs, list):
        raise ValueError("Missing GitHub API workflow_runs array")
    matches = {}
    for item in runs:
        if not isinstance(item, dict) or item.get("head_sha") != sha:
            continue
        name = item.get("name")
        if name not in REQUIRED:
            continue
        # Re-runs and duplicates must not allow stale SUCCESS to shadow a
        # newer incomplete/failed attempt for the same workflow.
        key = (str(item.get("created_at") or ""), int(item.get("run_attempt") or 1), int(item.get("id") or 0))
        if name not in matches or key > matches[name][0]:
            matches[name] = (key, item)
    checks = {}
    for name in REQUIRED:
        run = matches.get(name, (None, None))[1]
        checks[name] = {
            "status": run.get("status") if run else "MISSING",
            "conclusion": run.get("conclusion") if run else None,
            "url": run.get("html_url") if run else None,
            "id": run.get("id") if run else None,
        }
    incomplete = [name for name, c in checks.items()
                  if c["status"] != "completed" or c["conclusion"] != "success"]
    failed = [name for name in incomplete
              if checks[name]["status"] == "completed" and checks[name]["conclusion"] != "success"]
    state = "NO-GO" if failed else "PENDING" if incomplete else "GO"
    return {
        "source": "Exact GitHub Actions run API response, not an edited badge",
        "commit_sha": sha,
        "ci_v01": state,
        "production": "NO-GO",
        "production_reason": "No independent physical-site capacity/HA/PKI/CAB evidence is established by CI",
        "required_workflows": len(REQUIRED),
        "completed_success": len(REQUIRED) - len(incomplete),
        "incomplete_workflows": incomplete,
        "checks": checks,
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs", required=True, type=Path)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = evaluate(json.loads(args.runs.read_text()), args.sha)
    except (OSError, ValueError, TypeError) as e:
        report = {"ci_v01": "NO-GO", "production": "NO-GO", "errors": [str(e)]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "checks"}, indent=2))
    return 0 if report["ci_v01"] == "GO" else 1

if __name__ == "__main__":
    sys.exit(main())
