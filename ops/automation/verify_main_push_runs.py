#!/usr/bin/env python3
"""Fail-closed exact-main push-run evidence collector (stdlib only).

Usage: GITHUB_TOKEN=... python ops/automation/verify_main_push_runs.py \
  --repo example/repository --sha <40-hex-main-sha> \
  --required "CodeQL Advanced" --required "Control Center 0.1 - complete application source checks"
Writes sanitized JSON to stdout; never prints the token.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = "https://api.github.com"
SHA = re.compile(r"^[0-9a-f]{40}$")


def get_json(path, token):
    request = urllib.request.Request(
        API + path,
        headers={
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            **({"Authorization": "Bearer " + token} if token else {}),
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def pages(path, key, token):
    result = []
    page = 1
    while True:
        separator = "&" if "?" in path else "?"
        data = get_json(path + separator + "per_page=100&page=" + str(page), token)
        batch = data[key]
        result.extend(batch)
        if len(batch) < 100:
            return result
        page += 1
        if page > 100:
            raise RuntimeError("GitHub pagination exceeds safe bound")


def collect(repo, sha, required, token):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise ValueError("invalid repository")
    if not SHA.fullmatch(sha):
        raise ValueError("expected lowercase full 40-character commit SHA")
    if not required or any(not isinstance(name, str) or not name.strip() for name in required):
        raise ValueError("at least one non-blank required workflow name is mandatory")
    base = "/repos/" + repo
    initial = get_json(base + "/git/ref/heads/main", token)["object"]["sha"]
    if initial != sha:
        raise RuntimeError("main moved or supplied SHA is not current main")
    runs = pages(base + "/actions/runs?event=push&head_sha=" + sha, "workflow_runs", token)
    # The same commit can be pushed to multiple branches. SHA + event alone
    # is not evidence of the protected default-branch push.
    runs = [run for run in runs if run.get("head_sha") == sha and
            run.get("event") == "push" and run.get("head_branch") == "main"]
    names = {run["name"] for run in runs}
    missing = sorted(set(required) - names)
    evidence = []
    failures = []
    for run in runs:
        jobs = pages(base + "/actions/runs/" + str(run["id"]) + "/jobs", "jobs", token)
        failed_jobs = [
            {"id": job["id"], "name": job["name"], "conclusion": job.get("conclusion"),
             "url": job["html_url"]}
            for job in jobs if job.get("status") != "completed" or job.get("conclusion") != "success"
        ]
        record = {
            "id": run["id"], "name": run["name"], "status": run["status"],
            "conclusion": run.get("conclusion"), "url": run["html_url"],
            "jobs": len(jobs), "non_success_jobs": failed_jobs,
        }
        evidence.append(record)
        if not jobs or run["status"] != "completed" or run.get("conclusion") != "success" or failed_jobs:
            failures.append(run["id"])
    final = get_json(base + "/git/ref/heads/main", token)["object"]["sha"]
    accepted = bool(runs) and not missing and not failures and final == initial
    return {
        "repository": repo, "main_sha": initial, "main_sha_after": final,
        "required_workflows": sorted(set(required)), "missing": missing,
        "runs": evidence, "accepted": accepted,
        "note": "Only push CI evidence; independent review and physical acceptance remain separate.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--required", action="append", required=True, help="Required exact-name workflow; repeat for every acceptance gate")
    args = parser.parse_args()
    try:
        report = collect(args.repo, args.sha, args.required, os.getenv("GITHUB_TOKEN", ""))
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["accepted"] else 1
    except (ValueError, RuntimeError, urllib.error.URLError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"accepted": False, "error": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
