#!/usr/bin/env python3
"""Fail-closed GitHub Actions push-run evidence for an exact merged main SHA.

Read-only: no workflows, repository settings, or deployment state are changed.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_PAGES = 20


def get_json(path, token):
    req = urllib.request.Request(
        "https://api.github.com" + path,
        headers={"Accept": "application/vnd.github+json",
                 "Authorization": "Bearer " + token,
                 "X-GitHub-Api-Version": "2022-11-28",
                 "User-Agent": "GatewayCore-exact-push-evidence"},
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def paged(path, token):
    records = []
    for page in range(1, MAX_PAGES + 1):
        separator = "&" if "?" in path else "?"
        payload = get_json(path + separator + "per_page=100&page=" + str(page), token)
        if isinstance(payload, list):
            batch = payload
        else:
            batch = payload.get("workflow_runs", payload.get("jobs"))
            if not isinstance(batch, list):
                raise ValueError("Unexpected GitHub API collection")
        records.extend(batch)
        if len(batch) < 100:
            return records
    raise ValueError("GitHub pagination exceeded safety limit")


def collect(repo, sha, token):
    encoded = urllib.parse.quote(repo, safe="/")
    runs = paged("/repos/" + encoded + "/actions/runs?event=push&head_sha=" + sha, token)
    exact = [r for r in runs if r.get("head_sha") == sha and
             r.get("head_branch") == "main" and r.get("event") == "push"]
    evidence = []
    for run in exact:
        run_id = run["id"]
        jobs = paged("/repos/" + encoded + "/actions/runs/" + str(run_id) + "/jobs", token)
        evidence.append({
            "run_id": run_id, "name": run.get("name"),
            "url": run.get("html_url"), "status": run.get("status"),
            "conclusion": run.get("conclusion"),
            "jobs": [{"id": j.get("id"), "name": j.get("name"),
                      "url": j.get("html_url"), "status": j.get("status"),
                      "conclusion": j.get("conclusion"),
                      "failed_steps": [{"name": s.get("name"), "number": s.get("number")}
                                       for s in j.get("steps", [])
                                       if s.get("conclusion") in ("failure", "cancelled")]}
                     for j in jobs],
        })
    return evidence


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="owner/repository")
    parser.add_argument("--sha", required=True, help="full 40-character main commit SHA")
    parser.add_argument("--output", help="write sanitized JSON evidence to this file")
    args = parser.parse_args(argv)
    if not REPO.fullmatch(args.repo) or not SHA.fullmatch(args.sha):
        parser.error("Expected owner/repository and lowercase 40-character SHA")
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token:
        parser.error("Set GH_TOKEN or GITHUB_TOKEN with read-only Actions access")
    try:
        runs = collect(args.repo, args.sha, token)
    except (urllib.error.URLError, ValueError, KeyError, TimeoutError) as exc:
        print("GitHub evidence unavailable: " + str(exc), file=sys.stderr)
        return 2
    ok = bool(runs) and all(
        r["status"] == "completed" and r["conclusion"] == "success" and
        bool(r["jobs"]) and all(j["status"] == "completed" and
                               j["conclusion"] == "success" for j in r["jobs"])
        for r in runs
    )
    report = {"repository": args.repo, "main_sha": args.sha,
              "push_runs": runs, "observed_runs": len(runs),
              "all_observed_push_runs_passed": ok,
              "note": "This proves observed push runs only; compare required workflow inventory separately."}
    output = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        with open(args.output, "x", encoding="utf-8") as f:
            f.write(output)
    else:
        sys.stdout.write(output)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
