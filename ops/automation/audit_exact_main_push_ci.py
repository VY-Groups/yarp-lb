#!/usr/bin/env python3
"""Audit exact main push Actions runs and jobs; never infer push health from PR checks."""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def get_json(url, token):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "gatewaycore-exact-push-audit",
    })
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.load(response)


def paged(url, token, key):
    items = []
    for page in range(1, 51):
        sep = "&" if "?" in url else "?"
        data = get_json(url + sep + "per_page=100&page=" + str(page), token)
        batch = data[key]
        items.extend(batch)
        if len(batch) < 100:
            return items
    raise RuntimeError("pagination exceeded 5000 records; audit incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY"))
    parser.add_argument("--sha", required=True, help="Full exact main commit SHA")
    parser.add_argument("--output", default="-", help="JSON report path, or - for stdout")
    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token or not args.repo or len(args.sha) != 40 or any(c not in "0123456789abcdef" for c in args.sha.lower()):
        parser.error("GITHUB_TOKEN, owner/repo and full 40-character SHA required")
    if len(args.repo.split("/")) != 2:
        parser.error("repo must be owner/repo")
    base = "https://api.github.com/repos/" + args.repo
    ref = get_json(base + "/git/ref/heads/main", token)["object"]["sha"]
    if ref.lower() != args.sha.lower():
        raise RuntimeError("requested SHA is not current main; observed " + ref)
    runs = paged(base + "/actions/runs?head_sha=" + args.sha + "&event=push", token, "workflow_runs")
    selected = [run for run in runs if run.get("head_sha", "").lower() == args.sha.lower()
                and run.get("event") == "push" and run.get("head_branch") == "main"]
    report = {"repository": args.repo, "main_sha": ref, "runs": [], "verdict": "INCOMPLETE"}
    for run in selected:
        jobs = paged(base + "/actions/runs/" + str(run["id"]) + "/jobs", token, "jobs")
        report["runs"].append({
            "id": run["id"], "name": run.get("name"), "url": run.get("html_url"),
            "status": run.get("status"), "conclusion": run.get("conclusion"),
            "attempt": run.get("run_attempt"),
            "jobs": [{"id": j["id"], "name": j.get("name"), "url": j.get("html_url"),
                      "status": j.get("status"), "conclusion": j.get("conclusion"),
                      "failed_steps": [{"name": s.get("name"), "number": s.get("number")}
                                       for s in j.get("steps", []) if s.get("conclusion") == "failure"]}
                     for j in jobs],
        })
    complete = bool(report["runs"]) and all(
        r["status"] == "completed" and r["conclusion"] == "success" and bool(r["jobs"])
        and all(j["status"] == "completed" and j["conclusion"] == "success" for j in r["jobs"])
        for r in report["runs"])
    failed = any(r["conclusion"] in ("failure", "timed_out", "action_required", "cancelled")
                 or any(j["conclusion"] in ("failure", "timed_out", "action_required", "cancelled")
                        for j in r["jobs"]) for r in report["runs"])
    report["verdict"] = "FAIL" if failed else "PASS" if complete else "INCOMPLETE"
    result = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        print(result, end="")
    else:
        with open(args.output, "w", encoding="utf-8") as output:
            output.write(result)
    return 0 if complete else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, urllib.error.URLError, ValueError, KeyError) as exc:
        print("Exact main push CI audit unavailable: " + str(exc), file=sys.stderr)
        sys.exit(2)
