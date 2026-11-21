# Exact `main` push CI audit (software evidence)

This read-only tool checks GitHub Actions **push** runs for the exact current `main` SHA. Pull-request checks alone do not establish post-merge CI health.

```bash
export GITHUB_TOKEN='<fine-grained token with Actions: read and Contents: read>'
SHA=$(git rev-parse origin/main)
REPO=$(git remote get-url origin | sed -E 's#^.*github\.com[:/]([^/]+/[^/]+?)(\.git)?$#\1#; s#\.git$##')
python3 ops/automation/audit_exact_main_push_ci.py --repo "$REPO" --sha "$SHA" --output main-push-ci.json
```

The command checks `GET /repos/{owner}/{repo}/git/ref/heads/main`, paginated `GET /repos/{owner}/{repo}/actions/runs?head_sha=...&event=push`, and paginated `GET /repos/{owner}/{repo}/actions/runs/{run_id}/jobs`. It records run/job IDs, URLs, status, conclusion, attempt, and failing step names/numbers. Exit 0 is **PASS** only if at least one matching push workflow exists and every returned run and job is completed successfully. Exit 1 means **FAIL** or **INCOMPLETE** (including no matching runs, queued jobs, cancelled runs and missing jobs); exit 2 means an API, authentication, pagination, or ref-verification error. No workflow is retried or modified.

**Important limitation:** the tool cannot infer whether the repository's expected workflows are absent, disabled, skipped by path filters, or still waiting to appear. Compare against the required workflow inventory and branch protections separately. A PASS is evidence only for the returned exact-SHA push runs, **not** a software-release approval, security review, physical acceptance or production GO. Preserve the JSON evidence with the commit SHA, workflow inventory, CI job logs and independent review. Do not commit tokens or sensitive job logs.

For failed jobs, open each reported job URL and inspect the exact failed step and log before changing source. Fix on a focused PR branch; never push a CI fix directly to `main`. Re-run this audit after independently reviewed integration. Keep #36 open for physical acceptance and unchanged solo-node 750 Mbps, 1.5x peak RPS, 60-minute, zero-error and p99 gates.
