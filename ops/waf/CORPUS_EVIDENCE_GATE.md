# WAF per-route corpus evidence gate (issue #51)

This is a **post-run evidence checker**, not a WAF, a traffic generator, or proof of production readiness. Collect genuine request/response decisions using an approved, version-pinned ruleset and an independently labelled benign/malicious corpus. Keep request bodies, IPs, tokens and customer data out of this CSV and GitHub.

CSV header must be exactly `route,case_id,expected,observed,mode`. Every case ID must be unique within its route; `expected` is `benign` or `malicious`, `observed` is `allowed` or `blocked`, and `mode` must be `block`. A request returning a blocking response without a confirmed WAF decision must not be recorded as a true positive. Detect-only results need separate shadow-mode reporting and **cannot** be passed as enforced blocking.

Example (synthetic only):

```csv
route,case_id,expected,observed,mode
/api/demo,benign-json-1,benign,allowed,block
/api/demo,sql-injection-1,malicious,blocked,block
```

Before running, record the approved FP/FN limits, minimum per-route corpus sizes, pinned ruleset hash, corpus manifest hash, gateway SHA, OS, exact config, evidence collection method and operator. Then execute:

```sh
python3 -m unittest discover -s ops/waf -p 'test_assess_corpus_evidence.py' -v
python3 ops/waf/assess_corpus_evidence.py evidence.csv \
  --max-fp-rate 0 --max-fn-rate 0 --min-benign 1 --min-malicious 1 \
  > confusion-matrix.json
```

The zero rates and one-case minimum above are **illustrative**, not approved production thresholds. Do not lower an agreed gate to obtain a pass. Exit 0 means all routes meet the supplied gate, exit 1 means at least one route fails, exit 2 means invalid/missing evidence. The JSON contains TP/TN/FP/FN and per-route FP/FN rates, but no case payloads. Empty, duplicate, shadow-only, malformed, or insufficient per-route evidence fails closed.

This gate does **not** replace pinned-policy ownership/expiry/rollback tests, evasion and protocol corpora, direct/proxy/WAF matched-concurrency load with p95/p99/CPU/allocations, incident telemetry, or Windows/Linux deployment and real-site acceptance. Record those separately under #51 and #36. Never mark #51 complete from this checker alone.
