# WAF per-route corpus evidence: one authoritative acceptance gate (#51)

Use **ops/waf/corpus_evidence_gate.py**. There is NO separate HTTP-status-only evaluator. The preapproved JSON policy defines the approved routes, count thresholds, and (in version 3) per-route FP/FN rates, minimum corpus class sizes and pinned source metadata. Do not generate the policy or weaken its limits from observed test results.

## Version 3 policy (illustrative fixtures, not production approvals)

    {
      "schemaVersion": 3,
      "mode": "block",
      "approvedRulesetSha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "corpusManifestSha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "gatewaySha": "cccccccccccccccccccccccccccccccccccccccc",
      "platform": "linux",
      "routes": {
        "/api/demo": {
          "max_fp": 0, "max_fn": 0,
          "max_fp_rate": 0.0, "max_fn_rate": 0.0,
          "min_benign": 1, "min_malicious": 1
        }
      }
    }

All values shown are synthetic placeholders, NOT accepted enterprise limits. Each approved route must appear in the CSV and have independently labeled benign AND malicious cases, meeting its preapproved counts AND rates. A missing critical route, an unexpected route, duplicate case ID, noncanonical route or duplicate native audit digest fails closed. The approved version 2 absolute-count policy remains supported for existing detection-only and block-mode acceptance.

## Version 3 request evidence

The exact CSV columns are:

    case_id,route,expected,observed,would_block,mode,severity,audit_sha256

Column order can vary but the set must be exact. The original trusted semantics are retained: expected is benign/malicious ground truth, observed is allow/block *HTTP enforcement*, and would_block is the separate *native WAF rule decision*. A detection-only malicious request may have observed=allow AND would_block=true and is a **true positive of the shadow rule**, not a false negative. In block mode, observed and would_block must agree; a backend 403 or connectivity failure alone cannot be used as a WAF block decision.

Version 3 also requires an uppercase 64-hex audit_sha256 per request, unique across the whole corpus, from an independently retained **case-specific native WAF audit transaction**. Reusing one rule event for multiple cases is rejected. The gate checks shape and uniqueness, not cryptographic signatures of that operator-supplied audit digest. Keep native audit records, client labels, signed corpus manifest and pinned WAF policy in separately controlled custody, never in GitHub artifacts.

Synthetic example, not a measured customer corpus:

    case_id,route,expected,observed,would_block,mode,severity,audit_sha256
    benign-1,/api/demo,benign,allow,false,block,low,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    attack-1,/api/demo,malicious,block,true,block,high,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

## Run on the authorized local evidence

    python3 -m unittest discover -s ops/waf -p 'test_corpus*.py' -v
    python3 ops/waf/corpus_evidence_gate.py \
      --policy /private/waf/approved-policy-v3.json \
      --corpus /private/waf/per-request-observations.csv \
      --out /private/waf/private-confusion-matrix.json

The report is stored as a restricted local file. Public stdout shows only PASS/FAIL and case count, not customer route names or case IDs. Version 3 adds per-route FP/FN rates and preapproved pinned hashes to the private report. A run that fails policy, parsing, threshold, missing-route or correlation checks exits nonzero.

**Acceptance boundary:** These are operator-supplied inputs, so PASS cannot itself prove genuine native audit records, independently approved rule hashes, corpus labels, image provenance, signed exception rendering, production rollback, customer FP/FN rates or gateway performance. Preserve the signed source evidence externally; require real Windows/Linux integrated route tests, measured p99/CPU/GC/allocations, and separately accepted thresholds. The observed 500 Mbps peak and required headroom are production **#36** physical environment targets, not results of this CSV evaluator. #51 stays open for those software requirements and #36 stays open for real-site qualification.

## Version 2 compatibility

Existing v2 accepted columns are case_id,route,expected,observed,would_block,mode,severity, and the v2 policy retains per-route max_fp/max_fn absolute counts. The checker deliberately does not reinterpret detect-only rule evaluations as HTTP enforcement. Version 3 is additive, explicit and stricter, and never silently downgrades to v2 when v3-only columns or limits are missing.
