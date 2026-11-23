# WAF per-route corpus evidence gate (issue #51)

This is a **post-run consistency checker**, not a traffic generator, WAF, authenticated collector or proof of production readiness. Its inputs are **operator-supplied** and must be independently collected, retained and approved outside the repository. Never upload private request bodies, IPs, tokens, raw audit logs or customer secrets to GitHub.

## Independent approved route manifest

The required --route-manifest file is an independently held JSON record; it must **not** be derived from the submitted results CSV. Exact schema (all hashes below are synthetic placeholders, NOT verified production evidence):

    {
      "schemaVersion": 1,
      "approvedRulesetSha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "corpusManifestSha256": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
      "gatewaySha": "cccccccccccccccccccccccccccccccccccccccc",
      "platform": "linux",
      "evidenceBinding": "native-waf-audit-per-request",
      "routes": ["/api/demo"]
    }

The schema is exact, with duplicate keys/route aliases rejected. Every approved route MUST appear and no unapproved route may appear; a missing /admin route cannot silently pass when /api passes. Canonical routes are literal ASCII absolute paths with no repeated separator, dot segment, encoded alias, query, fragment or route parameter. Record the independent reviewer, approval timestamp, OS, installed ruleset/config, ground-truth corpus source and threshold governance outside this file. The checker does NOT verify signatures on that external approval.

## Evidence CSV

The header must be exactly:

    route,case_id,expected,observed,mode,waf_action,audit_sha256

The expected column is independent ground truth benign or malicious; observed is client-side allowed or blocked; mode must be block. The waf_action must be pass or block, obtained from the native WAF audit record bound to **this particular request**, and must agree with observed. A backend HTTP 403 or connectivity failure **cannot** be treated as a WAF true positive. The audit_sha256 is the 64-character uppercase SHA-256 digest of the independently preserved case-specific native audit record; a missing/reused digest fails closed, but its mere presence does **not** cryptographically authenticate that record or the ground-truth label.

Synthetic two-case example, **not** real evidence:

    route,case_id,expected,observed,mode,waf_action,audit_sha256
    /api/demo,benign-json-1,benign,allowed,block,pass,AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    /api/demo,sql-injection-1,malicious,blocked,block,block,BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB

Collect the genuine HTTP result, WAF action, unique native-audit transaction and independently labeled ground truth together. Verify the audit hash from the separately retained original audit using an independently reviewed procedure; do not fabricate values or reuse an unrelated WAF event. All data files must be regular, single-linked files under a private operator directory. The tool rejects symbolic/hard links, oversized data, invalid columns, duplicate evidence identities, malformed routes, absent approved routes and detect-only entries. It does not export native audit content or case IDs; its JSON report includes only per-route counts, rates, and submitted input digests.

## Run an approved acceptance check

Use absolute local paths and preapproved FP/FN limits and minimum per-route sample sizes (the numbers below are **illustrative**, not approved enterprise thresholds):

    python3 -m unittest discover -s ops/waf -p 'test_assess_corpus_evidence.py' -v
    python3 ops/waf/assess_corpus_evidence.py /private/waf/evidence.csv \
      --route-manifest /private/waf/approved-routes.json \
      --max-fp-rate 0 --max-fn-rate 0 --min-benign 1 --min-malicious 1 \
      > /private/waf/confusion-matrix.json

Exit 0 means the supplied, internally consistent corpus met the supplied per-route limits; exit 1 means a measured route failed; exit 2 means invalid/missing/ambiguous evidence. **Exit 0 is not a trusted production acceptance** unless the external ruleset pin, real WAF verdict provenance, route inventory, corpus manifest, threshold approval, independent audit evidence and collection chain of custody have also been verified. Record all those and the exact gateway commit, Windows/Linux build and operating system.

This checker cannot substitute for signed exception rendering, approved WAF ruleset deployment/rollback, real multi-node HA, OWASP evasions and protocol-specific testing, representative customer false positives/negatives or integrated gateway capacity testing with 500 Mbps observed peak plus approved headroom and real p95/p99/CPU/GC/allocations. Those remain under #51, with real physical-environment acceptance under #36. **Do not close #51 or claim production GO solely from this test.**
