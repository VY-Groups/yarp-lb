# WAF block / detect-only evidence contract (v2)

This offline checker evaluates **operator-supplied** per-route evidence. It
does not receive traffic, configure the WAF, independently validate the
audit records, or authorize production enforcement.

## Versioned inputs

The preapproved policy must be a JSON object with exactly these fields:

```json
{
  "schemaVersion": 2,
  "mode": "detect",
  "routes": {
    "synthetic_api": {"max_fp": 0, "max_fn": 0}
  }
}
```

The CSV evidence must include exactly:
`case_id,route,expected,observed,would_block,mode,severity`.

- `expected` is the precommitted ground truth (`benign` or `malicious`).
- `observed` is the **actual HTTP behavior** (`allow` or `block`).
- `would_block` is the **independently collected rule verdict**, canonical
  lowercase `true` or `false`; an HTTP status alone does not establish it.
  Before a customer acceptance, independently correlate this value with the
  approved WAF audit/rule event ID, pinned policy digest, case ID and UTC
  timestamp in controlled private evidence storage. This validator **does
  not verify those sources** and must not be presented as proof of them.
- `mode` must match the entire policy (`detect` or `block`).
  `severity` is one of low, medium, high, critical.

Example synthetic detection-only CSV:

```csv
case_id,route,expected,observed,would_block,mode,severity
benign-test,synthetic_api,benign,allow,false,detect,low
attack-test,synthetic_api,malicious,allow,true,detect,high
```

In `detect` mode, every actual response must be allowed, yet the
`would_block` rule verdict determines TP/TN/FP/FN. This prevents
**all attacks being incorrectly counted as false negatives** solely because
shadow mode intentionally allows them. In `block` mode the actual HTTP
decision and `would_block` must match; disagreement fails immediately.

Version-1 corpus files (which lacked `would_block`) are **rejected**,
rather than silently treating an observed allowance as an undetected attack.
Every approved route requires both benign and malicious cases. The per-route
FP/FN thresholds are never weakened or auto-selected from the CSV.

## Run and protect results

```bash
python3 ops/waf/corpus_evidence_gate.py \
  --policy /private/approved-waf-policy-v2.json \
  --corpus /private/approved-waf-corpus-v2.csv \
  --out /private/waf-evidence-report.json
```

The CLI prints only a PASS/FAIL status and case count. The local detailed
report (including operator-selected route labels) is written atomically with
owner-only `0600` permissions on POSIX, using exclusive creation and
no-follow temp handling. **Use a trusted private output directory.**
Never attach the corpus/report or ModSecurity raw audit logs to public
GitHub issues or CI artifacts. The dedicated workflow tests *synthetic*
fixtures only and runs no customer evidence.

This is a correctness and privacy test for the report processor, **not**
production WAF governance, signed rollback, real-rule evidence integrity,
representative false-positive/false-negative acceptance, Windows/Linux
YARP+WAF load testing or issue #51 completion. Physical host testing remains
under #36.
