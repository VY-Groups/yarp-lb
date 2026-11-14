# v0.1 CI GO is not production GO

The release verifier fetches the live GitHub Actions API and insists that
**all 14** named checks are `completed/success` on the **exact same
40-character source SHA**. A previous or newer successful build cannot
substitute, and a failed/missing/pending check never passes. The run can
be traced by the exact GitHub Actions links in the uploaded evidence JSON.

Run locally with **real API JSON** only:

```bash
python3 ops/release/assess_ci.py --runs actual-runs.json \
  --sha ACTUAL_40_CHAR_GIT_SHA --out evidence.json
```

GitHub automatically exercises the same verifier through
`v01-release-evidence.yml`. This is **software/CI readiness for the
disposable test environment**, not a signoff that the software is installed
on two independent production hosts.

**Production remains NO-GO** without the real 500 Mbps-versus-500 MB/s
traffic-source graph, peak RPS, connection churn, HTTPS/body-size mix,
precommitted p99, server CPU/RAM/NIC inventory, HAProxy/OSI tuning
baseline, a 60-minute solo 750 Mbps+RPS test on EACH physical gateway
with zero errors and zero operational log loss, independent physical
VRRP/ECMP and network fault injection, real metrics/alert delivery,
signed config and key-ring consistency, PKI revocation/rotation,
restore/rollback proof and authorized CA/CAB approval.

No lowering of thresholds, no software-only workaround to obtain a
production GO, and no automatic deployment from this workflow.
