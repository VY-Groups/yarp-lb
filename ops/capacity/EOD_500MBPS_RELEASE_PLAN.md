# EOD v0.1 on-prem readiness — reported 500 Mbps peak

**State: PRE-PRODUCTION VALIDATION; PRODUCTION NO-GO** until the original
physical hardware release gates and approvals pass. No network or CA servers
are touched by GitHub Actions. PR #60 is a draft and remains unmerged.

## Source-of-truth measurements

- The operator reported *500 Mbps maximum traffic*, assumed **0.5 Gbps**.
  Confirm in the switch/ISP graph that this is **megabits per second**,
  not 500 MB/s (4.0 Gbps). Confirm direction (ingress/egress) and
  p95/max interval, not nameplate 10GbE. The `peak_gbps` scenario is
  reported-unverified until linked raw traffic evidence is filed.
- Original **50% headroom** is untouched. The solo-gateway body throughput
  gate is `0.5 * 1.5 = 0.75 Gbps` = **750 Mbps** = **93.75 MB/s**.
  Original 30% scenario is **650 Mbps**, and must be run separately if
  management approves the 30% alternative; never silently switch from 50%.
- **If 500 MB/s**, the corresponding gate is **6.0 Gbps**, still under
  the existing 90%-of-10Gbps link cap (9 Gbps); DO NOT run the 750 Mbps
  case until units are confirmed.
- Body Gbps is lower than switch wire Gbps for normal packet headers.
  The reporter checks HTTP response BODY bytes, so using the reported
  0.5 Gbps wire measurement as the BODY floor is conservative.
  Verify real response payload mix and compression policy.

## EOD stop-or-go sequence (cannot be shortened)

1. **T0 — Freeze real measured inputs.** Populate
   `ops/capacity/scenario.500mbps.eod.template.json` with peak RPS,
   response-size mix with actual weights and protocols, concurrent clients,
   new connections/s, HTTPS share, TLS CA, hardware CPU/RAM/NIC model and
   speed, and preapproved strict p99 cap. Both generator host IDs must
   reflect independent load generators. **STOP** on any missing field,
   ambiguous Mbps/MBps, link speed mismatch, impossible target or
   `INFEASIBLE_LINK`. Do not copy test fixture values into live config.
2. **T1 — Generators directly to BACKENDS.** Confirm both generator and
   backends sustain the identical mixed scenario and TLS conditions,
   no drops/errors and reliable time synchronization. **STOP** on loss,
   generator saturation, bad certificate/SNI, or backend shortfall.
3. **T2 — HAProxy baseline.** Identical per-host bytes, connection mode,
   cipher/P-256, ALPN, keep-alive and response paths, then inspect
   CPU, RSS, NIC ring, RSS, IRQ, offloads, socket buffers and conntrack.
   One tuning change at a time with before/after counters. **STOP** on
   baseline failure, packet drops, or regressions.
4. **T3 — Gateway exploratory ramp.** Confirm actual NIC capacity and
   measured peak concurrent clients; derive
   `MaxConcurrentConnections >= ceil(1.5*peak concurrent clients)`
   and `LimitNOFILE >= ceil(2.5*actual MaxConcurrentConnections+4096)`.
   Fail-closed `python3 ops/capacity/limits.py --scenario NODE_A.json
   --profile actual-node-a-limits.json --out limits-A.json`.
5. **T4 — TWO SOLO ONE-HOUR TESTS.** NODE_A alone receives the entire
   750 Mbps BODY target **plus >=1.5*real peak RPS** for 60 complete
   minutes, 0 errors, strict p99 and real CPU/GC/NIC telemetry.
   Repeat separately for NODE_B alone, NOT two shared 375 Mbps runs.
   `run_oha.py` restarts connections each minute, so run an independent
   long-lived connection soak as well. **STOP** on any failed minute,
   uncollected sample, missing identity/telemetry or p99 exceedance.
6. **T5 — Physical redundancy, then monitoring.** Prove two independent
   host fault domains and identical signed monotonic configs; drain,
   SIGTERM, SIGKILL, host loss, VRRP/ECMP migration, blackhole/partition,
   failback and absence of non-idempotent CA replay. Record **actual**
   last failure and failed counts, not the ~1.5s Windows CI kill number.
   After HA acceptance, inject gateway down, 5xx, high p99, backend
   failure, log drops, and certificate expiring. Verify alert DELIVERY,
   Grafana dashboards, rollback, cert rotation and authorized CA review.
7. **T6 — Approve or remain NO-GO.** Keep PR draft/rollout disabled
   unless the physical report, both one-hour raw runs, dashboards,
   signed-config fingerprints, non-root keepalived and CA/CAB
   signoff are attached and independently accepted.

**Minimum elapsed time:** two separate 60-minute solo tests consume
**at least 120 minutes**, *after* baseline/exploration and before failure
drills; EOD completion depends on available physical hosts and operators.

## Exact operator commands (not executed on-site)

```bash
# Copy and complete independently for NODE_A and NODE_B.
cp ops/capacity/scenario.500mbps.eod.template.json NODE_A.json
# Update node IDs, actual output hosts, RPS, mix, TLS, NIC, CPU, p99, concurrency, etc.
python3 ops/capacity/limits.py --scenario NODE_A.json \
  --profile actual-node-a-limits.json --out limits-A.json
python3 ops/capacity/run_oha.py --scenario NODE_A.json \
  --host-id GENERATOR_A --out raw/A/GENERATOR_A --dry-run
# Remove --dry-run only after baseline is green; run both hosts synchronized.
python3 ops/capacity/report.py --scenario NODE_A.json \
  --results raw/A --gateway-csv real-node-A.csv --out gate-A.json
# Repeat for NODE_B independently with NODE_B.json and real-node-B.csv.
```

Version **1 #36**: two on-prem gateway hosts, VIP/ECMP, same signed config,
no Redis; Redis is separately tracked in #61. VRRP physical failure time
is **not** the 1.5s lab result; measure real elapsed window, possibly
several seconds. A production signature/CAB authorization is manual,
never inferred from a test runner.

## CI evidence is not site acceptance

The GitHub-hosted 1-hour k6 soak passed on a different workload:
34,010,745 requests, 0 request failures, p99 32.29ms, but 993,610
dropped low-priority logs, so the strict no-log-loss operations gate
**remains NO-GO**. The new 750Mbps CI canary uses a synthetic fixed 1MiB
body for 20 seconds, only to diagnose reference/gateway performance
without needing actual servers. Its result does **not** replace either
60-minute physical test or the real traffic mix.

Production status stays **NO-GO** without explicit site evidence.
