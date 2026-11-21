# GatewayCore v1 consolidated acceptance evidence manifest

Status: **UNEXECUTED TEMPLATE — NOT PRODUCTION APPROVAL**. This manifest is for independent reviewer and on-site operator evidence. It does not replace the original acceptance criteria in GitHub issues or the existing capacity scripts.

## Evidence identity and integrity

Record release commit SHA, signed artifact filename and SHA256, offline package checksum, OS image/version, gateway binary version, node IDs (redacted), operator, reviewer, UTC start/end, approved change/CAB ID and immutable evidence location. Keep passwords, private keys, client payloads and site addresses out of GitHub.

For each gate below record **prerequisite, exact command/config revision, expected result, actual result, raw evidence URI/hash, PASS/FAIL, reviewer and remediation/retest**. A blank, missing or skipped result is **NOT PASS**. CI or disposable lab results cannot substitute for real physical site results.

| Issue | Software entry evidence to link (mandatory before #36) | Independent environment proof and pass/fail gate |
|---|---|---|
| #34 | Three or more paired pinned allocation profiles, Windows/Linux characterization, p99 and GC regression reports | Representative traffic on each node, raw CPU/GC/working set/p95/p99/throughput with no preapproved threshold breach |
| #35 | Enterprise CA/PKI integration, failure/rollback and offline install tests | Authorized OCSP/CRL/CA/HSM where used; certificate rotation, chain and rollback |
| #37 | ACME issuer/provider, DNS-01/HTTP-01, renewal/orphan recovery and atomic PFX tests | Authorized staging CA, delegated challenge TXT/HTTP proof, chain, renewal and alert delivery |
| #38 | Signed audit receipt and fail-closed mutation, distributed revocation, IdP and retention tests | Real IdP, OTP/passkey recovery, WORM retention, external collector and multi-node revocation |
| #48 | Encrypted DP keyring, tamper/restart/backup/DR and supported Windows/Linux matrix | Service account permissions, key rotation, lost-key and restore drill on supported OS |
| #49 | GitOps reconciler/rollout, Kubernetes and rollback integration tests | Authorized repository/registry/cluster credentials and live reconciliation |
| #50 | Collector/Grafana integration, exporter backpressure and dashboard/alert fixtures | Live OTLP retention, high-priority log drop, backend outage, 5xx, p99 and cert-expiry alerts delivered |
| #51 | Pinned WAF rules, benign/malicious ground-truth corpus, per-route FP/FN, shadow/block and rollback tests | Approved representative traffic and thresholds, matched direct/proxy/WAF load, no uncontrolled bypass |
| #52 | DNS authority, DNSSEC/NSEC3, delegation, serial/key rollover and GeoIP tests | Authorized delegation and DS, real resolver/network interoperability, key rollover and licensed GeoIP data |
| #53 | L4 TCP/UDP real-socket Windows/Linux tests, loss and restart bounds | Real WAN fault, packet loss/reorder, long soak and resource ceiling evidence |
| #100 | Per-destination bounded queue, overload/rejection and non-replay tests | Live multi-backend admission under fault and full load |
| #101 | Signed peer-state freshness, restart/partition and replay tests | Independent peers partition/rejoin with no stale authority or false freshness |
| #109 | Signed mTLS observers, quorum, replay, partition fencing, operator controls and DNS convergence tests | Independent authorities/vantages, clock skew, key rotation, partition and recovery |
| #36 | All software issues reviewed and closed by authorized integrator, exact-head CI, frozen offline release and rollback | Two independent physical gateway hosts, signed config parity, failover/failback, CA no-replay, monitoring and CAB signoff |

## Mandatory solo capacity protocol (#36)

First verify **500 Mbps versus 500 MB/s** from switch/ISP records and peak RPS. At 500 Mbps and 50% headroom the floor is **750 Mbps response body per gateway alone**, and **1.5 times measured peak RPS**, in **each of 60 complete consecutive one-minute windows**. Run NODE_A alone and NODE_B alone separately, with zero HTTP/transport errors and unchanged preapproved p99, CPU/GC, NIC-drop and high-priority logging gates. Shared 375 Mbps tests, partial windows, missing telemetry or averages masking failed minutes are FAIL. If peak is 500 MB/s, the 50%-headroom target is 6.0 Gbps; do not reuse 750 Mbps.

From a clean checkout of the **frozen release SHA** (commands are examples, not claims of execution):

```bash
git rev-parse HEAD
sha256sum path/to/offline-release-artifact
cp ops/capacity/scenario.500mbps.eod.template.json NODE_A.json
# Populate NODE_A.json with actual measured RPS, response mix, TLS, generators, NIC and strict p99.
python3 ops/capacity/limits.py --scenario NODE_A.json --profile actual-node-a-limits.json --out limits-A.json
python3 ops/capacity/run_oha.py --scenario NODE_A.json --host-id GENERATOR_A --out raw/A/GENERATOR_A --dry-run
# After independently verified backend baseline, run the approved full test (without --dry-run).
python3 ops/capacity/report.py --scenario NODE_A.json --results raw/A --gateway-csv real-node-A.csv --out gate-A.json
# Repeat from a separately populated NODE_B.json for NODE_B alone.
```

Record all raw per-minute measurements, generator saturation checks, TLS/SNI and response mix, backend-only baseline, exact scenario hash, full generator command and report JSON. Do not substitute CI-generated synthetic figures for site evidence.

## Physical fault and security protocol

Prerequisites: independent failure domains; identical approved signed monotonic config digest/revision on both nodes; isolated management mTLS and data-plane VIP/ECMP; approved maintenance window, rollback and CA transaction canaries. Record UTC fault-injection and recovery timestamps, **absolute failed request count**, last error time and signed audit records for graceful drain, abrupt process kill, host loss, VIP migration, blackhole/partition, failback, key/certificate rotation and rolling upgrade. Any unauthorized config divergence, replay of non-idempotent signing POST, unsafe fail-open, missing audit or unapproved traffic shift is FAIL.

## Review decision

**NO-GO by default.** Release SHA: PENDING. Software gate evidence: PENDING. Physical gate evidence: PENDING. Independent reviewer: PENDING. CAB signoff: PENDING. No release publication or issue closure is authorized by this document.

References: [#36](https://github.com/VY-Groups/yarp-lb/issues/36), [AGENTS.md](../../AGENTS.md), [EOD capacity plan](../capacity/EOD_500MBPS_RELEASE_PLAN.md), [on-prem run order](../automation/ONPREM_RUN_ORDER.md).
