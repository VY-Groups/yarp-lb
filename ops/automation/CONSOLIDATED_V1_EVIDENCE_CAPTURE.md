# GatewayCore v1 — consolidated evidence capture (issue #36)

Status: **template only, not execution evidence**. Production is **NO-GO** until all software gates and this physical acceptance pass. This file must never be interpreted as a green check.

## Evidence provenance and freeze

Record the reviewed `main` SHA, immutable release tag, signed artifact SHA-256, offline dependency inventory, test host OS/build, architecture, NIC driver/firmware, clock synchronization, reviewer, and UTC start/end timestamps. Store raw JSON, logs, packet captures, traces, job URLs and approval records in an access-controlled evidence bundle. Redact credentials, CA transaction data, personal identifiers and secrets. Record **PASS / FAIL / NOT RUN** for each gate; missing data means NOT RUN, never PASS.

```bash
git rev-parse HEAD
git status --porcelain
sha256sum ./release/*              # compare with signed release manifest
dotnet --info
uname -a
ip -br addr
ip -s link
```

Windows equivalents (PowerShell): `git rev-parse HEAD`, `Get-FileHash .\release\* -Algorithm SHA256`, `dotnet --info`, `Get-ComputerInfo`, `Get-NetAdapter | Format-List *`, `Get-NetAdapterStatistics`. Commands are examples; adapt paths only in the approved run sheet. Never place production credentials in shell history or evidence.

## Software entry gates — each is a separate issue

| Issue | Required software evidence before physical acceptance | Failure criterion |
|---|---|---|
| #34 | >=3 paired pinned before/after runs on Windows and Ubuntu; allocation stack traces, Gen0/1/2, pauses, working set, p95/p99, throughput, streaming/POST/affinity/health/TLS characterization | Missing raw traces, uncertainty or correctness regressions |
| #37 | ACME HTTP-01 and DNS-01 disposable real-protocol issuer/provider integration, renew/revoke/restart/orphan recovery, strict key and TSIG handling, rollback | Unhandled orphan order, leaked secret, or broken zero-downtime renewal |
| #48 | Windows DPAPI and Linux encrypted key-ring persistence, rotation, backup/restore, fleet antirollback, negative tamper/missing-key, Windows/Ubuntu/RHEL support matrix | Plaintext persistent fallback or session isolation failure |
| #50 | Containerized OTLP Collector + Prometheus/Grafana acceptance, exporter absent/backpressure, privacy, retention, cardinality and Windows/Linux overhead | Missing metrics, unbounded memory, PII leakage or traffic blocking |
| #51 | Version-pinned WAF rules, shadow/block/rollback, bounded audited exceptions, labeled benign and attack corpora, per-route FP/FN, matched load and Windows/Linux evidence | Broad bypass, missing corpus, unsafe replay or unapproved FP/FN threshold |
| #52/#109 and successor tickets | Authoritative DNS/DNSSEC/health quorum, replay/partition fencing, signed state and operator controls with disposable Windows/Linux acceptance | Stale authority, split-brain publication, unsigned state or untested rollback |
| #100/#101 and other successor tickets | Per-destination queue bounds, peer-state convergence and failure recovery, exact-head CI | Missing implementation or failed integration |
| #35/#38/#49/#53 if closed | Preserve issue-specific merged SHA, original acceptance, exact-head CI, rollback and reviewer evidence | Closure without complete software evidence |

For every issue record PR URL, commit SHA, exact-head Actions run and job URLs, command, fixture digest, expected and actual output, reviewer and verdict. A merged PR alone is not issue completion.

## Physical entry and isolation

Two independent physical gateway hosts with different power/network failure domains. Choose and document **VRRP VIP** (root-owned keepalived config; dedicated unprivileged check identity) or a reviewed ECMP design. Both hosts must run identical signed monotonic routing revision/digest; reject rollback and mutation on divergence. Bind data listeners to approved data IPs, management API to management-only allowlisted IP with mTLS, and metrics to management IP only. No Redis dependency for v1. Test with disposable CA transaction fixtures before any approved live signing workflow.

Preflight evidence:
- Host A and B identities, rack/power/switch, NIC/driver, OS, gateway process/service, routes, VIP/ECMP config, cert chain/expiry and firewall ACL export
- SHA-256 of signed routing config on **both** nodes, signer identity, monotonic revision, authorization and change ticket
- Health and readiness from each node and independent external probe; negative tests for unsigned/downgraded/divergent revisions
- Offline install, service start/restart, upgrade and rollback, with measured downtime and preserved key/session state

## Capacity gate (repeat independently on A-only and B-only)

First prove from switch/ISP records that peak traffic is **500 Mbps**, not **500 MB/s**; preserve original graphs and measured peak RPS. If 500 Mbps is validated, each surviving node alone must sustain **>=750 Mbps response-body throughput AND >=1.5 × measured peak RPS** for **60 consecutive minutes**, with zero errors and the existing unchanged per-minute p99 ceiling. A bandwidth-only or RPS-only pass is a FAIL. Capture response-size mix, concurrency, HTTP/1.1 vs HTTP/2, TLS settings, signing POST distribution, generator saturation and baseline direct-backend throughput.

```bash
# On approved load generator hosts only; never execute against production without CAB.
# Replace placeholders from the signed run sheet. Use independent generator machines.
oha --duration 60m --concurrency <approved_concurrency> https://<approved_test_vip>/<safe_fixture>
# Capture once per minute on BOTH gateways and generators:
date -u; ip -s link; ss -s
```

The example command does not by itself establish response-body Mbps or real peak RPS. Capture per-minute body bytes, successful requests, errors by status, p50/p95/p99, CPU, working set, GC generations/pause, NIC drops, queue drops and high-priority log loss from the approved load harness. Store raw per-minute series and report `min(body_mbps)`, `min(rps)`, `max(p99)`, total errors and dropped records. No averaged 60-minute throughput may mask a failed minute. Preserve direct-backend baseline and identical fixture SHA.

## Failure injection and security

Perform and record **at least ten** repetitions of each approved scenario where repeatable: graceful drain/SIGTERM, abrupt process kill, physical host loss, VIP migration, blackhole, asymmetric partition, link flap, reconvergence, failback, config disagreement, cert rotation and rolling upgrade. Measure absolute failed requests, first/last error timestamps, end-to-end outage window and recovery, not only failure percentage. Do not reuse a CI process-kill timer as a VRRP SLA. Confirm no duplicate replay of non-idempotent CA signing POSTs, no management/metrics access from data plane, no split-brain authority and no stale signed revision acceptance.

Example evidence probes from an independent host:
```bash
curl --fail-with-body --silent --show-error https://<approved_test_vip>/gateway/health
openssl s_client -connect <approved_management_ip>:<management_port> -servername <approved_management_name> -verify_return_error </dev/null
dig @<approved_authority_ip> <approved_zone> SOA +dnssec +tcp
dig @<approved_authority_ip> <approved_zone> DNSKEY +dnssec +tcp
```
Expected: health 200 only for ready data plane; management requires authorized mTLS; DNS AA/SOA/DNSKEY, serial and signatures agree with approved delegation and published key material. A health 200 alone does not prove failover or PKI correctness.

## External acceptance in one owner batch

| Gate | Prerequisites | Evidence | PASS only when |
|---|---|---|---|
| Public DNS/delegation | Authorized domain, parent delegation and approved DNSSEC keys | Parent/child DS/DNSKEY, SOA serial, TCP/UDP and independent resolver traces | Converges without stale/split-brain answers |
| CA/PKI/IdP/mail | Approved staging accounts, chain, HSM where used, IdP and mail relay | Issuance/renew/revoke, auth/logout/revocation, message receipt and rollback | End-to-end accepted with no credential leakage |
| Live monitoring | Collector/Prometheus/Grafana/alert receiver with access control | Dashboard exports, alert firing and actual delivery, retention/privacy verification | 5xx, p99, cert <14d, unhealthy backend, high-priority log drops and audit loss alert |
| Operations/CAB | Signed release manifest, install/rollback, owner and independent reviewer | Change ticket, test evidence index, incident/rollback rehearsal and CAB signatures | All required signoffs recorded and no unresolved critical defect |

## Final decision

A designated independent reviewer signs each issue evidence row and each physical gate. Record verdict, evidence URL/hash, exceptions and reviewer identity. Any missing or failed gate is **NO-GO**. A physical defect requiring a software fix reopens the corresponding development issue and restarts exact-head Windows/Linux acceptance. Only after all gates pass may the owner consider a production GO decision.
