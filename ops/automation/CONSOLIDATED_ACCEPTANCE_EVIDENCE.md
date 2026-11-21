# GatewayCore v1 consolidated acceptance evidence ledger

Status: **template only; no acceptance claimed**. This file is an operator checklist for independent review. #36 is the single physical/environment gate; development defects and missing disposable integration tests stay with their software issues. Never put credentials, private topology, customer payloads or private keys in GitHub.

## Immutable identification and provenance

For each execution record UTC start/end, operator and independent reviewer, OS/runtime, gateway build SHA, signed configuration revision/digest, release artifact SHA-256, test-fixture revision, command, raw evidence location, actual result, expected result, verdict and remediation/retest. Freeze evidence under a read-only artifact store with retention and access controls. Record GitHub Actions run **and job** URLs for exact PR head and post-merge main push SHA. An Actions pass is not physical acceptance.

```bash
git rev-parse HEAD
dotnet --info
sha256sum ./GatewayCoreYarp*  # substitute the exact frozen artifact filename
```

On Windows use `Get-FileHash -Algorithm SHA256 <artifact>`, `dotnet --info` and `git rev-parse HEAD`. A missing hash, mismatched signed revision or absent independently reviewable raw output is **FAIL**, not 'pending pass'.

## Software entry gate (review before any physical drill)

For every open development ticket (#34, #35, #37, #38, #48, #49, #50, #51, #52, #53, #100, #101, #109 and verified successors), check the **live** issue state and original acceptance text; do not infer closure from this list. Require merged reviewed source, relevant Windows/Linux exact-head CI, real disposable integration proof, documented rollback and offline installation. #39/#61 remain post-v1 deferred. Record exceptions as development **FAIL**, never transfer them to #36.

Core reproducible DNS acceptance from repository root:

```bash
dotnet build engines/GslbDns/GslbDns.csproj -c Release
dotnet run --project tests/GslbAcceptance/GslbAcceptance.csproj -c Release -- "$PWD"
```

Expected: exit 0 and all required DNS assertions pass on both Windows and Linux Actions; attach exact-head job links. The commands alone do not prove authoritative fleet partition, DNSSEC rollover or public delegation.

## Issue-by-issue evidence manifest

| Issue | Prerequisites and exercise | Required evidence and pass/fail |
|---|---|---|
| #34 L7 allocations | Pinned build, identical payload/mix/concurrency, 3+ paired before/after runs on same runner; dotnet-trace/GC and 60-minute whole-gateway profile | Raw pairs, confidence interval, bytes/request, p50/p95/p99, CPU, errors; FAIL on missing pairing or worsened hard gates |
| #35 CA/PKI | Authorized disposable CA/OCSP/CRL and test HSM if configured; expiry/revocation/rotation and rollback | Chain, failure-mode, key custody and no-replay results; physical enterprise PKI moves to #36 only after software acceptance |
| #37 ACME | Disposable authoritative DNS and RFC2136/TSIG fixture; staging ACME directory, approved test FQDN; issue/renew/revoke and orphan recovery | Signed/serial TXT publication, two-authority visibility, order state, cleanup, cert chain and renewal rollback; never publish production secrets |
| #38 identity/audit | Disposable IdP, 2 nodes, independent HTTPS collector; fail collector, revoke session, restart, replay/tamper and retention expiry | Correlated durable receipts, denial-before-commit, cross-node revocation, redacted records; FAIL if mutations proceed without required audit authority |
| #48 key lifecycle | Windows service DPAPI plus Linux certificate-wrapped keyring; isolated restarts, rotation, restore and lost-key/tamper | Encrypted on-disk inspection, cookie continuity, anti-rollback and DR, OS ACLs; FAIL on plaintext fallback or unexpected session loss |
| #49 GitOps | Disposable Git/registry/Kubernetes reconciliation and signed configuration fixture | RBAC, drift, convergence, reject unsigned/rollback, safe undo and operator-visible state |
| #50 telemetry | Disposable Collector/Prometheus/Grafana with and without collector; HTTP/2 and backend failover traffic | Trace propagation, redaction, cardinality, bounded exporter, loss counters, real alert firing/delivery and before/after overhead |
| #51 WAF | Pinned rule version, approved benign and attack corpora, detect/block/rollback; matched direct/proxy/WAF load | Per-route confusion matrices, approved FP/FN limits, p95/p99/CPU/allocations and no uncontrolled bypass |
| #52 DNS | Disposable authority pairs; UDP/TCP EDNS, referrals, signed NSEC/NSEC3, serial/DS rollover, partition and stale data | Raw dig/kdig captures, DNSSEC validation, convergence, SERVFAIL fences; separately public delegation/recursive networks in #36 |
| #53 L4 | Real disposable TCP/UDP listeners, connect/reset/half-close/stop, loss/reordering and soak | Absolute failures, loss windows, bounded sockets/memory, no replay, Windows/Linux graceful stop |
| #100 queues | Two+ backends; saturate one destination, release, cancel, drain and restart | Per-destination queue upper bound, fairness, 429/503 behavior, zero unbounded growth and no non-idempotent retry |
| #101 peer registry | Two+ disposable peers; disconnect, restart, stale signed state, partition and recovery | Freshness/version fence, bounded sync, no false healthy state, peer convergence |
| #109 distributed health | 2 authorities and 3 independent signed mTLS observers with distinct groups; clock skew, replay, key rotation, quorum loss and partition | Signed evidence, operator RBAC, fail-closed SERVFAIL and recovery only after fresh quorum; predictive signals never override hard health |
| #36 physical | Two independent gateway hosts, signed identical config, VRRP/ECMP, management mTLS, real backend and monitoring | Raw network/host failure traces, absolute failed counts, VIP reconvergence, CA transaction no-replay, CAB signoff |

The rows are a **minimum manifest**, not a replacement for canonical issue criteria. Any unmet original criterion remains FAIL/open.

## Physical capacity procedure — run each gateway alone

1. Capture switch/ISP graphs and timestamped observed **peak response-body Mbps and peak RPS**. Explicitly resolve 500 Mbps versus 500 MB/s; do not substitute NIC nameplate. Pre-register exact p99 limit, zero-error requirement, NIC-drop policy, logging-loss and GC thresholds without relaxing existing values.
2. On gateway A only, remove B from the active traffic path using approved change control. Run the repository capacity kit with the **representative response-size mix, TLS settings, keepalive, connection arrival rate and multiple independent generators**. Save the exact kit command/config and baseline direct-backend run. Repeat separately with B only.
3. Record 60 consecutive one-minute windows for each node. For a verified 500 Mbps peak and approved 50% headroom, **every** window must meet response-body throughput >=750 Mbps **and** >=1.5 × measured peak RPS, zero HTTP/transport errors and the unchanged p99/GC/NIC/logging gates. Report min window and raw histogram, not only one-hour averages.
4. Repeat graceful drain, process kill, network blackhole, host power loss, partition, VIP/ECMP failover and failback, config divergence/rollback, certificate rotation and rolling upgrade. Capture timestamps, absolute errors and actual end-to-end loss interval. Do not use the CI 1.5-second timer as a physical VRRP SLA.
5. Verify live alert **delivery** for gateway down, 5xx, p99, destination ejection, cert expiry and high-priority log loss; record signed change ticket, rollback result, independent reviewer and CAB decision.

## Suggested read-only operator probes

```bash
# Substitute approved hostnames; use test-only credentials, never paste them into logs.
dig +tcp @AUTHORITY_IP example.test SOA +dnssec
dig @AUTHORITY_IP example.test DNSKEY +dnssec
dig @AUTHORITY_IP example.test A +dnssec
curl --fail --show-error --silent https://GATEWAY_TEST_HOST/gateway/health
```

Expected DNS: authoritative AA responses with the intended serial/signatures, valid negative proofs and fail-closed behavior under loss of signed quorum. Expected health: HTTP 200 only when the defined readiness policy passes. These are **probes**, not sufficient standalone proof. Keep public DNS/delegation and enterprise CA/IdP/mail validation within authorized infrastructure and attach sanitized evidence.

## Final decision record

| Field | Required value |
|---|---|
| Frozen main SHA / artifact SHA256 | UNVERIFIED |
| All software issues closed with reviewed evidence | NO |
| Windows/Linux exact-head and merged-main CI | UNVERIFIED |
| Independent physical two-host tests | NOT VERIFIED |
| Per-node 750 Mbps / 1.5x RPS / 60-minute strict gates | NOT VERIFIED |
| Public DNS / PKI / IdP / mail / monitoring | NOT VERIFIED |
| Independent security review and CAB approval | NOT VERIFIED |
| Release decision | **NO-GO** |

Update each field only with links to actual immutable evidence. A physical failure revealing a product defect requires reopening the corresponding development issue; do not waive it in this ledger.
