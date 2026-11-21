# GatewayCore consolidated release acceptance evidence worksheet

Status: **UNEXECUTED TEMPLATE — not a release approval**. Owner: independent reviewer / site acceptance team. Scope: issue #36 physical acceptance, entered only after every software issue has separately satisfied its original acceptance criteria and reviewed CI. Do not store credentials, private topology, customer payloads or private keys here.

## Freeze and software entry gate

Record UTC timestamp, `git rev-parse HEAD`, signed release identifier, artifact SHA-256 (`sha256sum <artifact>` on Linux or `Get-FileHash <artifact> -Algorithm SHA256` on Windows), platform/runtime (`dotnet --info`), independent reviewer and exact required workflow/job URLs. Compare the SHA against the immutable approved release manifest. **FAIL** if SHA, provenance, signature, OS matrix, offline installer, rollback instructions, any required CI, or independent review is missing. Do not use a green PR check as evidence that the exact merged main push passed.

For main push checks, query `GET /repos/VY-Groups/yarp-lb/actions/runs?head_sha=<MAIN_SHA>&event=push&per_page=100` (paginate); for every run retrieve `GET /repos/VY-Groups/yarp-lb/actions/runs/<RUN_ID>/jobs?per_page=100` and inspect failures. Save run ID, head SHA, event, workflow name, job ID, conclusion and URLs. A PR-filtered workflow lookup is not equivalent.

## Physical site prerequisites

Two separate gateway hosts, independently powered and networked, with an approved VRRP VIP or explicitly reviewed ECMP; identical signed monotonic configuration and signer identity; management-only mTLS on allowlisted addresses; isolated metrics listener; real backend readiness and separate CA/transaction safeguards. Record sanitized host inventory, interface speed, switch/ISP **measured peak** and peak request rate, OS/service identities, signed config digest/revision, exact deployment and rollback commands. No Redis requirement for v1. Keep #39/#61 deferred.

## Per-node solo capacity, 60 minutes EACH

Before testing, record the approved p99 ceiling, baseline CPU/GC/working set, NIC-drop ceiling, response-size mix, keepalive/TLS profile and measured peak RPS. Confirm 500 **Mbps**, not 500 MB/s, from network telemetry. For 500 Mbps and 50% headroom, required minimum is **750 Mbps response-body** and **1.5 × measured peak RPS**, in **each of 60 consecutive one-minute windows**, with **zero HTTP/transport errors** and unchanged p99, GC, NIC and high-priority logging gates. A combined two-node throughput number is insufficient.

Use the versioned capacity kit under `ops/capacity/` and run order in `ops/automation/ONPREM_RUN_ORDER.md`; pin load-generator version and command line in the evidence record. Execute one gateway alone while the other is excluded from traffic, then swap. Export per-minute request count, body bytes, errors, p50/p95/p99, NIC drops, CPU, GC pauses, memory, log drop counters, TLS/new-connection rate and exact load-generator output. Calculate `body_Mbps = response_body_bytes * 8 / (window_seconds * 1000000)` per window. **FAIL** any minute below either rate, above p99, or with any error; do not average away a bad window. Record uncertainty and rerun only after documented remediation.

## HA and security fault matrix

For every scenario capture UTC start/end, exact sanitized fault command, expected state, actual request/error count and first/last failure timestamps, alert delivery, signed audit correlation and independent witness.

| Scenario | Expected pass behavior |
| --- | --- |
| Graceful drain and rolling restart | New traffic drains; in-flight transactions remain safe; no automatic replay of non-idempotent POST |
| Abrupt process kill / full host power loss | VIP/ECMP reconverges; absolute errors and outage interval measured; no invented 1.5-second VRRP SLA |
| Blackholed gateway / asymmetric partition | Unreachable or stale gateway is fenced; split-brain config cannot be activated |
| VIP migration and failback | Stable signed revision/digest on both hosts, measured traffic convergence and no stale route resurrection |
| Config rollback/replay/tampering | Invalid signature, revision rollback and mismatched digest rejected before mutation |
| Certificate/key rotation and loss | Approved trust transition, no plaintext fallback, documented recovery and failed-auth denial |
| CA signing POST during failure | No retry or duplicate issuance without independently verified transaction semantics |

## DNS, PKI, identity and telemetry evidence

DNS (#52/#109): record authorized delegation, two authoritative servers, UDP/TCP/EDNS/DNSSEC and negative-response `dig`/`kdig` commands, DS/key/serial changes, partition/clock/quorum fencing, public resolver traces, licensed GeoIP dataset/version and ECS privacy. **FAIL** stale signed evidence, unsafe answer or unverifiable delegation.

ACME/PKI (#35/#37/#48): record approved staging CA, authorized domain and DNS-01 TSIG integration, challenge cleanup/orphan recovery, offline chain installation, renewal and rollback, CA/CRL/OCSP/HSM where configured, DP key-ring encrypted backup/rotation/restart/DR across supported Windows and Linux service identities. **FAIL** missing secure restoration or live private-key exposure.

Identity/audit (#38): record real IdP federation and logout/revocation across nodes, RBAC/CSRF, collector delivery receipts, WORM retention, notification and failure recovery; no sensitive event payload in GitHub. **FAIL** unaudited security mutation or stale revoked session.

Observability/WAF/admission (#50/#51/#100/#101): record actual Collector/Grafana dashboards, delivered alert timestamps, privacy and bounded queue loss metrics, approved per-route benign/malicious corpus FP/FN, peer restart/partition and admission behavior. Preserve pinned software lab fixtures and separately record site results. **FAIL** silent high-priority log loss, uncontrolled WAF bypass, unbounded queue, or false peer freshness.

## Signoff record (fill after execution)

| Field | Evidence |
| --- | --- |
| Frozen main SHA and release artifact SHA-256 | NOT VERIFIED |
| Independent code review and exact-head Windows/Linux CI | NOT VERIFIED |
| Host A solo 60-minute gates | NOT RUN |
| Host B solo 60-minute gates | NOT RUN |
| HA/failover and transaction safety | NOT RUN |
| Public DNS, CA/PKI, IdP, mail and security | NOT RUN |
| Live alerts, audit retention and CAB approval | NOT RUN |
| Rollback rehearsal, approver, UTC timestamp | NOT RUN |

**Decision: NO-GO until every applicable row is independently PASS with raw evidence.** A product defect found on site reopens its development issue; do not reclassify missing software or CI as site-only work.
