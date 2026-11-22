# GatewayCore v1 — consolidated independent acceptance evidence protocol

**Status: NOT EXECUTED.** This is an evidence collection contract, not an assertion of software acceptance, physical readiness, or production GO. Keep #36 open. Only an independent authorized tester on approved infrastructure may execute the physical steps. Never upload secrets, real CA transactions, private keys, client data, or unredacted topology.

## Entry gate and immutable manifest

Before any physical activity, record the reviewed, merged software release commit, artifact digest, Windows/Linux exact-head checks, installation/rollback instructions, unresolved issue count, independent reviewer, and approved change record. A missing item is **BLOCKED**, not PASS.

```bash
git rev-parse HEAD
git status --porcelain
sha256sum ./GatewayCore-release-package.zip
git log -1 --format='%H %cI %s'
```

Expected: HEAD equals the approved frozen release SHA, clean tree, package SHA-256 matches the independently published release manifest. Capture command output, runner/host OS and UTC timestamp. **Fail** on mismatch, unsigned/unknown release, missing rollback, or unresolved software defect. Do not infer the release SHA from this document.

## Evidence record schema

For **each** row below retain: issue ID, test ID, exact prereqs and approved configuration revision (redacted), UTC start/end, operator and independent witness, host/platform identifiers (redacted), exact commands and versions, expected result, observed result and raw counters, evidence artifact path plus SHA-256, PASS/FAIL/BLOCKED, remediation/retest reference and approval. A successful command exit code alone is insufficient. Attach artifact hashes and nonsecret summaries to #36; retain restricted raw evidence in the approved repository outside public GitHub.

## Independent physical execution order

| Test | Prerequisites and commands/procedure | Expected evidence / pass criterion |
|---|---|---|
| 36-A topology and isolation | Two independent physical gateways, approved VIP/ECMP design and management mTLS. On each: `hostname; date -u; ip -br addr; ss -lntup` (Windows: `hostname; Get-Date -AsUTC; Get-NetTCPConnection -State Listen`). Inspect firewall ACLs and listener binding with an approved remote probe. | Separate fault domains; only data listeners on data IP, management and metrics on allowlisted management IP. Unauthorized management probe rejected. No unapproved public DNS exposure |
| 36-B signed configuration parity | On both nodes export the approved nonsecret revision, signer fingerprint and canonical digest; compare revisions/digests before and after a staged signed rollout. Submit an invalid signature and stale revision to disposable control-plane test endpoints only. | Both nodes accept exactly the same approved monotonic revision; invalid/stale inputs rejected; divergent revisions fence further mutations. Preserve signed receipt and audit event |
| 36-C graceful and abrupt failover | Approved synthetic GET and non-idempotent POST fixtures only. Capture per-request IDs, HTTP status, gateway, monotonic timestamp and errors while stopping one gateway gracefully, then separately terminating it abruptly; repeat with VIP/ECMP path interruption, host loss, partition, restoration and rolling upgrade. | Record absolute failed requests and exact end-to-end failure interval per drill, not just percentages. No automatic replay of POST; convergence and failback match preapproved limits. Do not substitute CI 1.5s timer for VRRP SLA |
| 36-D solo capacity on EACH node | Confirm peak Mbps **and** measured peak RPS from switch/ISP graphs, then independently remove the other gateway from serving. Use approved traffic mix and multiple generators. Capture one-minute request counts, response-body bytes, p50/p95/p99, HTTP/transport errors, CPU/GC, working set, NIC drops, log drops and audit exporter state for 60 consecutive minutes per node. | If peak is verified **500 Mbps**, every one-minute window on **each gateway alone** must deliver >= **750 Mbps response-body** AND >= **1.5x measured peak RPS**, **zero HTTP/transport errors**, no unacceptable NIC/log loss, and unchanged preapproved p99. Any failing window fails the run; rerun full 60 minutes after remediation |
| 36-E PKI and application safety | Approved test CA/OCSP/CRL/HSM and test-only issuance records; exercise certificate chain failure, expiry warning, rotation, offline bundle install, rollback and management mTLS rejection. | Correct rejection, audit and alert delivery; no duplicated signing transaction or private-key disclosure |
| 36-F DNS and distributed authority | Authorized public test delegation, two authoritative nodes, independent resolver networks, valid DS/key chain and signed observers. Query `dig +dnssec @<approved-authority> <approved-test-name> A` and `dig +tcp +dnssec @<approved-authority> <approved-test-name> A`; repeat with signed report expiry, replay, clock skew, quorum loss, partition, recovery and key rollover. | Authoritative UDP/TCP consistency, DNSSEC validation and convergence within preapproved bound; quorum failure fences answers as specified; no stale/replayed evidence accepted. Retain wire traces with sensitive data removed |
| 36-G identity, audit and monitoring | Test-only enterprise IdP/LDAP/OTP/mail relay, external durable collector and monitoring. Trigger allowed and denied admin actions, distributed logout, collector outage/recovery, alert conditions and rollback. | End-to-end authorization, revocation, immutable external receipt, bounded no-loss/fail-closed policy where required, delivered alerts and verified recovery; no credentials in logs |
| 36-H platform and integrations | Windows service + Ubuntu/RHEL systemd, key backup/restore and rotation, supported IIS/Apache/Nginx/Kubernetes/WAF/L4 integrations where enabled. Test disposable workloads and documented rollback. | Supported platform matrix passes real restart, corruption/rollback rejection and integration contract; unsupported combinations explicitly marked NOT SUPPORTED |
| 36-I operational signoff | Attach issue-by-issue evidence ledger, frozen manifest, redacted topology, full raw-metric artifact digests, incident/rollback rehearsal and CAB record. | Independent review and authorized CAB signoff recorded; otherwise production remains NO-GO |

## Software issue prerequisites (never transfer unfinished software to #36)

| Issue | Disposable software evidence required before physical testing | Physical evidence recorded under #36 |
|---|---|---|
| #34 | 3+ pinned paired Windows/Ubuntu allocation profiles, trace stacks, streaming/POST/affinity/TLS regressions, uncertainty and unchanged p99 | Real-mix CPU/GC/working-set and throughput |
| #35 | CA/PKI/OCSP/CRL/HSM adapter contract and negative tests | Approved enterprise CA/HSM integration and rotation |
| #37 | DNS-01/HTTP-01 issuer lifecycle, lease/orphan recovery, provider/TSIG interoperability, negative and renewal tests | Authorized domain, approved staging CA and air-gap chain installation |
| #38 | All privileged operations durable-audited, signed collector receipt, identity revocation and fail-closed recovery tests | Real IdP, external WORM retention and multi-node revocation |
| #48 | Windows DPAPI and Linux encrypted keyring tests, anti-rollback, restart/restore and migration | Real OS service identities and DR drill |
| #49 | GitOps reconciler, Kubernetes/registry auth and rollback disposable integration | Approved enterprise Git/cluster permissions |
| #50 | Collector/Grafana container acceptance, privacy, dropped-record counters, absent collector and overhead | Live dashboards, retention, alerts and delivery |
| #51 | Versioned WAF corpus and shadow/block confusion matrix, rollback, matched load | Representative customer corpus and governed thresholds |
| #52 | DNS wire/DNSSEC/serial/delegation/GeoIP deterministic and disposable integration | Public delegation, DS, multi-network resolvers and data licensing |
| #53 | TCP/UDP socket, shutdown, resource and no-replay tests | Physical WAN fault/load/soak |
| #100 | Per-destination bounded queue admission, timeout and overload tests | Actual backend contention and sustained load |
| #101 | Peer-state restart, replay/partition and monotonic freshness tests | Multi-host peer recovery/partition |
| #109 | mTLS signed health authority, replay/clock/quorum/fencing and operator authorization tests | Independent observer/authority hosts and DNS convergence |

Any missing software implementation, Windows/Linux CI, disposable lab test, security review, installer or rollback documentation remains an **open development blocker**. Deferred #39 and #61 are not v1 gates unless explicitly re-scoped.

## Final decision

**GO** only if all required software issues are independently reviewed and merged, every applicable physical row passes with evidence, release hashes match, rollback is demonstrated, and CAB approves. **NO-GO** on any failure or missing mandatory evidence. **BLOCKED** means not executed or unavailable, never success. No unattended command in this document performs a production change.
