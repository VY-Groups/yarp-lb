# GatewayCore v1 consolidated acceptance evidence manifest

Status: **unexecuted template; NOT an acceptance result**. This file is for independent reviewers and the owner to collect one batch of evidence for [physical acceptance #36](https://github.com/VY-Groups/yarp-lb/issues/36). It does not move incomplete software implementation or disposable-lab tests into #36. The canonical issue text controls whenever a criterion below is abbreviated.

## Freeze and provenance

Record UTC timestamps, the immutable merged `main` SHA, signed release artifact names and SHA-256 hashes, installer version, configuration digest and monotonically increasing signed revision, platform and OS build, .NET runtime, DNS zone serial and DNSSEC key IDs. Save raw commands, exit codes, sanitized stdout/stderr, CI run/job URLs, packet captures where authorized, dashboards, and independent reviewer identity. Evidence must be from the **same release candidate**; changing code, binaries, configuration policy or thresholds invalidates affected measurements.

Before any site test, an independent reviewer must verify: all development issues are closed with their own source/Windows/Linux/disposable-integration evidence; exact merged-main push checks are green (inspect GitHub Actions **push** runs for that SHA, not only PR runs); no pending required reviews or security findings; installation and rollback instructions have been rehearsed on disposable hosts. Any failed software behavior reopens its development issue. Do not treat a closed issue as evidence by itself.

## Evidence collection worksheet

For each row, enter: **operator / UTC start-end / environment and host IDs / command or procedure revision / expected result / actual result / artifact path and SHA-256 / independent witness / PASS, FAIL or NOT RUN**. Blank evidence is NOT RUN, never PASS.

| Gate | Prerequisite and procedure | PASS evidence | FAIL or stop condition |
| --- | --- | --- | --- |
| G01 release integrity | Freeze commit, verify signed config identity/revision on both nodes and `sha256sum <artifact>` (Linux) or `Get-FileHash <artifact> -Algorithm SHA256` (PowerShell) against independently published hashes | Both hosts identical approved binaries and signed configuration; rollback rejection recorded | Mismatch, missing signature, stale revision or unknown provenance |
| G02 isolation | Inspect firewall, listening addresses, management mTLS and metrics allowlist on each host; attempt unauthorized access from a separate test source | Data plane on approved IPs; management/metrics inaccessible to unapproved sources; mTLS rejects untrusted client | Any management exposure or authentication bypass |
| G03 independent HA | On two distinct hosts with documented rack/network/power paths, record VRRP VIP or approved ECMP ownership; kill/stop each gateway separately while sending GET and non-idempotent POST test traffic | Failover durations, absolute error counts and p99 recorded for both directions; no duplicate signing POST | Unapproved retry, stale config, split-brain VIP, or unbounded outage |
| G04 capacity node A | Establish actual peak RPS and whether source measurement is 500 Mbps (not 500 MB/s); run **node A alone** for 60 continuous minutes with representative TLS, response-size and request-method mix | Response-body throughput >= 750 Mbps AND >= 1.5x measured peak RPS in every required reporting window, zero errors, unchanged approved p99 limit; preserve per-minute CPU/GC/NIC/log-drop data | Any missing minute, any error, failed throughput/RPS/p99/NIC/log gate |
| G05 capacity node B | Repeat G04 independently with **node B alone**, same frozen scenario and thresholds | Same full 60-minute pass on node B | Combining node capacity or shortening the run |
| G06 public DNS | With approved delegated test zone, query both authoritative nodes and independent recursive resolvers using `dig +tcp`, `dig +dnssec`, `dig +bufsize=1232`, `dig SOA`, `dig NS`, `dig A`, `dig AAAA` and negative names; capture serials and DNSSEC validation | Correct authoritative/recursive behavior, delegation, signed denial, bounded convergence and rollback; fail-closed unready-site routing | Lame delegation, bogus signatures, stale serial or transaction-unready answer |
| G07 CA/PKI and ACME | Approved staging CA, delegated challenge zone, real TSIG/issuer credentials via secret store, renewal and revoke rehearsal; record DNS TXT publish/cleanup, PFX atomic replacement, failed-renewal recovery | Verified staging order, key protection, rollback and no orphan challenge; no secrets in evidence | Credential disclosure, invalid certificate, orphan challenge or silent renewal failure |
| G08 enterprise integration | Approved test IdP/AD, mail relay, PKI/HSM as applicable; exercise login/logout/revocation, audit receipt, password reset, mail delivery and backend IIS/Apache/Nginx/Ingress paths where supported | Independent positive/negative evidence, durable audit correlation and rollback | Privilege bypass, missing durable audit, untested claimed integration |
| G09 monitoring and operations | Enable live collector/alert receivers; simulate gateway down, backend ejection, certificate expiry warning, high-priority log loss and DNS stale quorum | Alert delivery with timestamps, redacted traces, stable cardinality and retention; collector outage does not block traffic | Missing alert, PII leak, unbounded telemetry or blocked forwarding |
| G10 CAB and recovery | Perform controlled upgrade, restart, restore and rollback on both hosts; record operator and reviewer signoffs | Recovery time, config monotonicity, backup integrity and approved change ticket recorded | Unrehearsed rollback, inconsistent restored state or absent CAB approval |

Use `dig @<authority-ip> <approved-test-zone> SOA +norecurse` and the corresponding TCP/DNSSEC variants for G06. Replace placeholders only with authorized lab/test values; never include production credentials or private network topology in GitHub artifacts.

## Required software evidence cross-reference

Before G01, attach the latest accepted issue/PR/commit and Windows/Linux test artifacts for DNS and distributed authority (#52/#109), hot-path allocation (#34), ACME (#37), durable audit (#38), key-ring recovery (#48), telemetry (#50), WAF (#51), per-destination admission (#100), and peer registry (#101), **where these are in scope or successor tickets exist**. Explicitly identify any still-open development issue; do not reclassify it as environment-only. #39 and #61 remain deferred post-v1.

## Decision

Production is **NO-GO** unless every mandatory row has reproducible PASS evidence, required independent reviews and CAB signoff are recorded, and there are no open release-blocking development defects. A passing CI suite or a partial cloud/lab test never substitutes for G03-G10. Record the final release SHA, signed artifact hashes, issue references, reviewer signatures and decision timestamp in the approved release record; do not publish a release based on this template.
