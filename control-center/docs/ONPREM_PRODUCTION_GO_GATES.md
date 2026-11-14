# Single-tenant on-prem production release gates — **NO-GO**

This document describes the shipping candidate on the draft
PR #60 and replaces
the obsolete loopback-only/Redis-as-P0 guidance. **No production
deployment has happened from CI.** An auditor must not convert a green
GitHub Actions suite into physical operational approval.

## Two different decisions — do not merge them

| Decision | Requirement | Evidence |
| --- | --- | --- |
| **v0.1 development/CI GO** | All 14 named GitHub Actions workflows must complete SUCCESS on **the exact same head SHA**. The verifier rejects missing, failed, pending and stale checks. | `ops/release/assess_ci.py` and `v01-release-evidence.yml` |
| **Production GO** | All measured, physical, operational and authorized CA/CAB gates below must independently pass. | **NOT RUN / NO-GO**: do not bypass with CI fixtures |

The earlier exact head `000b7e7fd1c593b8b3ba6f2173b85771c3184996`
completed **14/14** workflows, which is a software-only GO for
continued controlled development. The source changes that follow this
revision require fresh CI evidence; never recycle that historical
verdict for a new commit.

## Listener and security reality

- `control-center/GatewayListenerIsolation.cs` and the current
  `Program.cs` provide opt-in explicit **traffic IP 80/443** and
  separate **management IP admin/metrics ports**, with pinned
  client certificates, management source-CIDR allowlist and rejection
  of wildcard management binds.
- `GET /gateway/health/ready` is the existing data-plane readiness
  endpoint; it returns **503** unless at least one active destination
  is healthy. `GET /gateway/health` is liveness only.
- The production systemd template binds 80/443 with
  `CAP_NET_BIND_SERVICE`, not an assumed NAT/L4 port forward.
  `MaxConcurrentConnections` and `LimitNOFILE` have **no guessed
  universal values**: derive from *measured* peak concurrency.
- Production management certificate verification explicitly uses a
  custom trusted CA and pinned leaf but has
  `X509RevocationMode.NoCheck` in the current source. **Real PKI
  revocation/OCSP/CRL acceptance remains unverified. Do not use the
  synthetic CI CA run to approve it.**
- Real fleet config signatures use the signed protocol v2, but
  full two-node rollout atomicity, loss of a control plane, secure
  shared/backup DP key rings and physical failover are **not proven**.

## Observed site traffic: reported max 500 Mbps

**Units and measurement source must be verified**. If 500 megabits/s is
the real observed peak, the unchanged **50% headroom** body-byte gate
is **750 Mbps = 0.75 Gbps** for each *surviving* gateway operating
alone. The optional existing 30% choice would be 650 Mbps and must
be explicitly preapproved — it cannot replace an approved 50% gate.
If the user's figure is instead **500 MB/s**, the corresponding 50%
target is **6 Gbps**, not 750 Mbps.

Link nameplate: 10 GbE; the previously approved single-node feasibility
rule rejects any target above **90% of the measured link capacity**.
Wire/switch throughput is not identical to HTTP response-body Gbps.
Use actual response sizes, weighted routes, HTTP/HTTPS split,
peak RPS, new connections/s and concurrent client count.

The isolated GitHub-hosted
20-second canary (GitHub Actions run 43576670237)
at the older head recorded **1.006572 Gbps** of HTTP body throughput
via the real .NET 10 YARP, 2,400 HTTP 200 responses, zero transport/HTTP
errors and **2.051 ms p99** using **synthetic 1 MiB plain HTTP**.
It is **not** a physical-site, 60-minute, real-mix acceptance result.

The different GitHub-hosted
one-hour k6 soak (GitHub Actions run 43568270365)
recorded 34,010,745 requests, zero request failures and 32.29 ms
overall p99, **but 993,610 dropped low-priority log messages**.
Those dropped messages violate a zero-log-loss production operations
gate; its CI availability PASS does not authorize production.

## Mandatory evidence, unchanged thresholds

1. Source-linked switch/ISP graph proving units and direction, actual
   peak body Gbps and RPS, weighted response sizes, HTTPS share,
   concurrent clients, new connections/s, CPU/RAM/NIC models and
   speed, and the **precommitted** p99. **STOP** on any missing value.
2. Direct generator-to-backend baseline, matching-ALPN ECDSA TLS and
   keep-alive HAProxy reference, then individual NIC/OS tuning with
   recorded ethtool RSS/rings/queues/offloads, IRQ, rmem/wmem,
   netdev backlog, conntrack and packet-drop deltas. **STOP** on errors,
   drops, saturation or regressions.
3. Exploratory wrk/h2load to find maximum safe rates. Enforce
   `Kestrel.MaxConcurrentConnections >= ceil(1.5 * measured peak
   clients)` and `LimitNOFILE >= ceil(2.5 * actual Kestrel cap +
   4096)` from actual deployment values. **STOP** if unmet.
4. **Each separate physical gateway alone** must complete at least
   3,600 seconds and all 60 60-second windows with **body Gbps >=
   required peak * (1+headroom)**, **RPS >= measured peak RPS *
   (1+headroom)**, **zero HTTP/transport errors**, every p99
   **strictly below approved cap**, no NIC drops/GC/log loss and
   complete genuine telemetry. Never claim combined half-load on
   two nodes passes the solo-node requirement.
5. Two truly independent gateway hosts behind validated VRRP/ECMP,
   with the same trusted signed config revision. Prove graceful drain
   **zero failures**, SIGKILL with actual absolute fail counts and
   windows, physical host failure, VIP movement/ARP, split network,
   rolling replacement, config rollback, per-node DP keys/restore,
   safe CA signing and **no replay** of non-idempotent requests.
   Do not reuse the ~1.5-second Windows lab time as a physical SLA.
6. Real external TLS expiry probe, Prometheus exporter, Grafana
   dashboards and **delivered** notifications after injected backend
   faults, 5xx, p99, log loss and certificate expiry. Signed rotating
   leaf certificate proof and CA/PKI approval, controlled rollback,
   on-prem operators' change/CAB authorization.
7. Production GO only when ALL the above are independently verified
   and approved by an authorized human. Until then **NO-GO**.

## Architecture and policy

- v1 P0 #36:
  two independent gateway hosts and identical signed configs behind
  proven VRRP or ECMP, **no Redis requirement**.
- Redis/Sentinel is the separate post-v1 research
  #61.
- Single-tenant only; future SaaS multi-tenancy [#39] is P2.
- Follow `ops/automation/ONPREM_RUN_ORDER.md` and
  `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md`.
  All real hardware operations are **NOT RUN** here and nothing in
  GitHub Actions has permission to touch the private production network.

**Release status: SOFTWARE CI GO on its verified SHA; PRODUCTION NO-GO.**

## Neutral identity migration gate (not passed on site)

The application and service identifiers are now **GatewayCore**. This
changes the assembly binary name, cookie and ASP.NET Data Protection
application isolation, protected credential purposes and default
Windows/Linux state paths. Backed-up old ciphertext cannot simply
be copied to the new installation and assumed to decrypt. Existing
installations must be inventoried, backed up and migrated through
approved credential re-enrollment with fail-closed verification.
A new empty CI install **does not test upgrades from legacy state**.
Treat live state conversion and restoration as **NOT RUN**, and do not
deploy a replacement over an existing service without an approved
migration and rollback record.
