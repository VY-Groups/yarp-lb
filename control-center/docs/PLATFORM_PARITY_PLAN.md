# GatewayCore YARP Control Center — complete load-balancer platform plan

## Product boundary

**Goal:** browser-driven control plane with independently protected identity, audit, policy, and rollout. Keep the data plane operational without the controller; do not put administrative APIs in the public traffic path. Single, HA pair and fleet topologies remain supported as a design, with fleet enrollment requiring real certificate and host configuration.

**Data plane:** 2+ independent YARP/Kestrel nodes for HTTP/HTTPS; one separate L4 engine for TCP/UDP if required; WAF/DoS layer in front as needed. **Control plane:** API, PostgreSQL 16 state store (dedicated schema/database, roles, migration/HA and recovery tested), AD/OIDC identity integration, immutable audit sink, orchestration agents. **Edge:** firewall/LB/VIP and GSLB DNS provider. **Observability:** OpenTelemetry collector + Prometheus-compatible TSDB + Grafana, separate ACL and retention. Existing CA PostgreSQL/Pgpool traffic topology is not altered by HTTP balancing.

## Feature disposition and acceptance criteria

| Requirement | Delivery strategy | Code status in 0.1 | Minimum acceptance test |
|---|---|---|---|
| Round Robin, Least Requests, P2C, Random, first-preferred | Built-in YARP | Available through cluster editor | 2-backend distribution and failure drill |
| Weighted selection | Custom `ILoadBalancingPolicy` | Implemented in source, Windows verification pending | 80/20 traffic distribution with confidence band and no unhealthy destinations |
| Source IP hash / consistent membership | Weighted rendezvous over trusted peer IP | Implemented in source, Windows verification pending | Same client stays mapped; adding a node remaps only a fraction; SNAT verification |
| Least response time | Custom feedback/EWMA algorithm | Not implemented | Concurrent request stress, outlier damping, no feedback loops |
| L4 TCP/UDP | Dedicated load balancer (not a YARP route) | Not implemented | End-to-end proxy, idle timeout, TLS pass-through, UDP state and failover |
| TLS termination, SNI, backend mTLS | Kestrel cert store, policy-bound endpoint config | Requires integration | SAN/chain validation, renewal, backend client cert, revocation, SNI tests |
| Automatic cert renewal | ACME client or enterprise CA enrollment; offline renewal process | Not implemented | Renewal while active, rollback, alert 30/14/7 days before expiry |
| HTTP 1/2/3, gRPC, WebSocket | Kestrel/YARP protocol configuration | Supported by stack, tests pending | Protocol negotiation, streaming, large upload, reconnect/failure test |
| Cookie/header affinity | Built-in YARP | Config editor available | Two gateways share Data Protection keys for encrypted affinity |
| IP affinity | Custom policy | Source code implemented, SNAT-sensitive | Verified identity source; no bare forwarded-header trust |
| Active/passive health | Built-in YARP | UI/API configuration exists | Recovery + failure and readiness semantics for each service |
| Slow start / connection drain | Custom drain controller + graceful shutdown | Not implemented | Rolling restart and long-running request handling |
| Rate limiting, queuing, timeouts | ASP.NET Core and policy adapters; shared counters if distributed | Partial local middleware | 429 behavior, fairness, queue overflow and two-node coordination |
| Circuit breaker, retry | Bounded, idempotent-only proxy middleware | Not implemented | Exactly-once/at-least-once risk analysis; block unsafe replay |
| ACL path/host/header/method, rewrites | Native YARP match/transforms | Existing advanced editor | Positive/negative matched route tests, header spoofing checks |
| IP ACL / Geo | Trusted peer IP + commercial/offline Geo-IP DB | Not implemented | Fail-closed match validation, DB version/accuracy and privacy review |
| GSLB authoritative DNS/Route53/Cloudflare | External health-aware provider integration, not YARP | Not implemented | Multi-region probing, healthy DNS failover, TTL behavior and recovery |
| Anycast | BGP/ISP infrastructure | Network design, not software switch | Route withdrawals, health, regional failover test |
| HA ingress | Existing firewall/LB health-aware distribution to all gateways | External prerequisite | Kill one YARP process; other remains reachable |
| Config reload | Native YARP config updates | Existing local file-based reload | Policy validation and no invalid config apply; request continuity |
| Shared Redis | Optional distributed counters/affinity design | Not integrated | Shared state with Redis failover, no global bypass |
| WAF/OWASP CRS | Approved WAF / Coraza / ModSecurity, not bare YARP | Not implemented | CRS tuning, false positive tests, protocol compatibility |
| DDoS/bot | Upstream network provider / WAF product | Not implemented | Volume protection, upstream saturation and recovery |
| OAuth/JWT | ASP.NET Core auth with per-route policy | Needs IdP and policy integration | JWT issuers/audience/signature/rotation tests; denial cases |
| RBAC/audit/approvals | Existing console | Partial local implementation | Distinct approvers, CSRF, disabled user, revocation and audit evidence |
| Prometheus/OpenTelemetry/Grafana | Collector/exporters + central storage | Process/local counters; exporter not integrated | Trace and metrics end-to-end under load, cardinality/privacy bounds |
| Admin UI / dynamic API | Existing console routes and YAML-free editor | Implemented locally | Audit every change; submit/approve/reject/restore tests |
| GitOps/Terraform/K8s | Declarative typed API, reconciliation controllers and provider SDKs | Not implemented | Drift detection, changes idempotent and policy approved |
| Canary/blue-green | Weighted destinations, deployment revisions, readiness gates | Basic weighting new; no full deployment workflow | 5/25/100% ramp with stop/rollback health gates |
| Multi-tenant | Tenant-scoped DB, RBAC and fleet segmentation | Not implemented | Cross-tenant access tests at every endpoint and data join |

## GatewayCore CA trust boundaries

1. Public GatewayCore sites, partner APIs and eKYC frontends are distinct from RA approval/SSCA admin zones and from private CA/HSM signing paths.
2. OCSP GET/POST and CRL publication require dedicated public URL, binary request, cache, freshness, and availability validation. Do not put JWT on public OCSP requests.
3. PostgreSQL 16 and Pgpool-II are a separate consistency/failover plane. HTTP Active–Active does not make databases multi-writer.
4. For signing/approval/settlement requests, never auto-replay non-idempotent requests without a proven idempotency token and state machine.
5. HA claims require testing failure of API-01, API-02, YARP-01, YARP-02, VIP/firewall, Pgpool/DB primary, mail, IdP, and control-plane storage independently.

## Pre-production milestones

**A — API L7 engine:** review standard/native settings, custom weighted policy verified on Windows, actual health/latency tests, workload separation.

**B — Control-plane persistence and security:** dedicated PostgreSQL 16 control store with migrations, encrypted secret storage, enterprise OIDC/FIDO2 or CA-approved equivalent, auditable two-person approvals, externally retained immutable logs, service identities.

**C — Fleet/data-plane separation:** signed enrollment bundles and mTLS identities, config drift detection and reconciler, staged/validated activation with health gates and automatic rollback in the controller; safe maintenance/drain actions.

**D — Protocol/edge integrations:** WAF, DDoS, global DNS routing, certificate lifecycle, L4 engine only if demanded by service inventory.

**E — Production CA acceptance:** threat model, dependency scanning, SAST/DAST, PKI workflow protocol validation, tabletop and live HA drills, security team and change advisory approval.

No production milestone should be marked **completed** until an artifact, test output, and accountable reviewer are attached to it.
