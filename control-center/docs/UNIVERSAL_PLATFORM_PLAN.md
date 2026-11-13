# Universal YARP delivery platform: architecture and product scope

## Product positioning

A vendor-neutral application-delivery/controller system with optional **industry profiles** (general, technology, e-commerce, healthcare, finance, government, telecom, education, CA/PKI). Profiles supply recommended controls and evidence requirements. **No industry profile may relax TLS, authentication, approval, revocation-status requirements or other controls by default.**

### Separate data plane, control plane and external integrations

```text
                    CLIENTS / INTERNET / INTERNAL USERS
                                    |
                         FIREWALL / WAF / DDoS
                                    |
                       optional GSLB / DNS / HA VIP
                                    |
                      +-------------+-------------+
                      |                           |
                   YARP-01                      YARP-02  (+N)
                     L7                           L7
                      +-------------+-------------+
                                    |
                      healthy applications / APIs
                                    |
                       optional DB/cache/queues

       MANAGEMENT ZONE: admin UI/API -> identity -> approvals
                               |         |        |
                      config revisions  audit   fleet agents
                               |                  |
                         controller DB       mTLS rollout

     Optional separate engines: L4 TCP/UDP | WAF/CRS | DNS/GSLB
```

YARP gateways must continue proxying approved configuration while the controller is unavailable. Do NOT place the controller or audit backend in the synchronous customer request path. YARP is L7; TCP/UDP and DNS/GSLB require dedicated engines/integrations.

## Service categories per industry

| Industry | Typical services | Special controls before activation |
| --- | --- | --- |
| General/technology | web apps, internal portals, APIs, gRPC | HTTPS trust, auth, readiness, deployment rollback |
| E-commerce | checkout/payment API | idempotency, retries, checkout session state, PCI boundaries |
| Finance | transaction APIs, customer portals | maker/checker, HSM/keys separation, strong audit and regulatory review |
| Healthcare | portals, data APIs | identity, privacy, access trace, PHI minimization |
| Government | citizen portals, restricted services | public/internal segmentation, approval and compliance evidence |
| Telecom | customer provisioning/API | long-lived sessions, latency and overload protection |
| Education | LMS, login, reporting | session, peak load, identity |
| CA/PKI | enrollment/eKYC, RA, issuance integration, OCSP/CRL | separate service zones; do not rewrite OCSP/CRL; HSM signing never delegated to proxy; do not blindly retry issuance |

Industry selection is NOT authorization policy enforcement in v0.1.

## Modules, status, acceptance

| Capability | Engine/control design | 0.1 status | Required production evidence |
| --- | --- | --- | --- |
| L7 HTTP routes, transforms, host/method matching | Native YARP | Config editor exists | routing unit and negative tests, canary tests |
| RoundRobin/LeastRequests/P2C/Random | Native YARP | Configurable | two-backend load and failover |
| Weighted random, source-IP hashing | Custom policies in source | C# compile/HTTP test pending | 80/20, sticky/rebalance under failure, SNAT identity |
| Health checks, destination runtime states | Native YARP | Configurable and readable | recovery, false positive, flap tolerance |
| Slow start, graceful draining | Controller + data-plane coordination | Not implemented | in-flight requests preserved until deadline, no-new-request evidence |
| HTTP timeouts, queue, affinity | YARP + ASP.NET middleware | Partial/configurable | load tests; distributed limit semantics documented |
| Prometheus process counters | Local exporter | Source implemented, runtime gate pending | `/gateway/metrics` local 200, remote 403, scrape test |
| OpenTelemetry traces + persistent metrics | OpenTelemetry SDK/Collector/TSDB | Not implemented | trace across proxy + backend, data retention, cardinality |
| HTTPS/mTLS cert lifecycle | Kestrel + Windows/PKI/ACME | Configurable externally, controller missing | renewal, revocation and rotation drills |
| Active-active fleet ingress | HA firewall/LB/VIP | External prerequisite | failure of either gateway, config drift checks |
| Central controller/PostgreSQL/HA | Controller + dedicated DB | Not implemented | election, backup/restore, fencing and failover |
| Remote provisioning/onboarding | Signed agent and privileged approval | Not implemented | authenticated enrollment, attestation, remote rollback |
| WAF / OWASP CRS, bot and DDoS | Dedicated WAF and upstream network | Not implemented | false-positive testing, saturation protection |
| L4 TCP/UDP | Dedicated L4 proxy engine | Not implemented | protocol state, connection/UDP idle behavior |
| Geo/GSLB/DNS/anycast | DNS provider + network/BGP | Not implemented | multi-region probes, DNS TTL/failback tests |
| OIDC/FIDO2, MFA and RBAC | Approved IdP + admin API | Local RBAC, AD/OTP only | identity provider rotation/revocation, phishing-resistant MFA |
| WORM/immutable audit | External retention-protected collector | Local JSONL only | independent integrity and retention challenge |
| GitOps/Terraform/Kubernetes | typed API + reconcilers | Not implemented | convergence, drift, no approval bypass |
| Multi-tenancy | per-tenant auth and DB boundaries | NOT implemented | deny every cross-tenant data/action at API, DB, cache and fleet |

## Production delivery sequence

0. **Verified existing gateway** — clean Windows build and runtime checks, organization settings, local auth and approvals.
1. **Measured L7** — mock+real backends, weighted and hash distribution, active/passive health, failover, timeouts, draining and slow-start acceptance.
2. **Observability** — local Prometheus scrape, OpenTelemetry Collector, metrics DB and Grafana, access-log privacy and sample rate.
3. **Secure listener and certificates** — production HTTPS, SNI, backend trust, permitted mTLS, expiry/revocation and credential rotation.
4. **Gateway fleet HA** — two live gateways, upstream health-aware load balancing, signed config revisions, drift reconciliation and distributed rollback.
5. **Control-plane security/persistence** — PostgreSQL HA store, robust OIDC/FIDO2, external immutable audit, DR tested.
6. **Optional plug-in engines** — L4, WAF, GSLB, Geo/anycast, IaC/GitOps/Terraform/K8s, selected per deployment need.
7. **Tenant isolation product** — separate architecture track, not just a dropdown; design/tests before a SaaS release.

Each gate requires executable tests, logs, failure drills, independent review, and a measured performance budget. No unsupported capability should appear as enabled just because an organization picked an industry profile.
