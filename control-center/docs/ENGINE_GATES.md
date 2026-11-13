# Independently verified engine capability gates (0.1 Development)

The capabilities API reports the **status of source and isolated CI evidence**, not a live deployment assertion. An engine labeled `external-lab-verified` is neither installed automatically nor enabled by the Control Center UI. This product is single-organization, not a SaaS multi-tenant controller.

| Engine | Evidence | What does not exist yet |
|---|---|---|
| L7 YARP data plane | Windows Server 2022 + Ubuntu 24.04 real HTTP, failover, draining, weighted/hash distribution and TLS tests | Production throughput/SLO, long-lived connection drain guarantees |
| Standalone L4 engine | `.github/workflows/l4-acceptance.yml` real TCP and UDP socket tests on both OSes | Operational config APIs/approval, health probes, DDoS, scale, distributed UDP sessions, TLS/SNI |
| Standalone DNS/GSLB engine | `.github/workflows/gslb-acceptance.yml` real DNS A responses, weighted health routing and fail-closed all-down on both OSes | Authoritative production DNS TCP/AAAA/DNSSEC, regional monitoring, provider integration, delegation |
| External WAF (OWASP CRS) | `.github/workflows/waf-crs-acceptance.yml` real nginx/ModSecurity container; HTTP benign 200 and XSS 403 | Signed rule updates, application tuning, false-positive rate, production TLS, central audit and DDoS |
| HA ingress demo | `.github/workflows/l7-acceptance.yml` runs 2 gateways + ingress on one runner, SIGTERM/graceful/kill | Redundant ingress/VIP, real host partitions, Redis and atomic fleet rollouts |
| TLS/mTLS | Control-plane build and outbound certificate validation contracts; ephemeral HTTPS lab | ACME, managed backend cert rotation, enterprise trust drills |
| Identity/GitOps/multi-tenancy | Local RBAC and approval APIs only | OIDC/FIDO2/SSO, immutable audit, Terraform/K8s, tenant partition and isolation tests |

**Not implemented:** Anycast/BGP, cloud DNS provider integration, ACME renewal, Redis distributed rate-limit/session coordination, multi-host HA, WAF production policy management, gateway fleet reconciliation, OpenTelemetry tracing, GitOps/Terraform/Kubernetes, and true tenant isolation. The code must not enable production switches for these features.

Independent engine binaries are installed, rolled back and monitored separately until authenticated controller agents, signed configuration schemas, staged distribution and operator runbooks are built and verified.

**No live infrastructure is provisioned.** CI uses disposable hosted runners with loopback services and Docker containers. A CI green check is development evidence, not an SLA.
