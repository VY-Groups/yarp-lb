# Feature coverage — GatewayCore YARP Control Center 0.1

Status definitions:
- **Browser-configurable**: an authenticated frontend action writes a *draft*, or updates a non-routing control; routing changes still require independent approval.
- **Inspect only**: live or saved state view, no remote mutation guarantee.
- **Design only**: captures topology preferences, does not provision infrastructure.
- **Integration pending**: required code/infrastructure acceptance not delivered in 0.1.

| Feature | Coverage in 0.1 | Limits / production action |
|---|---|---|
| Recovery Administrator, password login | Browser-configurable | Local account for controlled recovery; production identity review |
| Admin/Operator/Viewer and account disable | Browser-configurable | Role controls require Windows acceptance/pentest |
| SMTP/OTP, LDAPS and AD group roles | Browser-configurable | Needs relay/DC trust and integration tests; not FIDO2 SSO |
| Standalone/HA pair/fleet topology | Design only | HA VIP, controller election and remote agents not installed by wizard |
| Public application quick onboarding | Browser-configurable draft | Two backend HTTPS URLs, exact FQDN; no direct live traffic until approval |
| Host/path route matching, route IDs | Browser-configurable | Header/query/method match via advanced editor; security review required |
| HTTP transforms, forwarding settings | Browser-configurable advanced editor | Validated subset; custom middleware requires code and tests |
| Load-balancing policy | Browser-configurable | Policies per cluster, capacity/failure testing required |
| Active/passive destination health | Browser-configurable / inspect | Runtime health endpoint reflects YARP state; readiness contract external |
| Session affinity and HTTP forwarding | Advanced editor | Review cookie/secret persistence, gRPC/WebSockets and TLS |
| Backend enable/disable | Browser-configurable draft | No graceful connection drain; don't interrupt CA transactions |
| Routing change freeze | Browser-configurable | Local HTTP 423 enforcement, audit entry; not distributed lock |
| Two-person approvals, config backups | Browser-configurable | Local single-node store; separately test rollback/reconciliation |
| Per-destination request counters | Inspect only | Process-local metrics; restart resets counters |
| Authoritative YARP health values | Inspect only | Active/Passive Unknown/Healthy/Unhealthy; per gateway |
| Gateway fleet inventory/status | Partial / inspect | mTLS agent compatibility/integration not production qualified |
| Remote software provisioning | Integration pending | No arbitrary remote shell/service installer exposed to browser |
| Production OIDC / phishing-resistant MFA | Integration pending | Requires approved IdP enforcing FIDO2/smart-card |
| Independent immutable audit | Integration pending | Local JSONL is mutable; WORM export not connected |
| PostgreSQL-backed HA controller | Integration pending | Existing Pgpool/PostgreSQL application data tier remains untouched |
| OCSP/CRL/RA/HSM-specialized policies | Integration pending | Protocol and trust-boundary validation required |

The platform is **not** a replacement for Pgpool-II, PostgreSQL replication, a firewall/VIP, enterprise IdP, WORM archive or HSM.
