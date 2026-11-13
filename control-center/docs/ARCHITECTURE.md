# SpeedSign HA design specification

## Modes

| Mode | YARP data plane | Controller (future) | Frontend ingress | State store recommendation |
|---|---|---|---|---|
| Standalone | one gateway, multiple backends | combined local | DNAT or internal DNS | local file acceptable for lab |
| HA pair | two equal active gateways, each routes to both backends | dedicated single or HA controller | health-aware VIP/load-balancer | dedicated PostgreSQL for control plane |
| Fleet | 3+ independent active gateway instances | HA controller and enrolled agents | VIPs/service discovery per network zone | dedicated PostgreSQL + durable audit |

**No master/slave YARP traffic roles.** `leader/standby` applies only to a *future controller*, never to incoming HTTP request distribution. Both APP-01 and APP-02 must be capable of handling requests safely. Multi-gateway HA requires an upstream health-aware routing mechanism.

## Certificate Authority boundaries

- Segregate public website/partner APIs, eKYC, restricted RA/SSCA, internal management, and OCSP/CRL (PKI trust-status) traffic.
- Keep HSM/private-key operations and CCA/CA approvals behind authorization and network boundaries.
- A matching YARP route is not a network access control policy.
- Existing PostgreSQL 16/Pgpool-II remain owned by the application stack, not YARP. An eventual management database must use distinct roles, schema, credentials and retention policies.
- No arbitrary remote command execution, remote service install, or secret provisioning during onboarding.

## Backend API design and persistence

`GET /admin/api/onboarding`: authenticated read; includes revision and blocking issues.

`POST /admin/api/onboarding/validate`: Administrator + CSRF; performs validation without writes.

`POST /admin/api/onboarding`: Administrator + CSRF; accepts `expectedRevision`, `plan`, `confirmDesign` flag. Persists topology metadata to ProgramData, creates backups, audit entry. Strict confirmation checks are broader than draft checks. Revision mismatch returns HTTP 409.

Status is `not-started`, `draft`, or `design-confirmed`. **There is deliberately no `deployed` status** in the 0.1 development baseline.

The API never touches YARP routes (`appsettings.json`), firewall, certificate keys, Pgpool, PostgreSQL or Windows services.
