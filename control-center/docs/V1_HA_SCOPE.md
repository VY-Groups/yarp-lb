# Scope of #36: version 1 on-prem HA, **no Redis**

Two independently hosted gateways behind a verified VRRP VIP or ECMP ingress.
Both instances must start with the same **signed, validated configuration
revision**; changes are staged, verified and committed on both nodes. Keep
control-plane writes frozen if consistency cannot be proven; never retry
non-idempotent CA POST/signing calls automatically. Do **not** ship Redis,
Sentinel or a Redis-backed distributed leader election as part of v1.
The Docker Redis prototype is a **separate investigation**, not a dependency
and not evidence of integrated shared state.

The existing strict two-second HA test in disposable CI **does not claim**
VRRP host failover. Keepalived with 1-second adverts and 2-second checks may
take several seconds (e.g., 3-6) depending on fall/rise/advert intervals,
kernel/network conditions and application. Record the actual wall-clock
absolute failed count and last failure offset on independent hosts. No
assumed 1.5-second physical benchmark. Production remains NO-GO.

## Binding caveat for VRRP
The current split-socket Control Center binds only configured IPs; the
BACKUP host cannot bind a nonlocal VIP without validated kernel
nonlocal-bind configuration and routing. A simpler v1 route may use ECMP
to explicit per-node data IPs. Choose the topology before deploying
keepalived; the check script requires a reachable **node-local** readiness
path and a separate non-root script identity. **VRRP is not yet integrated
or validated with these listeners**, and these templates are not a GO.
