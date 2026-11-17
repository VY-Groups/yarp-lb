# GatewayCore 99.9% availability target — provisional design case

## Commitment level

The project adopts **99.9% monthly availability as a planning objective** for
the protected GatewayCore HTTP endpoint. This is an operating target, not a
measured production SLO or warranty. It lets engineering proceed against a
specific budget while telemetry collects evidence to confirm or revise the
assumptions. Production remains NO-GO until the independent-host, load,
failover, security, and operator acceptance gates in
[`ONPREM_PRODUCTION_GO_GATES.md`](ONPREM_PRODUCTION_GO_GATES.md) pass.

The HTTP SLI is measured from independent external probes to the customer
service URL and separately for each probe region. A sample succeeds only when
DNS resolution, TCP connection, TLS validation, and
`/gateway/health/ready` all return HTTP 200 within the configured 2-second
probe deadline. Timeouts, DNS/TLS errors, non-200 responses, and missing probe
samples count as unavailable. Planned maintenance is included. Keep DNS
authority availability as a separate SLI; it is not interchangeable with HTTP
gateway availability. Production traffic request outcomes should be analyzed
alongside probes once privacy-safe, low-cardinality central telemetry is
deployed.

For a rolling 30-day window, 99.9% allows at most **43.2 minutes** of
unavailability (0.1% of 43,200 minutes). A 10-second probe cadence produces
259,200 samples per probe region; a 0.1% error budget is 259 failed samples,
approximately 43 minutes of wall-clock outage when failures are continuous.
Alerting uses multi-window burn rate so operators see fast budget consumption
before the rolling window is exhausted.

## Explicit reliability assumptions for engineering

This provisional model is a reason to build for 99.9%; its percentages are
assumptions and must not be presented as measured component availability.

| Element | Planning assumption |
| --- | ---: |
| Each gateway node, considered alone | 99.0% monthly availability |
| Two nodes | Independent failure domains and successful failover; no shared power, host, NIC, or rack failure |
| Shared critical paths (DNS/delegation and ingress/network) | 99.98% each |
| Common-cause outage allowance | No more than 10 minutes per rolling 30 days |
| Automatic failover allowance | At most six events per 30 days, each losing no more than 10 seconds |

Under independence, two 99.0% nodes yield a theoretical 99.99% parallel-node
availability. Multiplying by two 99.98% shared paths gives 99.9500%. Adding the
assumed 10 minutes of common-cause loss and one minute of failover loss yields
about **32.6 minutes unavailable / 99.9245%** in 30 days, leaving about
**10.6 minutes** of the 99.9% budget. This calculation is only a planning
model: correlated failures, DNS caching, failed failover, operator error,
capacity exhaustion, or a shared dependency below its assumption can consume
the margin. A single 99.9% shared dependency plus the other modeled losses is
not enough to retain the same margin.

Required design consequences:

- Two separately hosted gateways, each able to serve measured peak plus the
  approved headroom alone; use the issue #36-approved VRRP/ECMP topology.
- Independent public/recursive DNS paths and externally monitored service
  probes. A private EC2 pair or one Vercel route is not the same as independent
  authoritative DNS or a shared production VIP.
- Automatic failure detection, a measured bounded failover interval, and
  recovery without manually editing routing state.
- Alert on service availability, budget burn, backend readiness, DNS answer
  failures, certificate expiry, log loss, and missing telemetry; retain raw
  timestamps, probe region, status, latency, and sanitized failure category.
- Review incident data monthly. If any independence or component assumption
  is false, update the model and design; do not hide the incident as an
  exclusion.

## Monitoring contract

The Prometheus rules in `control-center/ops/prometheus/gateway-alerts.yml`
expect a separately deployed Blackbox Exporter job named
`gatewaycore-availability`, with one `probe_success` series per `service` and
`region` plus a matching `up` target series, sampled every 10 seconds against
the production HTTPS URL. A failed probe-target scrape is converted to a zero
sample and alerted. Keep
`service` and `region` labels bounded. Alert delivery must be tested from the
customer's Alertmanager to its real operator channel; promtool tests validate
rule behavior only. The monitoring endpoint must not be exposed through the
public gateway listener.

Evidence record per outage: incident ID, UTC start/end, affected region and
service, failed probe samples, user-visible request impact, alert delivery
time, node/backend state, DNS behavior, recovery action, and follow-up issue.
That record is the input for future development and for replacing the
assumption-based model with observed availability.
