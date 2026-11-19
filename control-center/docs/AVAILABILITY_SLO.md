# GatewayCore 99.9% availability target — provisional design case

## Commitment level

The project adopts **99.9% availability over a rolling 365-day year as a planning objective** for
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

For a rolling 365-day window, 99.9% allows at most **8 hours, 45 minutes,
36 seconds** of unavailability (0.1% of 31,536,000 seconds). A 10-second
probe cadence produces 3,153,600 samples per probe region; the error budget
is 3,154 failed samples, approximately 8 hours and 46 minutes of continuous
outage. Alerting uses short burn-rate windows to detect a fast outage and a
full 365-day window to calculate the annual SLI. Keep at least 13 months of
probe history in the production TSDB; before a full year of samples exists,
the annual SLI is **unknown**, not a pass.

## Explicit reliability assumptions for engineering

This provisional model is a reason to build for 99.9%; its percentages are
assumptions and must not be presented as measured component availability.

| Element | Planning assumption |
| --- | ---: |
| Each gateway node, considered alone | 99.0% annual availability |
| Two nodes | Independent failure domains and successful failover; no shared power, host, NIC, or rack failure |
| Shared critical paths (DNS/delegation and ingress/network) | 99.98% annual availability each |
| Common-cause outage allowance | No more than 10 minutes per rolling year |
| Automatic failover allowance | At most six events per month, each losing no more than 10 seconds |

Under independence, two 99.0% nodes yield a theoretical 99.99% parallel-node
availability. Multiplying by two 99.98% shared paths gives 99.9500%. Adding the
assumed 10 minutes of common-cause loss and 12 minutes of failover loss (72
events per year) yields about **4.75 hours unavailable / 99.9458%** in a year,
leaving about **4.01 hours** of the 99.9% budget. This calculation is only a planning
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
sample and alerted. The annual SLI and sample-coverage alerts need 365-day
retention; the 5-minute/6-hour burn alerts work before a year of history is
available. Keep
`service` and `region` labels bounded. Alert delivery must be tested from the
customer's Alertmanager to its real operator channel; promtool tests validate
rule behavior only. The monitoring endpoint must not be exposed through the
public gateway listener.

`GatewayFailoverRecoveryExceeded` is a short-window warning that a successful
external probe has not returned for more than the 10-second planning budget.
Its dedicated rule group evaluates every five seconds, while the external
probe is expected every ten seconds. Actual notification delay also includes
probe timeout, scrape timing, rule evaluation and Alertmanager delivery. It
reports sampled user-visible unavailability; it cannot attribute the event to
a particular gateway or prove that automatic failover was attempted. The
Grafana interruption panel estimates failed seconds in the rolling hour as
failed probe samples multiplied by the configured 10-second cadence, so gaps
shorter than that cadence can be undercounted. Neither measure is a substitute
for a controlled, timestamped failover drill.

Evidence record per outage: incident ID, UTC start/end, affected region and
service, failed probe samples, user-visible request impact, alert delivery
time, node/backend state, DNS behavior, recovery action, and follow-up issue.
That record is the input for future development and for replacing the
assumption-based model with observed availability.
