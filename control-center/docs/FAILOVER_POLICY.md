# Conservative YARP ingress failover policy (0.1 Development)

This feature registers an **opt-in** YARP passive health policy named
`BoundedTransportFailure` on the real Control Center gateway and GatewayLab.
It **never** automatically replays/retries a forwarded HTTP request. The
automatic retry budget is **zero**, including GET/HEAD and all POST, signing,
RA, enrollment and approval operations. This is a deliberately safe bound, not
a claim that safe-idempotent retry support has been implemented.

## Configuration (example only)

```json
{
  "HealthCheck": {
    "AvailableDestinationsPolicy": "HealthyAndUnknown",
    "Active": {
      "Enabled": true,
      "Policy": "ConsecutiveFailures",
      "Path": "/health/ready",
      "Interval": "00:00:00.500",
      "Timeout": "00:00:00.500"
    },
    "Passive": {
      "Enabled": true,
      "Policy": "BoundedTransportFailure",
      "ReactivationPeriod": "00:00:15"
    }
  },
  "Metadata": {
    "BoundedTransportFailure.MaxEjectedPercent": "50",
    "BoundedTransportFailure.MinHealthyRemaining": "1",
    "ConsecutiveFailuresHealthPolicy.Threshold": "1"
  }
}
```

Active probes and the asynchronous passive health updater remain independent.
Transport failures can reserve a per-cluster ejection slot until cooldown, but
ordinary HTTP application 5xx and client-initiated cancellations cannot.
The policy reserves slots under a short lock, then calls the YARP updater
**outside** that lock, avoiding work under request-path contention.

With two gateways, 50% and minimum remaining one permit one simultaneous
passive ejection. This is not an absolute active-health survivor guarantee:
YARP may independently mark every destination down. The default
`HealthyAndUnknown` then fails closed with HTTP 503.

YARP's built-in `HealthyOrPanic` is available only on **explicit configuration**:
on an all-down condition it can send requests to nodes known unhealthy, which
may yield 502 and duplicate *business* attempts if callers independently
retry. Never select that mode for CA/RA/eSign signing or other high-integrity
operations without risk approval. The HA CI lab starts a fresh isolated ingress for each all-down policy to avoid treating an unverified live policy reload as proven. It validates the different failure results (503 fail-closed versus 502/504 explicit panic).

## Evidence and deployment gates

The disposable HA lab tests a real process kill, bounded two-gateway
health convergence, Windows/Ubuntu end-user last-failure offset <=2 seconds,
zero-failure pre-drained graceful stop, all-down fail-closed mode, explicit
panic mode, and transaction side-effect counts showing no automatic POST replay.
The failure window is measured at **HTTP completion**, not inferred from a
health-check timestamp.

The same tests do **not** prove cross-host network partitions, WAN latency,
long-lived WebSocket/gRPC behavior, 500/1000-VU scale, end-to-end production
latency, or firewall blackhole timing. Keep these explicitly unverified in
release/capability evidence. Avoid changing defaults on customer systems.
