# Opt-in active health rise/fall hysteresis

GatewayCore supports `HealthCheck.Active.Policy = "RiseFall"` as an independent YARP `IActiveHealthCheckPolicy`. It uses YARP's own periodic active probes (no duplicate scheduler, request replay or HAProxy source import). It maintains bounded consecutive successes/failures per destination state:

- `Metadata.RiseFall.Rise` = 2 by default, validated 1–10: consecutive successful probes needed to mark healthy after startup, policy change or an outage.
- `Metadata.RiseFall.Fall` = 3 by default, validated 1–10: consecutive failed probes needed to mark unhealthy once healthy.
- Mixed success/failure resets the opposite streak. New/updated thresholds fail closed until the rise requirement is met. Invalid metadata is rejected by the reviewed change API; a malformed runtime cluster is marked unhealthy.
- Existing clusters on YARP `ConsecutiveFailures` retain the original behavior; this is opt-in.

Example cluster:
```json
{
  "HealthCheck": {
    "Active": {
      "Enabled": true,
      "Interval": "00:00:01",
      "Timeout": "00:00:01",
      "Path": "/health/ready",
      "Policy": "RiseFall"
    },
    "AvailableDestinationsPolicy": "HealthyAndUnknown"
  },
  "Metadata": {"RiseFall.Rise":"2","RiseFall.Fall":"3"}
}
```

For explicit fail-closed all-down semantics, use `HealthyAndUnknown` or a site-approved more restrictive policy, not YARP's panic fallback. All bootstrap states must be evaluated against that choice.

Software acceptance: deterministic probe-sequence tests cover success/failure thresholds, streak reset, config changes and invalid values. Real isolated L7 tests check actual HTTP backend failover and recovery using the new policy. Pass only when CI on exact head commit is green.

Remaining limits: process-local destination health, not VRRP/BGP; no persistent cluster consensus, physical network partition certification, immutable external audit, or field/500 Mbps sustained capacity acceptance. This does not copy or claim ownership of HAProxy GPL source.

References: https://www.haproxy.org/ and https://learn.microsoft.com/en-us/aspnet/core/fundamentals/servers/yarp/dests-health-checks
