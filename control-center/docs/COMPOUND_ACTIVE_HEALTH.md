# Active compound HTTP health monitoring

This opt-in configuration uses the native YARP active-health scheduler. It is
different from the on-demand management diagnostics API. Neither enables fleet
acceptance or changes the physical acceptance requirements.

## Configure a service group

Use **Backend groups → Health monitor** in the Control Center. Choose off, AND or OR under Active compound mode; enter the distinct secondary readiness path. The guided editor selects HealthyAndUnknown for compound mode, rejects incompatible backends, and propagates compound settings across linked groups in the draft. Unlink a group to edit its monitor independently. Advanced cluster JSON is also available. Preserve existing destinations,
load-balancing policy, passive checks and unrelated metadata. Add the following
properties to the appropriate existing objects:

```json
{
  "HealthCheck": {
    "AvailableDestinationsPolicy": "HealthyAndUnknown",
    "Active": {
      "Enabled": true,
      "Interval": "00:00:15",
      "Timeout": "00:00:05",
      "Policy": "RiseFall",
      "Path": "/health/ready"
    }
  },
  "Metadata": {
    "ADC.Health.CompoundMode": "AND",
    "ADC.Health.SecondaryPath": "/health/dependencies",
    "RiseFall.Rise": "2",
    "RiseFall.Fall": "3"
  }
}
```

Both readiness paths must be distinct, bounded same-origin HTTP paths.
TCP connectivity is mandatory; AND additionally requires both HTTP checks
to succeed; OR requires at least one. TCP alone never establishes readiness.
Do not use a cluster web proxy or alternate destination Health address.
Preserve the existing backend TLS verification and client certificate settings.
The current feature uses no additional requests on ordinary customer traffic.

Submit the entire draft with a justification. A different administrator reviews
and approves it. For a shared monitor, the guided source editor updates matching metadata for every linked group in the draft. Advanced JSON edits require matching metadata for all linked groups.

## Verify

- Inspect runtime destination health and send a disposable test request.
- In a lab, fail the secondary readiness endpoint with AND configured: affected
  destinations must stop receiving new requests. Fail both origins: expect 503.
- With OR, one passing HTTP readiness endpoint and a successful TCP connection
  are sufficient; failure of both HTTP endpoints removes that origin.
- Restore readiness and wait for native health recovery before sending traffic.
- A changed cluster or destination generation needs fresh compound evidence.
  Missing, failed or expired evidence denies new traffic. A completed failed
  compound probe denies eligibility immediately, even with fall hysteresis.

## Rollback and troubleshooting

If configuration is rejected, inspect the review response for unsupported mode,
duplicate paths, alternate health origin, proxy settings or health policy.
If all traffic is refused, verify the backend port, HTTP status codes, TLS trust,
client certificate, configured readiness endpoints and runtime health. Do not
use panic routing or disable certificate validation to bypass failed probes.
Remove both compound metadata keys together in a reviewed draft (including
linked groups) or restore the known-good configuration using the existing
authorized rollback workflow. Verify native health and application traffic.

This guide is an operator procedure, not proof of a successful execution.
Exact-head Windows/Linux CI, independent review and physical testing remain
required.
