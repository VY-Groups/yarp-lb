# Primary/backup HTTP destination selection (opt-in)

This GatewayCore policy is an **independent managed-code implementation** of a useful HAProxy routing pattern, informed by the HAProxy 3.4 configuration manual. No source code from HAProxy or `ha-praxy` is incorporated.

## What it does

Choose **Clusters → Load balancing → PrimaryBackup**, enable **Active health checks**, then set **Backends → Traffic role** for each destination. Existing clusters remain unchanged and use their original load balancing policies.

- `Metadata.TrafficRole` omitted or `primary`: candidate receives traffic while an available non-draining primary exists. Multiple primaries receive weighted random requests using the existing 1..100 `Weight` and bounded `SlowStartSeconds` logic.
- `Metadata.TrafficRole=backup`: selected **only if every primary is unavailable or draining**. To avoid nondeterministic changes when two backups exist, select the backup destination with the lowest ordinal destination ID. Other backups remain idle unless the earlier backup becomes unavailable, then the next eligible one is used.
- Active health **must** be enabled on the cluster to submit an approved PrimaryBackup configuration. Select an application-specific readiness path. Invalid roles and weights fail closed.
- When **both classes are unavailable**, YARP has no available destination and returns its normal failure response. No automatic POST replay, no stick-table/session state migration, no blind retry, no cross-node coordination or primary promotion.
- Draining explicitly removes a destination from new-request selection. Long-running streams are governed by the existing drain controls. Reactivation is governed by YARP health and configured rise/fall thresholds.

## Example configuration

```json
{
  "ReverseProxy": {
    "Clusters": {
      "critical-service": {
        "LoadBalancingPolicy": "PrimaryBackup",
        "HealthCheck": {
          "Active": {
            "Enabled": true,
            "Path": "/health/ready",
            "Interval": "00:00:02",
            "Timeout": "00:00:01"
          }
        },
        "Destinations": {
          "primary-a": {
            "Address": "https://primary-a.internal.example/",
            "Metadata": {"TrafficRole": "primary", "Weight": "80"}
          },
          "primary-b": {
            "Address": "https://primary-b.internal.example/",
            "Metadata": {"TrafficRole": "primary", "Weight": "20"}
          },
          "backup-a": {
            "Address": "https://backup-a.internal.example/",
            "Metadata": {"TrafficRole": "backup"}
          }
        }
      }
    }
  }
}
```

> Example hostnames are placeholders. The management editor creates drafts and requires an independent reviewer before applying changes. **Production HA is not proven by selecting this policy.** Do not use it for a stateful service until application and database recovery have been verified; upstream HA and backend replication are independent.

## Acceptance

The pure core checks the 80:20 weight band, invalid input rejection, lack of primaries, and default role behavior. The disposable real L7 HTTP lab starts two backends, verifies exclusive primary routing, takes the primary down, verifies exclusive backup routing, takes the backup down as well, verifies fail-closed behavior, then restores both and verifies the primary is preferred. This is not a production certificate, physical-host test, or a HAProxy native binary protocol.

Reference: [HAProxy 3.4 configuration manual](https://docs.haproxy.org/3.4/configuration.html), server `backup` selection rules and `rise`/`fall` active check settings.
