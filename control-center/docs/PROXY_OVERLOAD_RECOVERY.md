# Bounded proxy overload and passive failure hysteresis (development)

The Control Center's shipping `MapReverseProxy` endpoint now has a **process-local** concurrency limiter. It applies before reverse-proxy forwarding, with bounded FIFO waiting; rejected excess requests receive HTTP **429**, with **no retry/replay**. It is not a global or cross-node quota and does not protect the management API from its own independent load.

| Environment variable | Default | Allowed | Meaning |
|---|---:|---:|---|
| `GATEWAY_PROXY_CONCURRENCY` | 128 | 1–100000 | Maximum concurrently admitted proxy requests per process |
| `GATEWAY_PROXY_QUEUE_LIMIT` | 0 | 0–4096 | Maximum waiting requests; 0 rejects immediately |

Invalid values fail startup rather than silently disable the gate. Defaults are conservative test settings, **not production capacity sizing**. Long-lived upgraded connections, streaming, and request aborts must be included in concurrency measurement. Use realistic 500 Mbps site workloads and validate p99, 429 rate, NIC drops, and backend capacity. Use per-node 60-minute measurements before a physical production decision.

The opt-in `BoundedTransportFailure` passive health policy now requires **2 consecutive destination transport failures** by default before bounded ejection. Optional cluster metadata `BoundedTransportFailure.ConsecutiveFailures` accepts integers 1–10. Successful forwarding resets the streak. The existing absolute ejection budget, mandatory survivor reserve and reactivation cooldown still apply. This is **not** a comprehensive HAProxy rise/fall active-probe implementation; actual post-recovery behavior must be validated with active checks and a real fault-injection workload.

Weighted random destination recovery uses existing `SlowStartSeconds` (0–600) and first observed eligibility; it is not an autonomous background probe scheduler. Source-IP hash remains exempt to avoid remapping. The observation logic now resets its ramp timer when a destination becomes eligible again after a previously observed unavailable/draining state. This is not asynchronous active-probe monitoring: if no request observes the unhealthy state, recovery can still retain an old ramp. Runtime recovery and fairness under load remain an open acceptance test.

For operator safety: do not change existing running Windows test configuration, sign-in identities, TLS or firewall. No on-prem deployment or live provider credentials are involved. Production remains **NO-GO**.
