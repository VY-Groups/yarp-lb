# Bounded proxy overload and passive failure hysteresis (development)

The Control Center's shipping `MapReverseProxy` endpoint now has a **process-local** concurrency limiter. It applies before reverse-proxy forwarding, with bounded FIFO waiting; rejected excess requests receive HTTP **429**, with **no retry/replay**. It is not a global or cross-node quota and does not protect the management API from its own independent load.

| Environment variable | Default | Allowed | Meaning |
|---|---:|---:|---|
| `GATEWAY_PROXY_CONCURRENCY` | 128 | 1–100000 | Maximum concurrently admitted proxy requests per process |
| `GATEWAY_PROXY_QUEUE_LIMIT` | 0 | 0–4096 | Maximum waiting requests; 0 rejects immediately |

Invalid values fail startup rather than silently disable the gate. Defaults are conservative test settings, **not production capacity sizing**. Long-lived upgraded connections, streaming, and request aborts must be included in concurrency measurement. Use realistic 500 Mbps site workloads and validate p99, 429 rate, NIC drops, and backend capacity. Use per-node 60-minute measurements before a physical production decision.

An optional **stick-table-style** fixed-window limiter tracks the actual TCP peer IP (not an untrusted forwarded header). Set `GATEWAY_PROXY_IP_RATE_PER_MINUTE` to 1–1000000 to enable; optionally set `GATEWAY_PROXY_IP_TABLE_CAPACITY` to 1–65536 (default 4096 when enabled). Entries have a one-minute fixed window and expire on subsequent access or when the hard-cap table needs space; at capacity new peers fail closed with HTTP 429. A NAT gateway shares its quota; this is a **process-local**, not HA-distributed quota. It does not implement HAProxy's full stick-table semantics, sliding-window tracking, bans, synchronization, or persistent counters. Changing controls requires a process restart. Test fairness and NAT behavior before enabling on real services.

The opt-in `BoundedTransportFailure` passive health policy now requires **2 consecutive destination transport failures** by default before bounded ejection. Optional cluster metadata `BoundedTransportFailure.ConsecutiveFailures` accepts integers 1–10. Successful forwarding resets the streak. The existing absolute ejection budget, mandatory survivor reserve and reactivation cooldown still apply. This is **not** a comprehensive HAProxy rise/fall active-probe implementation; actual post-recovery behavior must be validated with active checks and a real fault-injection workload.

Weighted random destination recovery uses existing `SlowStartSeconds` (0–600) and first observed eligibility; it is not an autonomous background probe scheduler. Source-IP hash remains exempt to avoid remapping. The observation logic now resets its ramp timer when a destination becomes eligible again after a previously observed unavailable/draining state. This is not asynchronous active-probe monitoring: if no request observes the unhealthy state, recovery can still retain an old ramp. Runtime recovery and fairness under load remain an open acceptance test.

For operator safety: do not change existing running Windows test configuration, sign-in identities, TLS or firewall. No on-prem deployment or live provider credentials are involved. Production remains **NO-GO**.


## Autonomous YARP health observation (proposed)

`AutonomousRecoveryObserver` runs once a second as an in-process background service, reading **YARP's configured active-health state** for each loaded destination, rather than sending duplicate HTTP probes. When an actively unhealthy destination later becomes healthy, `TrafficLifecycle` restarts its `WeightedRandom` ramp timer even if no customer traffic was received during the fault. The shared eligibility state is synchronized and pure transition checks are included in the load-balancing test project.

Boundaries: no new independent probe engine, no replacement for YARP's active check intervals/threshold semantics, no multi-node health consensus, no proof of physical VIP/host faults. An active health state of Unknown is not treated as a successful probe. This is not a HAProxy source-code port. A real HTTP acceptance scenario now injects backend failure and restores readiness with no customer proxy traffic for 3.2 seconds before measuring weighted warmup. CI success is required before treating that result as evidence; it remains different from multi-node physical failover.

The referenced GitHub repository `REA` was not available through the connected account search during this implementation. No assertions about its source, tests or licensing have been made.

## Passive-aware idle recovery safety (incremental fix)

The autonomous observer only starts or retains warmup eligibility when active health is `Healthy`, passive health is **not** `Unhealthy`, and the destination is not draining. An actively healthy but passively ejected destination is no longer incorrectly considered recovered. Unknown active health does not count as affirmative recovery evidence. This does not replace YARP's own availability policy or override destination health and does not implement distributed health consensus. Active and passive health compatibility is covered by dedicated contract tests and existing Windows/Linux gateway acceptance CI.

### Source comparison and limits

Read-only comparison reference: `ha-praxy/src/check.c` (health probes), `src/queue.c` (queue lifetime and locks), `src/stick_table.c` (tracked counters), and `src/peers.c` (peer synchronization). Those files are GPL-licensed C and **are not copied into the .NET app**. The existing peer rate table is per-process, not synchronized: it must not be presented as a HAProxy peer-equivalent. A fully correct distributed quota requires independently designed/authenticated peer transport, sequence/replay handling, convergence, storage bounds, partition behavior, and at least two independent failure-domain tests. Production physical throughput, NIC/VRRP/ECMP failover, and network-partition evidence remain NOT TESTED.
