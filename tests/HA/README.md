# Two-gateway HA fault-injection lab

This is a **simulated, loopback-only**, three-YARP-instance test on one Windows or Ubuntu runner: two data-plane gateways and a health-aware ingress YARP instance in front. Both gateways route to two fake application backends. The test sends traffic, kills one gateway, verifies continuing 200 responses after health detection, restarts it, and then confirms all-down returns 503.

Neither controller nor Redis is involved in this model. It verifies *basic ingress survival*, **not** deployment-grade VRRP, cloud ingress, distributed stickiness, rate limits, cross-node config revisions, multi-host network partitions or atomic config rollout.

The test uses 18080/18083/19080 loopback HTTP ports and 18443/18444/19443 ephemeral TLS listeners. It does not bind publicly. Output is attached to GitHub Actions as `artifacts/ha/ha-results.json`.

## Continuous-load fault injection

The test also runs 24 concurrent request loops while gateway-1 is killed (1.5 seconds before and 6 seconds after). Evidence includes **all attempted calls**, exception/status failures, p95/p99 request duration, and the time of the **last observed failed request relative to the process kill**. It asserts that the final 1.5-second observation window is error-free and that the healthy gateway continues serving after failure.

This is not a true packet-level failover timer; no new request retries are assumed for non-idempotent work. Request errors immediately after death are retained, not hidden. Client retry/timeout policy is a separate application decision.
