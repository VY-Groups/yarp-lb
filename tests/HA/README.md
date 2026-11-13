# Two-gateway HA fault-injection lab

This is a **simulated, loopback-only**, three-YARP-instance test on one Windows or Ubuntu runner: two data-plane gateways and a health-aware ingress YARP instance in front. Both gateways route to two fake application backends. The test sends traffic, kills one gateway, verifies continuing 200 responses after health detection, restarts it, and then confirms all-down returns 503.

Neither controller nor Redis is involved in this model. It verifies *basic ingress survival*, **not** deployment-grade VRRP, cloud ingress, distributed stickiness, rate limits, cross-node config revisions, multi-host network partitions or atomic config rollout.

The test uses 18080/18083/19080 loopback HTTP ports and 18443/18444/19443 ephemeral TLS listeners. It does not bind publicly. Output is attached to GitHub Actions as `artifacts/ha/ha-results.json`.

## Continuous-load fault injection

The test also runs 24 concurrent request loops while gateway-1 is killed (1.5 seconds before and 6 seconds after). Evidence includes **all attempted calls**, exception/status failures, p95/p99 request duration, and the time of the **last observed failed request relative to the process kill**. It asserts that the final 1.5-second observation window is error-free and that the healthy gateway continues serving after failure.

This is not a true packet-level failover timer; no new request retries are assumed for non-idempotent work. Request errors immediately after death are retained, not hidden. Client retry/timeout policy is a separate application decision.

## Passive health at ingress and graceful stop

The HA lab opts the **ingress cluster only** into a custom `ImmediateTransportFailure` passive health policy. It ejects a gateway on the first *YARP forwarding transport error*, not on ordinary application HTTP 500 responses. This is an intentionally aggressive lab threshold with a 30-second reactivation period, **not automatically safe production policy**. It uses YARP's built-in passive-health middleware and health updater, in parallel with the existing 1-second active probe. No retry middleware is present, so non-idempotent operations are never replayed.

The new graceful-maintenance scenario runs live traffic while:
1. gateway 1's `/lab/drain` switches its health probe from 200 to 503;
2. ingress is verified to route 25 consecutive requests exclusively through gateway 2;
3. gateway 1 calls `IHostApplicationLifetime.StopApplication` to gracefully drain Kestrel;
4. test clients continue and **must** observe zero failed HTTP requests.

The Windows test calls a loopback-only Kestrel host-stop endpoint, which exercises the same .NET shutdown lifecycle but is **not literally SIGTERM**; a separate Linux OS-signal test may be added. The zero-error objective is for **pre-drained maintenance**, not a raw SIGTERM with no readiness withdrawal.

For SIGKILL, the report now classifies requests by **completion time** so requests already in flight when the process dies count as failures after the fault. It reports failed-request count, first/last failure offset and observed window in milliseconds; it doesn't invent a health-detector timestamp.

Even with passive ejection, already-in-flight requests on the terminated gateway can fail. Do not retry signing, OCSP POST or other non-idempotent operations without explicit, auditable idempotency semantics.

## Exact Linux SIGTERM acceptance

Linux CI now sends **`/usr/bin/kill -TERM <dotnet-gateway-pid>`** to the real gateway process *after ingress has confirmed readiness withdrawal*. Windows CI retains the `IHostApplicationLifetime.StopApplication` path, which is not a literal SIGTERM. Both assert zero failed requests and preserve distinct shutdown-method labels in the evidence. A raw SIGTERM without readiness withdrawal is outside the zero-failure guarantee.
