# HAProxy loopback comparison baseline (test-only)

This is an **original minimal HAProxy configuration**, not copied HAProxy source. It provides a reproducible, independent HTTP/1.1 reference to compare the GatewayCore/YARP test installation against a single upstream. It does not prove equivalent functionality, capacity, TLS behavior, safety, or production readiness.

## Scope and boundaries

- HAProxy accepts **only** `127.0.0.1:19080`; backend is **only** `127.0.0.1:18081`.
- GatewayCore/YARP can serve the same origin via `127.0.0.1:8080/proxy/`.
- Both reference and GatewayCore remove the `/proxy/` prefix for this comparison.
- HAProxy includes HTTP active checks with `fall 3` / `rise 2`; these are **not proof of full feature parity** with GatewayCore's health/recovery lifecycle.
- Do not use this with real customer traffic, credentials, production listeners, publicly reachable interfaces, or sensitive directories. Never benchmark against `C:\` or an arbitrary current working directory.
- This example intentionally has no TLS. HTTPS capacity tests require a separate **matched ALPN, certificate and cipher** baseline; do not compare plaintext HAProxy throughput to HTTPS GatewayCore performance.

## Ubuntu disposable test lab

From repository root (with HAProxy, Python 3 and curl installed):

```sh
mkdir -p /tmp/gatewaycore-haproxy-origin
printf 'GatewayCore Backend Working\n' > /tmp/gatewaycore-haproxy-origin/index.html
python3 -m http.server 18081 --bind 127.0.0.1 --directory /tmp/gatewaycore-haproxy-origin &
origin_pid=$!
haproxy -c -f ops/capacity/haproxy-reference/haproxy.cfg
haproxy -db -f ops/capacity/haproxy-reference/haproxy.cfg &
haproxy_pid=$!
curl --fail-with-body http://127.0.0.1:19080/proxy/index.html
kill "$haproxy_pid" "$origin_pid"
```

Always verify the active server PID and listening port before stopping local processes. In unattended CI, a dedicated disposable runner is required.

## Fair comparison protocol

Run **one gateway at a time**, with the same backend content, protocol, request sequence, client count, connection reuse, response-body sizes, network limits and load-generator hosts. Collect HTTP body Gbps, RPS, p50/p95/p99, connection errors, proxy CPU/RAM, socket/NIC drops, and full failed-request counts. Repeat experiments to detect variance. Never use a local loopback rate as a 500 Mbps physical-network acceptance test. The project's existing `ops/capacity/report.py` remains the production evidence gate, requiring 60 measured minutes and 50% headroom (750 Mbps if observed peak is truly 500 Mbps).

## HAProxy-inspired feature gaps to review independently

| Capability | Existing GatewayCore evidence | Next acceptance requirement |
| --- | --- | --- |
| Active HTTP probes / passive health | YARP active checks and bounded transport-failure policy exist | Validate failure thresholds, all-down 503, real upstream recovery and false positives |
| Drain and slow start | Metadata controls with known limitations in `control-center/docs/L7_LIFECYCLE_OBSERVABILITY.md` | Prove in-flight drain deadline and recovery ramp under real mixed traffic |
| Stick tables / rate abuse controls | No equivalent HAProxy stick-table engine established | Define privacy-safe bounded keys, memory quotas, evictions, 429 and multi-node consistency |
| Connection/queue bounds | Partial runtime and deployment controls | Enforce queue/concurrency thresholds with saturation and overload tests |
| Runtime updates | YARP reload and management approval exist | Fail-closed, atomic rollout/rollback with two physical nodes |
| L4 PROXY protocol, TLS/HTTP3 | Separate L4 and ingress work exists | Independently verify trust boundaries, byte-level behavior and real network integrations |

References: https://www.haproxy.org/ , https://www.haproxy.com/documentation/ , https://github.com/haproxy/haproxy/blob/master/LICENSE

HAProxy is independently licensed under GPL; this project does **not** import HAProxy C source or claim proprietary ownership of that source. Consult legal counsel before code reuse or distribution decisions.
