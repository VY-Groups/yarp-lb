# On-prem production release gate (single tenant)

First deployment is single-tenant, on-prem. Issue #36 remains P0; future SaaS tenant isolation #39 remains P2. Issue #40's harness-only starvation fix is already merged, and its original strict 1.5-second upstream activity timeout and 2-second gateway kill window must not be relaxed.

## Actual CI evidence, 2026-11-14

- Revision: https://github.com/VY-Groups/yarp-lb/commit/bc0bd60440e0702dd7549c70b80f9961e559ddf4
- Complete Windows 2022 and Ubuntu 24.04 Control Center source checks SUCCESS: https://github.com/VY-Groups/yarp-lb/actions/runs/43554184563 . Ubuntu real production-mode startup with RSA X509 key wrapping, encrypted persisted Data Protection keys, permission and password negative cases, old-certificate overlap and loopback Gen2/log-drop metrics PASS in that runner. No on-prem service was tested.
- Windows HA matrix SUCCESS, 10/10 independent CI jobs: https://github.com/VY-Groups/yarp-lb/actions/runs/43553809750 . Worst logged last observed failed response after abrupt kill was 1538.0 ms (trial 7); worst failed request count was 26. Abrupt-kill CI allows short bounded 502/504 failures; this does NOT satisfy the separate zero-error load gate.
- Windows/Ubuntu L7, HA, performance profiling and short 75-client k6 SUCCESS: https://github.com/VY-Groups/yarp-lb/actions/runs/43554184556 . This is NOT a 60-minute multi-host capacity test.

## Mandatory gates — nothing can be skipped

| Gate | Release criterion | Current |
| --- | --- | --- |
| Source/build/security | Build exact deployed commit, encrypted Linux DP secrets, cross-restart and rotation decryption | CI PASS; on-prem NOT RUN |
| Capacity | Each surviving gateway alone: >= peak x 1.30 or x 1.50 for >= 3600s; every 60s window meets target; 0 HTTP/transport errors; every p99 strictly below precommitted cap; real GC/RAM/CPU/NIC evidence | NOT RUN |
| #36 P0 independent HA | >=2 independent ingress hosts plus >=2 YARP hosts; VIP/ECMP ejection, SIGTERM with 0 failed requests, SIGKILL, blackhole and partition scenarios, rolling upgrade, safe fail-closed CA signing | NOT RUN |
| Redis/shared state | TLS + ACL HA, coherent revision/lease semantics, split-brain-safe behavior, non-idempotent transaction no-replay, Redis outage does not block ordinary traffic | NOT IMPLEMENTED / NOT RUN |
| Monitoring | Real loopback /gateway/metrics scrape, active destination, 5xx, p99, external cert probe under 14 days, log drops, alert delivery and dashboard | Source counters CI PASS; live operations NOT RUN |
| Control and trust | DP key backup/restore, trusted TLS hostname/SNI, restricted management, proper OCSP/CRL, CAB/CA authorization, real rollback and recovery | NOT RUN |

Release answer is NO-GO while any mandatory gate is unknown, failed, skipped or not independently reviewed. Never claim a production GO from CI, a generated script, or synthetic data.

## Source-specific caveats

The shipping application exports yarp_control_http_requests_total, yarp_control_http_responses_total (status_class), yarp_control_http_duration_seconds_bucket, yarp_control_destination_active_health, yarp_control_gc_collections_total and yarp_logging_dropped_total. External monitoring must NOT assume nonexistent gateway_* series. /gateway/metrics accepts only loopback clients; use a local collector with authenticated central forwarding. /gateway/health is process liveness; there is no /gateway/health/ready and ingress should require a real proxied backend readiness probe.

Linux production requires YARP_CONTROL_PLANE_DIR, YARP_RUNTIME_CONFIG_PATH, YARP_LINUX_DP_CERT_PFX_PATH and YARP_LINUX_DP_CERT_PASSWORD_FILE pointing at private directories and regular files. The current shipping Linux implementation enforces 0700 state/key directories and 0600 PFX/password files. Do not copy a conflicting generic systemd secret recipe or alter Windows DPAPI defaults.

No deployment steps execute automatically from this document.