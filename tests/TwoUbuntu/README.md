# Two independent Ubuntu GitHub Actions runners — HTTP benchmark evidence

This workflow schedules **two separate GitHub-hosted Ubuntu 24.04 VMs** (`node-a` and `node-b`). On EACH VM, it builds the actual GatewayCore application image, starts two disposable API website origins and one gateway container, serves a unique temporary HTML page, then measures the gateway proxying exactly 1 MiB HTTP response bodies.

The default PR mode runs a short **15-second smoke** on each VM, gates correctness and zero errors, but does NOT gate throughput. The manually dispatched `sustained_60m` mode records and gates each of **60 complete one-minute windows** on **each** runner, with a 750 Mbps HTTP body floor and strict p99 below the supplied ceiling. If either host misses one minute, reports failures, cannot build, or lacks verifiable commit identity, its job fails. Raw evidence files identify VM hostnames and the exact commit. The aggregation gate rejects duplicate runner hostnames and missing/failed artifacts.

**These are two distinct cloud VMs, not two on-prem GatewayCore hosts.** The default matrix jobs do not route between runners: GitHub-hosted runners are isolated, so they do not share a VIP, ingress or health state. This workflow cannot prove active-active network failover. Cloud measurements use a synthetic 1 MiB HTTP response over Docker virtual networking, not the measured customer response-size/TLS mix, actual NIC drivers, LACP, real physical switches, packet drops or traffic generators outside the gateway host. Even a successful 60-minute cloud run is `CLOUD_SYNTHETIC_PASS_NOT_PHYSICAL_GO`, **never** an on-prem hardware acceptance.

For actual **two-host network failover**, configure separately reachable isolated nodes or an approved encrypted overlay, and execute `tests/HA` with a real ingress/VIP and traffic generators. The signed configuration, physical NIC and network-fault gates in `ops/capacity/EOD_500MBPS_RELEASE_PLAN.md` remain in force. Do not enable public inbound ports in GitHub-hosted runners.

Workflow: `.github/workflows/two-ubuntu-gateway-load.yml`.

The offline evidence test suite proves that forged reports (duplicate hostnames, wrong SHA, missing minutes, per-window throughput shortfall) fail closed. It does **not** manufacture throughput figures.
