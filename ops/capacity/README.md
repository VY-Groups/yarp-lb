# v0.1 on-prem capacity code (not physical acceptance)

These scripts reject absent measured traffic/hardware numbers, enforce **separate minimum body Gbps and RPS** in EACH complete minute, zero HTTP/transport errors, exact weighted response body bytes and p99 strictly below the approved ceiling. Gbps is HTTP *body*, not Ethernet wire Gbps. Each surviving gateway is tested **alone** for 60 minutes at the precommitted 30% or 50% headroom. 90% of single NIC rating is a feasibility cap; 10GbE *rated capacity* must not be substituted for observed peak load.

Full generator tooling for concurrent oha response profiles, real NIC collection, reference HAProxy template, and run order are in the downloadable v6 operator kit; their execution on physical hardware is NOT RUN.

Run fail-closed report: `python3 ops/capacity/report.py --scenario actual.json --results /real/raw --gateway-csv /real/metrics.csv --out /real/gate.json`.
Run actual connection limits: `python3 ops/capacity/limits.py --scenario actual.json --profile actual-systemd-and-kestrel.json --out limits.json`. This validates `MaxConcurrentConnections>=ceil(1.5*peak_concurrent_connections)`, and `LimitNOFILE>=ceil(2.5*ACTUAL_MaxConcurrentConnections+4096)`, not hardcoded 10,000/65,536.

Both require real, source-linked evidence. The template contains intentionally null input fields and cannot pass.