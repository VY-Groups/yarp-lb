# GatewayLab OTLP overhead diagnostic

This opt-in diagnostic compares the same GatewayLab YARP pipeline with OTLP
disabled and enabled. Each gateway forwards through YARP to two separate local
BackendLab processes. Six samples run as three alternating off/on pairs, with
10,000 measured requests, 500 warm-up requests and 16 persistent HTTP/1.1
connections per sample. Response bodies are read before latency is recorded.

The enabled mode uses the production `GatewayOpenTelemetry` configuration and
proxy middleware, including the default 5% trace sampling ratio, ASP.NET Core
instrumentation, proxy metrics and structured `GatewayCore.AccessLog` records.
The diagnostic binds a disposable loopback HTTP receiver. It records received
trace, metric and log batch counts and bytes. An explicit local flush and
collector drain happen after each timed request window and are excluded from
the reported request timing.

The GitHub Actions workflow runs on Windows Server 2022 and Ubuntu 24.04 and
uploads the full JSON report and gateway logs. Compare individual paired results
and the runner metadata, not only the median. These short loopback measurements
help distinguish middleware-only behavior from a real YARP-to-backend path; they
do not establish a production capacity target, a site-specific overhead figure,
or availability/SLO evidence. Use representative backend latency, connection
reuse, TLS, traffic shape and host capacity before making deployment decisions.

To avoid altering existing L7 acceptance runs, GatewayLab only adds this
telemetry and access-log middleware when `YARP_LAB_OTEL_OVERHEAD=1` is set.

## Preliminary local measurements

On a Windows 11 laptop run, the three paired deltas were throughput `+1.476%`,
`-1.671%`, `-2.287%` and p95 latency `+1.340%`, `+0.254%`, `+1.528%`.
Their medians were `-1.671%` throughput and `+1.340%` p95. A WSL2 Ubuntu 24.04
run produced throughput deltas `+16.000%`, `-3.513%`, `+6.949%` and p95 deltas
`-15.784%`, `+2.479%`, `-7.409%`. The variation shows why these laptop results
are preliminary; they are not a stable overhead estimate. The Windows Server
2022 and Ubuntu 24.04 hosted-runner artifacts from the exact PR head are the
review evidence for this diagnostic.
