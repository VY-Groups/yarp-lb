# .NET YARP performance profiling

GitHub Actions runs a separate 75-VU/25-second HTTPS k6 load lab while collecting diagnostic counters directly from the **YARP gateway process** with `dotnet-counters`. The tool samples System.Runtime (CPU, allocations, garbage collections), System.Net.Http (connection pooling), System.Net.Security (TLS activity) and Microsoft.AspNetCore.Hosting (server request activity).

The workflow produces the raw `runtime-counters.csv`, collector log, `k6-summary.json`, and `profile-report.json` artifacts. Read the counters *before* changing `MaxConnectionsPerServer`, Server GC, metrics instrumentation or middleware; a significant throughput difference between baseline and proxy on a shared runner is not sufficient proof of a specific bottleneck.

Note: diagnostic collectors add overhead; the profiler benchmark **must not** be used for customer-facing performance claims. To isolate CPU hotspots in handlers, take targeted `dotnet-trace` traces on a dedicated non-production host. The workflow does not gather a trace with sensitive request data.

## Multi-VM performance qualification (not provisioned)
Use at least three isolated VMs or equivalent dedicated hosts: (1) k6 generator, (2) YARP gateway, and (3) mock application backends. Put them in the same availability zone/VPC with explicit firewall rules, stable VM sizes and autoscaling disabled during a run. Restrict administrative endpoints and private key stores to an isolated management network. Collect CPU/GC/network and TLS counters independently per host. Run direct, HTTP proxy, HTTPS proxy and mTLS-proxy scenarios multiple times in alternating order with matched payloads and connections; report mean and standard deviation, p50/p95/p99, errors and retransmits. 500–5,000-VU tests must use multiple independent generators if necessary. No cloud resources or credentials are provisioned by this repository's lab workflow.
