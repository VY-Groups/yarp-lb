# Manual long-duration soak workflow

The `Manually requested long-duration k6 soak` workflow lets a repository operator run sustained loopback HTTP tests for 15 minutes, one hour, or four hours, with 75/500/1000 virtual users, 0/1KB/64KB responses and connection reuse on/off. A dedicated GitHub runner hosts the load generator, YARP and mock backends.

It samples working-set, managed heap and GC counts every 30 seconds, saves k6 latency percentiles, and uploads a machine-readable `report.json`. It does **not** measure GC pause time, guarantee absence of leaks, or emulate network hops. For production benchmarks use independent generators and real infrastructure.

This is manual-only due to runner expense; creating the workflow does not execute an hour-long test. To run: GitHub repository → Actions → Manually requested long-duration k6 soak → Run workflow. The action only affects disposable CI runners, never production.

## Five-minute latency and memory trend analysis

New soak runs record **bounded five-minute k6 latency Trends** (one custom metric per 5-minute window, maximum 48 for four hours). The JSON report includes per-window p99 estimates and the average ratio of the final three populated windows to the first three. A ratio above 1.5 is an **investigation flag, not a product SLO**.

The report also groups memory and cumulative Gen2 collection counts by sample quarter. A rising working set or Gen2 count alone cannot establish a leak; analyze managed heap stabilization, allocation rate, finalization, GC pause duration and full traces before concluding. The first one-hour soak already running from an earlier commit cannot retroactively provide per-window p99; the new metrics apply only to new runs.
