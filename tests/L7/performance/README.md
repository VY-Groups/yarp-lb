# Comparable L7 HTTP/TLS lab benchmark

The GitHub Actions `performance-soak` job creates an ephemeral HTTPS listener on 127.0.0.1:18443 and runs k6 at 75 virtual users for 20 seconds per phase: direct against two backends (70/30 mix), HTTP through YARP, and HTTPS terminated at YARP. Each phase uses the same endpoint and virtual-user count; runs sequentially on the SAME GitHub-hosted Ubuntu VM.

`artifacts/k6/comparison.json` reports req/s, p95 and p99, throughput ratios and latency differences against the direct-backend baseline. These are only indicative measurements. The generator and gateway compete for VM CPU, TLS uses an ephemeral self-signed certificate with test-only bypass, and no independent network hops are present. Do not compare these numbers to HAProxy or extrapolate them to production.

A later production benchmark must use separate hosts for load generator, ingress, gateway and backends; trusted TLS chains, real mTLS, payload/connection reuse variants, multiple sustained concurrency levels (500–5000) and multi-hour soak/GC pause statistics. Those features are **not demonstrated** by this lab.
