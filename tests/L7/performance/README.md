# Comparable L7 HTTP/TLS lab benchmark

The GitHub Actions `performance-soak` job creates an ephemeral HTTPS listener on 127.0.0.1:18443 and runs k6 at 75 virtual users for 20 seconds per phase: direct against two backends (70/30 mix), HTTP through YARP, HTTPS terminated at YARP with persistent connections, and HTTPS through YARP with connection reuse disabled. It checks every HTTPS response's negotiated TLS version rather than inferring TLS solely from the URL. Each phase uses the same endpoint and virtual-user count; runs sequentially on the SAME GitHub-hosted Ubuntu VM.

`artifacts/k6/comparison.json` reports req/s, p95 and p99, throughput ratios and latency differences against the direct-backend baseline. These are only indicative measurements. The generator and gateway compete for VM CPU, TLS uses an ephemeral self-signed certificate with test-only bypass, and no independent network hops are present. Do not compare these numbers to HAProxy or extrapolate them to production.

A later production benchmark must use separate hosts for load generator, ingress, gateway and backends; trusted TLS chains, real mTLS, payload/connection reuse variants, multiple sustained concurrency levels (500–5000) and multi-hour soak/GC pause statistics. Those features are **not demonstrated** by this lab.

TLS no-reuse comparison includes a new handshake on each client connection. The JSON report includes observed TLS-negotiated response counts and average TLS handshake and TCP connection setup time. Because these four tests are run sequentially on a shared host, differences are indicative only. These tests do not validate certificate trust or backend mTLS.
