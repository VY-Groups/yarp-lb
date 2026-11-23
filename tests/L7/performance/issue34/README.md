# Issue #34 paired allocation profile

`.github/workflows/issue34-paired-profile.yml` runs one serial job on one GitHub-hosted Ubuntu 24.04 runner. Pull-request runs check out the exact PR base SHA and candidate head SHA; manual runs retain historical baseline `d2b135f760e92fb2646ec5542d89a7dc309eb88c`. It builds each lab and executes three paired rounds in alternating baseline/candidate order. Within each revision sample it runs the same 75-VU, 45-second direct-backend phase and proxy phase with identical payload and connection reuse. A short proxy warmup is excluded from measurements.

Each measurement records request rate, p95/p99, requests and errors, request checks, allocated bytes, working-set change, Gen0/1/2 collection deltas, managed-heap change, and GC pause duration. PR runs enable `YARP_LAB_OTEL_OVERHEAD=1` and apply equivalent diagnostics overlays to both disposable `GatewayLab` checkouts. The baseline overlay adds `Activity.Stop()` only when the exact known pre-fix completion helper is present; a candidate that already stops the activity is left unchanged. The lab overlay passes the configured route, cluster, and destination IDs to proxy metrics. Together these keep trace and metric collection equivalent on both revisions without changing production middleware or accepting unknown source shapes. Each lab process receives a unique loopback `YARP_OTEL_ENDPOINT`; the harness requires non-empty trace, metric, and log exports before accepting that sample, and checks exported trace/metric payloads for proxy activity, request counter, and route/cluster/destination dimensions before recording signal counts in `paired-runs.json`. Historical manual runs leave telemetry disabled; their d2b baseline has no OTEL API, so only the GC-pause counter overlay applies. The report contains paired deltas, sample standard deviation and a Student-t 95% interval. Existing acceptance limits are retained: 30–115 seconds, at least 1,000 requests, <1% failed requests, >99.5% checks, p95 <2,500 ms and p99 <5,000 ms.

After the measured rounds, the workflow collects one 25-second `dotnet-trace` `gc-verbose` trace per revision with a 64 MiB EventPipe buffer. A dedicated exec wrapper applies Linux `RLIMIT_FSIZE` only to each trace collector process, capped at 256 MiB; the runner also verifies each completed trace stays under that limit. The CLI preflight, gateway labs and k6 runner do not inherit this file limit. `gc-verbose` samples object allocations and records stack data. The trace is bounded diagnostic evidence for later human attribution; the report does not parse or automatically claim a particular code path caused an allocation.

The Actions summary labels a report **interim** if any required profile step fails. It calls the evidence complete only when the paired report, trace index and both non-empty trace files exist.

Artifacts include raw per-run summaries and gateway counters, paired JSON report, trace files, and trace metadata. Keep them as isolated CI evidence. A single hosted runner is not production-scale evidence, and a measured improvement is not inferred if the paired interval includes zero. This workflow alone does not close issue #34: Windows parity, streaming and CA-signing POST/no-replay characterization, a defensible allocation-stack attribution, and an independently validated optimization without safety regressions remain acceptance work.

## Report-evidence validation (strict, no threshold relaxation)

The paired report validator now rejects non-integer request/error counts,
out-of-range check rates, nonpositive or count/duration-inconsistent RPS (with
a 15% allowance for the difference between k6 active time and outer process
wall time), negative or reversed p95/p99
measurements, and missing or malformed VU/duration/payload/connection-reuse
metadata. It continues enforcing the existing 30–115 second, minimum-request,
failed-request, check and latency gates. Beyond the tabulated Student-t degrees
of freedom, the CI uses a conservative critical value rather than a narrower
normal approximation. Negative unit fixtures ensure corrupt summaries cannot
be mistaken for a measured optimization. This protects benchmark evidence but
**does not itself reduce the gateway's bytes allocated per request**.

## Reviewable Speedscope stacks (PR #429)

The paired workflow additionally converts each bounded baseline and candidate
`.nettrace` to a Speedscope JSON file using the pinned `dotnet-trace`
version. `verify_speedscope.py` rejects a missing/oversized file, invalid
frame references, and structurally valid JSON with no sampled stack or
evented-open observations. Its negative tests run in the existing deterministic
profile unit-test step; CI requires both nonempty validated stack files.

This is an **evidence integrity check**, not automatic object-allocation
attribution. Speedscope conversion can discard runtime metadata, and an
observed stack is not necessarily an allocation stack. Keep raw `.nettrace`
files for reviewer correlation with GC/allocation events and the paired
allocation report. A green conversion neither proves lower bytes/request nor
substitutes for Windows parity, correctness, or physical load acceptance.
