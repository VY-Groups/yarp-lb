# Issue #40 — 100 ms cross-process HA heartbeat evidence

This is diagnostic instrumentation for the disposable HA fault-injection suite,
not a production health-check mechanism and not proof of fast active detection.

Each process started by the test writes its own CSV every **100 milliseconds**:
`heartbeat-ha-harness.csv`, `heartbeat-backend-a.csv`,
`heartbeat-backend-b.csv`, `heartbeat-gateway-1.csv`,
`heartbeat-gateway-2.csv`, `heartbeat-health-aware-ingress.csv`
and files for any restarted gateways/ingress variants.

Each heartbeat is written by a **dedicated OS thread** rather than a
ThreadPool task. The first executed Windows run showed 6.8–11.0-second
*harness-only* ThreadPool-timer heartbeat gaps while separate child processes
continued to tick. That observation is compatible with local harness
ThreadPool starvation, not proof of a whole-runner pause. The dedicated thread
provides a less ThreadPool-dependent clock for the next repetition.

The CSV includes UTC milliseconds, *independent monotonic stopwatch ticks*,
stopwatch frequency, process ID, live ThreadPool thread count, pending work
items, and cumulative process CPU milliseconds. Flushing happens on each tick
so a forcibly killed process retains its recent samples. Ordinary k6 runs do
not enable this heartbeat and production gateway code remains unaffected.

`prekill-request-timeline.csv` records **every** sampled test request
(phase, start/completion time, HTTP status and exception type), including
the 100-request post-slow period that previously failed before the abrupt kill.
The existing `fault-traffic-timeline.csv` remains unchanged for kill-time
completion evidence.

`heartbeat_summary.py` runs even if the HA test fails; it writes
`heartbeat-summary.json` with each process's maximum monotonic gap, the
gaps ≥250 ms, cross-process overlapping gaps and prekill failed request
samples. Simultaneous gaps across multiple streams **suggest** a host-wide
scheduler pause; a gap in one stream **suggests** a process-local delay.
Neither is proof. To establish cause, correlate with OS/CLR ETW/ThreadPool
traces and per-request status evidence. A missing sample stream is explicitly
reported as unavailable, never converted to a passing test.

The strict **2,000 ms last-failure-after-kill**, 1,500 ms upstream
activity timeout, zero-loss graceful drain, bounded passive-ejection and
zero automatic replay requirements are **unchanged**. A no-data run is a
failed HA run. The first two matrices remain **9/10 and 8/10**, not green.

Run links:
- https://github.com/VY-Groups/yarp-lb/actions/runs/43547047146
- https://github.com/VY-Groups/yarp-lb/actions/runs/43547492741

The new 10-run workflow deliberately fails its aggregate check unless all
ten individual tests pass. Investigate failed-run heartbeat evidence before
tuning any thresholds.
