# Control Center stdout backpressure policy (0.1 Development)

The serving `control-center/Program.cs` is a **different executable** from the disposable `tests/L7/GatewayLab` and the independent GatewayAgent. PR #19 only reduced log volume and drained redirected child logs in the test harness. It did not protect the actual Control Center process. See GitHub issue #20.

## Product gateway change

The Control Center now filters out only its built-in ConsoleLoggerProvider and replaces it with an explicit `NonBlockingConsoleLoggerProvider`. Debug/EventSource and other registered providers remain unaffected. The replacement writes through one dedicated background thread and a **bounded 1,024-message queue**. Producers use `TryAdd` with no queue-wait loop; if stdout is not consuming, messages are discarded and their count increases monotonically. Every formatted line is bounded to 4,096 characters. This is intentionally a fail-open *logging* mechanism, NOT fail-open authentication.

The authorized, loopback-only `GET /admin/api/logging-health` reports queue capacity, queued count, enqueued total, written total, dropped total and write-error total. An OpenTelemetry-compatible .NET Meter named `SpeedSignYarp.Logging` publishes `yarp_logging_dropped_total` and `yarp_logging_write_errors_total` as ObservableCounters.

A lab acceptance project directly blocks the sink writer and sends 15,000 log calls. It asserts that producers do not stall, the queue stays bounded, and drop counters increase. It runs in the Control Center Windows Server 2022 + Ubuntu 24.04 CI matrix.

## Operational limits

- Any dropped console log is a signal to investigate stdout collection and reduce verbosity. Configure alerts on changes to `droppedTotal` and `writeErrorsTotal`. A count of zero is a non-lossy observation only for the current process, not a durable lifetime guarantee.
- Audit records remain separately persisted in `admin-audit.jsonl`. **Never** rely on the lossy console writer for CA signing, security/audit, compliance, user approval or incident evidence. Production requires an independently protected central audit sink.
- A blocked background stdout writer can remain blocked indefinitely, but must not stall request threads. Host restarts can lose still-queued console messages. The shutdown hook waits at most 100ms for writer completion, rather than blocking indefinitely.
- This is a source-level protection and isolated blocked-writer test, NOT a same-load Control Center one-hour soak or production SLA. More testing is required with actual hosting, persistent collectors and multi-host service topology.
- The original hang was reproduced in *GatewayLab* with its own verbose logger and redirected pipes. Its corrective PR #19 remains a distinct patch with a separate 75-VU controlled regression. Passing only lab acceptance is not sufficient to certify Control Center.
