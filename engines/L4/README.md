# Standalone TCP / UDP engine — experimental 0.1

This is a separate .NET 10 process, **not YARP middleware**. It binds explicit TCP and UDP listeners; TCP forwards bidirectional streams with half-close propagation, health-probed connect-time fallback, explicit per-backend admission drain, configurable idle timeout, and opt-in PROXY protocol v1; UDP uses per-client source IP/port sessions with backend replies routed to their original client. Both use round-robin across configured backends. It bounds active TCP streams and UDP sessions to 1,024 each per listener by default and expires idle sessions after 30 seconds of inbound inactivity by default, with a one-second periodic sweep even when no datagrams arrive.

## Capability and configuration matrix

| Capability | Status | Configuration and boundary |
| --- | --- | --- |
| TCP stream pass-through and half-close | Supported | Round-robin; connect-time backend fallback only. An established stream is never replayed. |
| TCP health | Supported, connect-only | `ProbeIntervalSeconds`; not application, TLS, or transaction readiness. |
| UDP relay and source-endpoint affinity | Supported | Round-robin for new endpoints; existing sessions remain pinned until idle expiry or process stop. Opaque datagrams are forwarded unchanged. |
| UDP application health | Optional | `UdpProbePayload` and `UdpProbeExpectedResponse` must both be configured; a passing probe gates new sessions only. |
| Backend drain | Supported at startup | `DrainNewConnections` excludes a backend from new TCP streams or UDP sessions. Live drain controls are not implemented. |
| Admission and idle limits | Supported | Per listener: 1,024 TCP streams / UDP sessions by default; 1–4,096 allowed. TCP and UDP idle timeouts are configurable; excess TCP connections close and excess UDP endpoints drop without an application queue. |
| Safe listener binding | Supported | IPv4 literal addresses only. Loopback by default; non-loopback requires `AllowNonLoopbackListeners: true`. |
| PROXY protocol | Optional TCP v1 only | `SendProxyProtocolV1` defaults to false and requires a backend that explicitly understands the header. |
| TLS termination, TLS passthrough SNI routing, and PROXY v2 | Unsupported | This engine does not inspect or terminate TLS. |
| UDP fragmentation controls and multi-host shared state | Unsupported | No fragmentation policy or cross-process session/config coordination is provided. |

The matrix describes this experimental process, not the YARP Control Center's operational capabilities. Keep L4 marked **partial** in the Control Center until enrollment, monitoring, and rollback are verified.

The Windows/Linux socket acceptance includes a TCP half-close case: after the client sends its request and shuts down only its send direction, the backend must observe EOF, produce a complete response, and close its send direction; the client must receive that response through EOF. This verifies bidirectional FIN propagation in the loopback lab only. It does not demonstrate packet-loss behavior or WAN reliability.

## Lab execution

```powershell
dotnet build engines/L4/L4Proxy.csproj -c Release
dotnet engines/L4/bin/Release/net10.0/L4Proxy.dll "C:\absolute\path\to\l4.json"
```

Listener addresses default to loopback-only; **non-loopback binding requires** `AllowNonLoopbackListeners: true`. Only IPv4 literal addresses are supported. No secrets, production ports or example internet-facing listeners are included. Real TCP and UDP socket tests, including configurable TCP health/drain/idle/PROXY v1 checks, are configured to run on both OSes in GitHub Actions.

## Additional TCP listener fields

- `TcpIdleTimeoutSeconds` (default 300, permitted 1–3600): total-connection idle timeout, refreshed by data in either direction; actively used connections are not replayed after a failure.
- `ProbeIntervalSeconds` (default 2, permitted 1–60): TCP connect checks with a 500 ms limit. A target that fails probes is excluded from new connections while at least one target is healthy; if every probe fails, the engine attempts non-draining targets at connect time to prevent probe-induced total unavailability.
- `SendProxyProtocolV1` (default false): prefixes the backend connection with a `PROXY TCP4` line. Only enable for a trusted backend that explicitly expects PROXY v1. Do not enable against ordinary TCP services.
- Backend `DrainNewConnections` (default false): prevents *new* streams from using that target, without interrupting already established streams. This is static config at process startup in version 0.1; a coordinated, zero-loss live drain API is NOT implemented.

TCP checks are connect-only, NOT application readiness, TLS or real traffic SLOs. UDP application checks are optional as described below.

## UDP listener fields

- `UdpIdleTimeoutSeconds` (default 30, permitted 1–3600): monotonic idle timeout refreshed by inbound datagrams. The periodic sweep retires unused upstream sockets without waiting for another packet; a new datagram after expiry establishes a new round-robin relay. Expired or failed datagrams are not replayed. New sessions exclude draining backends; all-drained listeners drop new datagrams. The signed engine configuration validator enforces the same timeout range as the engine.
- UDP application health is opt-in. Set both `UdpProbePayload` and `UdpProbeExpectedResponse` to non-empty UTF-8 strings of at most 512 bytes, plus optional `UdpProbeIntervalSeconds` (default 2, permitted 1–60). The engine sends the exact payload to each non-draining backend and requires an exact response within 500 ms. Failed probes remove a backend only from **new** sessions; existing UDP source-affinity sessions remain pinned and are never replayed. A passing probe restores eligibility. If all probes fail, the engine attempts non-draining backends (availability-first fallback); this is not proof of application health. The probe protocol must be explicitly supported by each backend and must be safe to invoke repeatedly. If either payload field is omitted, UDP health probes are disabled.

## Boundaries

**Not production certified.** Does not yet include protocol-independent application readiness, live rolling drain controls, PROXY v2, TCP/TLS passthrough SNI selection, UDP fragmentation controls beyond datagram size, multi-host state sharing, durable config approval/signing, per-client IP authentication, DDoS protection, observability, hot reload, or backpressure/SLO capacity tests. UDP health is only as meaningful as the operator-configured request/response contract. TCP failover is safe **only before a connection is established**, never replaying an established TCP stream. UDP never provides at-least-once delivery. Separate firewall, change control and host isolation are mandatory.

The Control Center capability API must continue marking L4 as **partial**, not complete, until operational enrollment, monitoring and rollback are verified.

## Bounded transport admission

`TcpMaxConnections` and `UdpMaxSessions` default to 1024 per listener; valid range 1–4096. The signed configuration validator uses the same bounds and rejects null/string values. TCP counts pending upstream connects and established streams; excess accepted sockets close immediately, with no upstream connect or application-byte replay. The kernel listen backlog is separate; no application waiting queue is provided. Established streams retain their slots through bidirectional shutdown; errors and idle expiry release slots. UDP drops new endpoints when the configured session table is full, preserving existing source affinity; idle expiry releases capacity. TCP admission emits one aggregate active/rejected summary on listener stop, not a per-rejection log. The process stops accepting on shutdown and permits established TCP streams up to five seconds to drain, then cancels their forwarding (up to two seconds additional cleanup). This is a process-local bound, not distributed quota, dynamic live drain, per-client admission, full DDoS defense or demonstrated capacity. Windows/Linux socket tests cover overload, preservation of existing streams/sessions, half-close slot recovery and UDP idle recovery. Physical soak and transport-level loss/reordering evidence remain open.

A listener bind or runtime failure shuts down sibling listeners and exits nonzero; startup must not advertise engine readiness if a configured listener fails to bind. The real-process fixture occupies a TCP port, verifies bounded nonzero exit and checks that sibling TCP/UDP ports can be rebound. This is local process failure containment, not physical failover.

The real-process fault fixture sends a unique TCP transaction to a backend that resets after receiving its bytes, then checks the next independent connection succeeds without replaying the old transaction. It also deliberately drops one UDP response, counts receipt on both backends, and checks source-affinity and new-endpoint routing without retransmission by the proxy. These are loopback software contracts, not packet-loss/WAN benchmarks.

The fixture also checks a refused upstream connection and an all-drained TCP listener: both close new downstream connections without forwarding application data. These do not test backend recovery after an established stream; the reset and UDP-drop cases separately verify no replay after forwarding begins.

Linux real-process SIGTERM acceptance exercises two established TCP streams: admission stops, one transaction finishes and half-closes during drain, the other is cancelled within the bounded shutdown budget, and the UDP port is released. Windows console-control shutdown is a separate acceptance requirement; Linux SIGTERM coverage must not be reported as Windows graceful-stop verification.

Windows acceptance now starts a shipping L4 process in its own console process group and sends a real `CTRL+BREAK` event. It checks that new TCP admission stops, an established transaction completes and half-closes during drain, a held stream is released within the shutdown bound, the process exits successfully, and the UDP listener can be rebound. This is real Windows console-control acceptance; it is not Windows Service Control Manager integration or physical host testing.

## Capacity-aware L4 selection

Listener `BalancingPolicy` defaults to `RoundRobin`. `WeightedRoundRobin` is supported for new TCP connections and UDP sessions; backend `Weight` defaults to 1, allowed 1–100. `WeightedLeastConnections` is TCP-only and selects the lowest projected (connecting + established + 1)/weight, with local per-listener counters. Established streams and UDP sessions never migrate. Existing connect-only fallback and health behavior are preserved; no application-byte replay. Signed staging validates the same policy and weight bounds. This change requires fresh real-socket CI and does not implement dynamic listener reconfiguration or fleet-wide counts.
