# Standalone TCP / UDP engine — experimental 0.1

This is a separate .NET 10 process, **not YARP middleware**. It binds explicit TCP and UDP listeners; TCP forwards bidirectional streams with half-close propagation, health-probed connect-time fallback, explicit per-backend admission drain, configurable idle timeout, and opt-in PROXY protocol v1; UDP uses per-client source IP/port sessions with backend replies routed to their original client. Both use round-robin across configured backends. It limits UDP sessions to 1,024 per listener and expires idle sessions after approximately 30 seconds of inactivity (when new packets arrive).

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

Checks are TCP-connect-only, NOT application readiness, TLS or real traffic SLOs. UDP still has no corresponding active health checks.

## Boundaries

**Not production certified.** Does not yet include application-layer health probes, live rolling drain controls, PROXY v2, TCP/TLS passthrough SNI selection, UDP fragmentation controls beyond datagram size, multi-host state sharing, durable config approval/signing, per-client IP authentication, DDoS protection, observability, hot reload, or backpressure/SLO capacity tests. TCP failover is safe **only before a connection is established**, never replaying an established TCP stream. UDP never provides at-least-once delivery. Separate firewall, change control and host isolation are mandatory.

The Control Center capability API must continue marking L4 as **partial**, not complete, until operational enrollment, monitoring and rollback are verified.
