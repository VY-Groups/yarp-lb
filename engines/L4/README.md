# Standalone TCP / UDP engine — experimental 0.1

This is a separate .NET 10 process, **not YARP middleware**. It binds explicit TCP and UDP listeners; TCP forwards bidirectional streams with half-close propagation and connect-only failover; UDP uses per-client source IP/port sessions with backend replies routed to their original client. Both use round-robin across configured backends. It limits UDP sessions to 1,024 per listener and expires idle sessions after approximately 30 seconds of inactivity (when new packets arrive).

## Lab execution

```powershell
dotnet build engines/L4/L4Proxy.csproj -c Release
dotnet engines/L4/bin/Release/net10.0/L4Proxy.dll "C:\absolute\path\to\l4.json"
```

Listener addresses default to loopback-only; **non-loopback binding requires** `AllowNonLoopbackListeners: true`. Only IPv4 literal addresses are supported. No secrets, production ports or example internet-facing listeners are included. Real TCP and UDP socket tests run on both OSes in GitHub Actions.

## Boundaries

**Not production certified.** Does not yet include upstream health probes, TCP/TLS passthrough SNI selection, UDP fragmentation controls beyond datagram size, multi-host state sharing, durable config approval/signing, per-client IP authentication, DDoS protection, observability, hot reload, or backpressure/SLO capacity tests. TCP failover is safe **only before a connection is established**, never replaying an established TCP stream. UDP never provides at-least-once delivery. Separate firewall, change control and host isolation are mandatory.

The Control Center capability API must continue marking L4 as **partial**, not complete, until operational enrollment, monitoring and rollback are verified.
