# L7 real-HTTP acceptance — development 0.1

This is an isolated executable test harness. The gateway is a small ASP.NET Core process that compiles the exact LoadBalancingCore.cs and LoadBalancingExtensions.cs classes in src/TrafficPolicies. Two separate mock ASP.NET Core processes serve **real** HTTP traffic. The test does not validate the full admin/control-center application, Windows services, certificates, or multi-gateway HA.

## Commands

From the repository root, with the .NET 10 SDK and NuGet access:

    dotnet build tests/L7/GatewayLab/GatewayLab.csproj -c Release
    dotnet build tests/L7/BackendLab/BackendLab.csproj -c Release
    dotnet build tests/L7/Acceptance/Acceptance.csproj -c Release
    dotnet run --project tests/L7/Acceptance/Acceptance.csproj -c Release --no-build

The runner starts processes on loopback only: Gateway 127.0.0.1:18080, backend A 127.0.0.1:18081, backend B 127.0.0.1:18082.

It writes JSON evidence to artifacts/l7/lab-results.json and process stdout/stderr to the same directory. A test failure exits nonzero and fails CI; results upload happens even on failure.

## Acceptance gates

| Area | Gate |
|---|---|
| Compilation | Real .NET 10/YARP 2.3.0 build |
| Weighted random | 4,000 requests with 80:20 weights; A is 75–85% |
| Reverse weights | 3,000 requests with 20:80 weights; B is 75–85% |
| Affinity | Same TCP-peer IP consistently maps 300 requests |
| Rendezvous | 5,000 deterministic keys; only removed node's clients move |
| Live reload | Weight change while sending 5,000 requests, no lost responses |
| Backend health | Unhealthy A removed; healthy B continues; A recovers |
| Both down | HTTP 503 with explicitly configured HealthyAndUnknown policy |
| In-flight failure | Killing A mid-request must not report HTTP 2xx |
| Backend restart | A re-enters selection after restart |

## Limits

- Local HTTP without TLS or authentication, for CI only.
- SourceIpHash uses TCP-peer IP. Source-NAT can collapse users into one backend.
- Rendezvous test keys are synthetic, not 5,000 real source IPs.
- Passing CI does not establish production readiness, CA compliance, or control-plane security.
- Health timing is aggressive to reduce CI runtime.

Never upload credentials, real customer data or production certificates.

**YARP default behavior:** HealthyOrPanic deliberately routes to unhealthy destinations if all health checks fail. The lab explicitly configures HealthyAndUnknown to enforce fail-closed 503 behavior. Choose the production policy based on service risk and readiness semantics.
