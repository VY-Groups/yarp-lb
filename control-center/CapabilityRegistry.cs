using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Authorization;

/// <summary>Machine-readable capability inventory. "planned" never means installed.</summary>
public static class CapabilityRegistry
{
    public sealed record Capability(string Id, string Name, string Category, string Status,
        string Engine, string Notes);

    public static readonly Capability[] Items =
    [
        new("http-routing", "HTTP routes, hosts, methods, headers, transforms", "L7", "native-config", "YARP", "Host/path/header/query and transform rules need policy validation."),
        new("round-robin", "Round Robin", "Balancing", "native-config", "YARP", "Built in."),
        new("least-requests", "Least Requests (not true TCP least connections)", "Balancing", "native-config", "YARP", "Built in; examines active HTTP requests."),
        new("power-of-two", "Power of Two Choices", "Balancing", "native-config", "YARP", "Built in and YARP default."),
        new("weighted-random", "Weighted Random", "Balancing", "source-implemented-unverified", "YARP Control Center extension", "Destination Metadata.Weight 1..100. Windows C# build/integration verification required."),
        new("source-hash", "Source-IP Rendezvous Hash", "Balancing", "source-implemented-unverified", "YARP Control Center extension", "Stable HTTP peer-IP mapping, sensitive to SNAT and changing destination membership."),
        new("latency-aware", "Least observed response time", "Balancing", "planned", "Custom policy", "Requires EWMA, outlier resistance, feedback isolation, load tests."),
        new("l4-tcp-udp", "Layer-4 TCP / UDP proxy", "L4", "external-module", "Dedicated L4 product", "YARP does not turn HTTP middleware into a transparent TCP/UDP proxy."),
        new("tls", "TLS, SNI and outbound backend mTLS", "Transport", "partial-implementation", "Kestrel + certificate store", "BackendClientCertificateThumbprint selects a validated LocalMachine/My client-auth certificate for YARP cluster HTTPS egress. TLS lab builds; real enterprise mTLS enrollment and rotation still require independent validation."),
        new("acme", "ACME certificate renewal", "Transport", "external-module", "Approved ACME client", "Only for eligible public DNS names; private CA names require internal PKI."),
        new("http-streaming", "HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket", "L7", "integration-required", "Kestrel + YARP", "Protocol negotiation and upgrade paths must be tested per service."),
        new("sticky", "Cookie/header session affinity", "Balancing", "native-config", "YARP", "Multiple gateways require shared Data Protection keys for encrypted affinity modes."),
        new("health", "Active/passive health", "Health", "native-config", "YARP", "Paths and transport failure policy require service tests."),
        new("draining", "Connection drain and weighted slow start", "Health", "source-implemented-unverified", "YARP middleware + custom policy", "TrafficState=draining blocks new requests under all load-balancing policies. SlowStartSeconds 0..600 ramps WeightedRandom when first observed eligible; failover tests pending."),
        new("rate-limits", "Rate limiting/queueing/timeouts", "Protection", "integration-required", "ASP.NET Core + YARP", "Distributed limits need a separate shared store and correct client identity."),
        new("circuit-retry", "Circuit breaker/retry", "Protection", "planned", "Proxy middleware", "CA transactions require idempotency; never retry signing/approvals blindly."),
        new("gslb", "DNS health/geo/weighted/DR routing", "GSLB", "external-module", "DNS provider / GSLB", "Requires authoritative DNS or provider API and multi-site probes."),
        new("anycast", "Anycast", "GSLB", "network-design", "BGP/network", "Cannot be enabled from YARP alone."),
        new("ha-ingress", "Active–Active gateway VIP", "HA", "external-module", "Firewall/LB", "Health-aware ingress to both independent gateways is mandatory."),
        new("redis", "Shared rate-limit and session state", "HA", "planned", "Redis + application adapters", "Redis is not a plug-and-play YARP distributed state store."),
        new("waf", "OWASP CRS / WAF / bot protection", "Security", "external-module", "ModSecurity/Coraza / enterprise WAF", "Requires separate supported WAF engine and rule lifecycle."),
        new("jwt", "JWT/OAuth at edge", "Security", "integration-required", "ASP.NET Core auth", "Issuer, audience and signing key trust must be configured per route."),
        new("audit-rbac", "RBAC, audit and approvals", "Control Plane", "local-implemented", "YARP Control Center", "Local RBAC/approvals exist; WORM/SSO security verification pending."),
        new("otel", "Prometheus-format metrics, remote Grafana/OpenTelemetry", "Observability", "partial-implementation", "Local exporter", "Loopback exporter includes latency histogram, in-flight, working set/GC, and YARP health; no distributed collector, tracing, or remote Grafana integration."),
        new("config-api", "Dynamic route/cluster configuration", "Control Plane", "local-implemented", "YARP reload + Control Center", "Uses independently approved local config changes."),
        new("fleet", "Fleet rollout/rollback", "Control Plane", "source-implemented-unverified", "Gateway agents", "Staged rollout exists, not atomic; verify fleet reconciliation."),
        new("gitops", "GitOps, Terraform provider and K8s Gateway API", "Control Plane", "planned", "Separate integrations", "Requires versioned schemas, reconciliation and automated tests."),
        new("multi-tenant", "Multi-tenant isolation", "Control Plane", "planned", "Controller architecture", "Needs authorization boundaries at every API and data layer.")
    ];

    public static void MapCapabilityRegistry(this WebApplication app) =>
        app.MapGet("/admin/api/capabilities", () => Results.Ok(new
        {
            productVersion = "0.1", source = "declared capabilities - not live infrastructure state",
            policies = new[] { "RoundRobin", "PowerOfTwoChoices", "LeastRequests", "Random", "FirstAlphabetical", "WeightedRandom", "SourceIpHash" },
            weightedMetadata = new { key = "Weight", min = LoadBalancingCore.MinWeight, max = LoadBalancingCore.MaxWeight, @default = 1 },
            capabilities = Items
        })).RequireAuthorization();
}
