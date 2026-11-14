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
        new("weighted-random", "Weighted Random", "Balancing", "lab-verified", "YARP Control Center extension", "Compiled and validated with real L7 distribution traffic on Windows and Ubuntu; production capacity and NAT identity still require testing."),
        new("source-hash", "Source-IP Rendezvous Hash", "Balancing", "lab-verified", "YARP Control Center extension", "Real HTTP affinity/rebalance tests passed on Windows and Ubuntu; source-IP identity depends on ingress/SNAT."),
        new("latency-aware", "Least observed response time", "Balancing", "planned", "Custom policy", "Requires EWMA, outlier resistance, feedback isolation, load tests."),
        new("l4-tcp-udp", "Layer-4 TCP / UDP proxy", "L4", "external-lab-verified", "engines/L4 independent .NET process", "TCP bidirectional and UDP source-session real-socket CI passed on Windows/Ubuntu. No lifecycle integration, production health, distributed state or public deployment approval."),
        new("tls", "TLS, SNI and outbound backend mTLS", "Transport", "partial-implementation", "Kestrel + certificate store", "BackendClientCertificateThumbprint selects a validated LocalMachine/My client-auth certificate for YARP cluster HTTPS egress. TLS lab builds; real enterprise mTLS enrollment and rotation still require independent validation."),
        new("acme", "ACME certificate renewal", "Transport", "external-module", "Approved ACME client", "Only for eligible public DNS names; private CA names require internal PKI."),
        new("http-streaming", "HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket", "L7", "integration-required", "Kestrel + YARP", "Protocol negotiation and upgrade paths must be tested per service."),
        new("sticky", "Cookie/header session affinity", "Balancing", "native-config", "YARP", "Multiple gateways require shared Data Protection keys for encrypted affinity modes."),
        new("health", "Active/passive health", "Health", "native-config", "YARP", "Paths and transport failure policy require service tests."),
        new("bounded-ejection", "Bounded passive transport-failure ejection", "Health", "source-implemented-unverified", "YARP configurable policy", "Opt-in 50% ejection ceiling, minimum survivor, 15s anti-flap cooldown and safe zero automatic retries; all-down fail-closed is default, panic explicit. Does NOT prove WAN/partition/recovery under real firewalls."),
        new("draining", "Connection drain and weighted slow start", "Health", "lab-verified", "YARP middleware and custom policy", "CI proves new-request drain, weighted warmup and pre-drained graceful maintenance. Not a deadline guarantee for WebSockets, gRPC or long-lived TCP."),
        new("rate-limits", "Rate limiting/queueing/timeouts", "Protection", "integration-required", "ASP.NET Core + YARP", "Distributed limits need a separate shared store and correct client identity."),
        new("circuit-retry", "Circuit breaker/retry", "Protection", "planned", "Proxy middleware", "CA transactions require idempotency; never retry signing/approvals blindly."),
        new("gslb", "DNS health/weighted/DR routing", "GSLB", "external-lab-verified", "engines/GslbDns independent .NET process", "UDP A-record responder passes health withdrawal, weighted answers and recovery on Windows/Ubuntu. No production authoritative DNS TCP, delegation, DNSSEC or regional probes."),
        new("anycast", "Anycast", "GSLB", "network-design", "BGP/network", "Cannot be enabled from YARP alone."),
        new("ha-ingress", "Active–Active gateway VIP", "HA", "lab-verified", "isolated health-aware YARP ingress lab", "Two gateways survive one abrupt kill and pre-drained graceful stop in single-runner CI. NOT proven: redundant ingress, VIP, multi-host partitions, realistic WAN latency, production scale and cluster-wide consistency."),
        new("redis", "Shared rate-limit and session state", "HA", "planned", "Redis + application adapters", "Redis is not a plug-and-play YARP distributed state store."),
        new("waf", "OWASP CRS / WAF / bot protection", "Security", "external-lab-verified", "ModSecurity/OWASP CRS official container", "Docker CI passes benign HTTP and blocks XSS with 403; no production provisioning, TLS trust, bot policy, tuning, false-positive review or DDoS certification."),
        new("jwt", "JWT/OAuth at edge", "Security", "integration-required", "ASP.NET Core auth", "Issuer, audience and signing key trust must be configured per route."),
        new("audit-rbac", "RBAC, audit and approvals", "Control Plane", "local-implemented", "YARP Control Center", "Local RBAC/approvals exist; WORM/SSO security verification pending."),
        new("otel", "Prometheus-format metrics, remote Grafana/OpenTelemetry", "Observability", "partial-implementation", "Local exporter", "Loopback exporter includes latency histogram, in-flight, working set/GC, and YARP health; no distributed collector, tracing, or remote Grafana integration."),
        new("nonblocking-console", "Bounded nonblocking gateway console logging", "Observability", "source-implemented-unverified", "Control Center dedicated background writer", "Real gateway logs cannot wait for stdout; bounded queue with drop/error counters and admin-only readout. Still requires same-load production-binary CI and real deployment validation. Lossy logs are NOT an audit trail."),
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
