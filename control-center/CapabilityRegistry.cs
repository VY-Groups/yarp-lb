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
        new("weighted-round-robin", "Weighted HTTP round robin", "Balancing", "source-implemented-unverified", "GatewayCore managed YARP policy", "Cyclic weighted selection over eligible non-draining destinations; fixed membership and weights give an exact ratio per complete cycle. Local cursor only."),
        new("weighted-least-requests", "Weighted least outstanding HTTP requests", "Balancing", "source-implemented-unverified", "GatewayCore managed YARP policy", "Chooses minimum projected local outstanding requests per effective destination weight; excludes draining destinations and respects existing eligibility. Not TCP connection count, measured response time or a shared fleet counter."),
        new("primary-backup", "Primary/backup HTTP server selection", "Balancing", "lab-verified", "GatewayCore managed YARP policy", "Opt-in PrimaryBackup policy; active health required; weighted healthy primaries take precedence, a fixed backup serves only if primaries fail. Real two-backend L7 failover, all-down and recovery CI passed. No transaction replay or physical HA claim."),
        new("latency-aware", "Least observed response time", "Balancing", "planned", "Custom policy", "Requires EWMA, outlier resistance, feedback isolation, load tests."),
        new("l4-tcp-udp", "Layer-4 TCP / UDP proxy", "L4", "external-lab-verified", "engines/L4 independent .NET process", "TCP bidirectional and UDP source-session real-socket CI passed on Windows/Ubuntu. No lifecycle integration, production health, distributed state or public deployment approval."),
        new("tls", "TLS, SNI and outbound backend mTLS", "Transport", "partial-implementation", "Kestrel + certificate store", "BackendClientCertificateThumbprint selects a validated LocalMachine/My client-auth certificate for YARP cluster HTTPS egress. Opt-in isolated traffic listeners can atomically hot-reload validated TLS PFX files; enterprise mTLS enrollment and deployment acceptance remain unverified."),
        new("acme", "ACME certificate lifecycle", "Transport", "bounded-http01-renewal-and-guarded-manual-revocation", "Certes ACME v2 + GatewayCore isolated traffic listener", "Opt-in HTTP-01 renewal uses a DP-protected account key, bounded challenge store, validated atomic PFX rotation and live-listener confirmation/rollback. A role-protected, rate-limited operator endpoint can revoke a confirmed prior TLS leaf and refuses the currently served leaf. Deterministic Windows/Linux fake-CA contracts cover the coordinator; public-domain staging, DNS-01, automatic revocation, OCSP/CRL freshness, external alerts and multi-node challenge sharing remain pending."),
        new("http-streaming", "HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket", "L7", "partial-implementation", "Kestrel + YARP", "Isolated traffic listeners opt into HTTP/3 with httpVersion=3, retaining HTTP/1.1 and HTTP/2; UDP reachability and MsQuic are required. Windows CI runs HTTP/3 wire acceptance; the current Ubuntu runner lacks MsQuic and explicitly skips wire checks. No physical deployment certification."),
        new("sticky", "Cookie/header session affinity", "Balancing", "native-config", "YARP", "Multiple gateways require shared Data Protection keys for encrypted affinity modes."),
        new("health", "Active/passive health", "Health", "native-config", "YARP", "Paths and transport failure policy require service tests."),
        new("bounded-ejection", "Bounded passive transport-failure ejection", "Health", "source-implemented-unverified", "YARP configurable policy", "Opt-in 50% ejection ceiling, minimum survivor, 15s anti-flap cooldown and safe zero automatic retries; all-down fail-closed is default, panic explicit. Does NOT prove WAN/partition/recovery under real firewalls."),
        new("draining", "Connection drain and weighted slow start", "Health", "lab-verified", "YARP middleware and custom policy", "CI proves new-request drain, weighted warmup and pre-drained graceful maintenance. Not a deadline guarantee for WebSockets, gRPC or long-lived TCP."),
        new("rate-limits", "Rate limiting/queueing/timeouts", "Protection", "integration-required", "ASP.NET Core + YARP", "Distributed limits need a separate shared store and correct client identity."),
        new("circuit-retry", "Circuit breaker/retry", "Protection", "planned", "Proxy middleware", "CA transactions require idempotency; never retry signing/approvals blindly."),
        new("gslb", "DNS health/weighted/DR routing", "GSLB", "external-lab-verified", "engines/GslbDns independent .NET process", "UDP A-record responder passes health withdrawal, weighted answers and recovery on Windows/Ubuntu. No production authoritative DNS TCP, delegation, DNSSEC or regional probes."),
        new("anycast", "Anycast", "GSLB", "network-design", "BGP/network", "Cannot be enabled from YARP alone."),
        new("ha-ingress", "Active–Active gateway VIP", "HA", "lab-verified", "isolated health-aware YARP ingress lab", "Two gateways survive one abrupt kill and pre-drained graceful stop in single-runner CI. NOT proven: redundant ingress, VIP, multi-host partitions, realistic WAN latency, production scale and cluster-wide consistency."),
        new("redis", "Optional atomic shared rate limiting", "Protection", "lab-verified", "GatewayCore TLS Redis rate limiter", "Two-gateway Docker/TLS CI verifies atomic request quota and fail-closed disconnect behavior. Session state, Sentinel quorum/fencing and physical partition correctness remain NOT IMPLEMENTED or NOT VERIFIED."),
        new("waf", "OWASP CRS / WAF / bot protection", "Security", "external-lab-verified", "ModSecurity/OWASP CRS official container", "Docker CI passes benign HTTP and blocks XSS with 403; no production provisioning, TLS trust, bot policy, tuning, false-positive review or DDoS certification."),
        new("jwt", "JWT/OAuth at edge", "Security", "integration-required", "ASP.NET Core auth", "Issuer, audience and signing key trust must be configured per route."),
        new("audit-rbac", "RBAC, audit and approvals", "Control Plane", "local-implemented", "YARP Control Center", "Local RBAC/approvals exist; WORM/SSO security verification pending."),
        new("otel", "Prometheus metrics and optional OTLP traces/metrics/logs", "Observability", "partial-implementation", "Local Prometheus exporter + opt-in OTLP/HTTP", "Loopback Prometheus includes latency histogram, in-flight, working set/GC and YARP health. Optional OTLP/HTTP exports sampled traces, bounded proxy and logging-loss metrics, and allowlisted structured access logs; versioned Grafana dashboard/alert assets and a loopback-only Collector/Prometheus/Grafana/Alertmanager acceptance stack exist. Production collector deployment, durable fleet storage, deployed alert delivery, and Windows/Linux overhead baselines remain unverified."),
        new("nonblocking-console", "Bounded nonblocking gateway console logging", "Observability", "source-implemented-unverified", "Control Center dedicated background writer", "Real gateway logs cannot wait for stdout; bounded queue with drop/error counters and admin-only readout. Still requires same-load production-binary CI and real deployment validation. Lossy logs are NOT an audit trail."),
        new("config-api", "Dynamic route/cluster configuration", "Control Plane", "local-implemented", "YARP reload + Control Center", "Uses independently approved local config changes."),
        new("fleet", "Fleet rollout/rollback", "Control Plane", "source-implemented-unverified", "Gateway agents", "Staged rollout exists, not atomic; verify fleet reconciliation."),
        new("gitops", "GitOps, Terraform provider and K8s Gateway API", "Control Plane", "partial-implementation", "Offline route/cluster planner", "A version-1 read-only planner validates route-to-cluster references and reports redacted ID-only diffs. It does not apply changes; Terraform/provider, Gateway API, signed provenance and fleet reconciliation remain unimplemented."),
        new("multi-tenant", "Multi-tenant isolation", "Control Plane", "planned", "Controller architecture", "Needs authorization boundaries at every API and data layer.")
    ];

    // Coverage describes delivered software scope, not enabled infrastructure or physical certification.
    public sealed record AdcFeature(string Id, string Name, string Status, string Notes, string Evidence);
    public static readonly AdcFeature[] AdcCoverage =
    [
        new("http-services", "HTTP routing and approved service configuration", "implemented", "Routes, clusters, enabled/disabled destinations and reviewed configuration.", "Frozen L7 and browser/API acceptance; #573/#574"),
        new("virtual-services", "Virtual services / ports", "partial", "Host-provisioned isolated HTTP(S) sockets and route binding exist. Unified editable L4/L7 virtual-server registry and cross-engine conflict lifecycle remain pending.", "#573, #589"),
        new("reusable-objects", "Reusable server/group/monitor objects", "partial", "Reviewed templates and materialized snapshots exist; full shared identity and live reference lifecycle remain pending.", "#568–#572"),
        new("balancing", "HTTP balancing algorithms", "implemented", "Round robin, weighted variants, least requests, source hash, primary/backup and local fastest-response policies. Local request/latency state only.", "#564, #589; frozen L7"),
        new("persistence", "Advanced persistence profiles", "partial", "Secure expiring HTTPS affinity and scoped shared-key compatibility; broader protocol profiles and deployment custody remain pending.", "#570–#571"),
        new("health", "Health monitors and application templates", "partial", "Active/passive and compound HTTP/TCP checks, profile registry and copied/linked snapshots; wider protocol/template catalog pending.", "#565–#569"),
        new("l4", "Independent TCP/UDP engine", "implemented", "Separate runtime with real socket acceptance; not an HTTP route or unified lifecycle UI.", "Frozen L4 acceptance"),
        new("dns", "Independent DNS/GSLB engine", "implemented", "Authoritative DNS TCP/UDP, DNSSEC/NSEC3 and source admission tested; real delegation and geography under #36.", "#578–#579; frozen GSLB"),
        new("network", "Network management", "partial", "Local inventory, Linux VLAN observation and guarded VIP management; full interface/VLAN mutation, routing/NAT/SNAT pending.", "#580–#589"),
        new("security", "Security and application access", "partial", "Reviewed CIDR/HTTPS access, WAF tooling and quotas; application SSO, advanced DDoS, and expanded policies pending.", "#574, #577; frozen security/WAF"),
        new("acceleration", "Acceleration", "partial", "Opt-in public HTTP static compression and method policy; HTTP caching and expanded programmable policy pending.", "#576–#577"),
        new("observability", "Observability, diagnostics CLI and SOP", "partial", "Local telemetry, audit, scoped diagnostics and operator SOP exist; unified advanced analytics, configuration CLI and training remain pending.", "#563, #575; frozen audit"),
        new("multi-tenancy", "Multi-tenant partitions", "unavailable", "Single-tenant architecture; no isolation guarantee from metadata.", "Roadmap future architecture"),
        new("routing-nat", "Managed routing, NAT and SNAT", "unavailable", "No authorized full host routing/NAT management UI or runtime contract.", "Roadmap network phase"),
        new("app-sso", "Application identity-aware access", "unavailable", "Admin login is not application identity-aware proxy authorization.", "Roadmap security phase"),
        new("hardware-ddos", "Hardware acceleration / volumetric DDoS absorption", "unavailable", "No appliance-level hardware or volumetric mitigation claim.", "Deployment-dependent"),
    ];

    public static void MapCapabilityRegistry(this WebApplication app) =>
        app.MapGet("/admin/api/capabilities", () => Results.Ok(new
        {
            productVersion = "0.1", source = "declared capabilities - not live infrastructure state",
            policies = new[] { "RoundRobin", "PowerOfTwoChoices", "LeastRequests", "Random", "FirstAlphabetical", "WeightedRandom", "WeightedLeastRequests", "WeightedRoundRobin", "FastestResponse", "SourceIpHash", "PrimaryBackup" },
            backupMetadata = new { key = "TrafficRole", primary = "primary", backup = "backup", @default = "primary", requiresActiveHealth = true },
            weightedMetadata = new { key = "Weight", min = LoadBalancingCore.MinWeight, max = LoadBalancingCore.MaxWeight, @default = 1 },
            adcCoverageScope = "Software feature coverage, not deployment, licensing or physical readiness",
            adcCoverage = AdcCoverage,
            capabilities = Items
        })).RequireAuthorization();
}
