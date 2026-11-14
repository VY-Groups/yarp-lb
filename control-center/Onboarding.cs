using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;

// 0.1: Topology DESIGN only. This API deliberately does not edit running YARP
// routes, enroll gateways, install services, open ports, or connect databases.
public static class OnboardingApi
{
    private static readonly SemaphoreSlim WriteGate = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = true, WriteIndented = true
    };

    public static bool IsDesignConfirmed(string privateDir) =>
        ReadState(Path.Combine(privateDir, "onboarding-topology.json")).Status == "design-confirmed";

    public static bool IsMultiGatewayDesign(string privateDir)
    {
        var state = ReadState(Path.Combine(privateDir, "onboarding-topology.json"));
        return state.Status == "design-confirmed" && (state.Plan.Mode is "ha-pair" or "fleet");
    }

    public static void MapOnboardingApi(this WebApplication app, string privateDir)
    {
        var statePath = Path.Combine(privateDir, "onboarding-topology.json");
        var backupDir = Path.Combine(privateDir, "onboarding-backups");
        var auditPath = Path.Combine(privateDir, "admin-audit.jsonl");

        app.MapGet("/admin/api/onboarding", () =>
        {
            var state = ReadState(statePath);
            return Results.Ok(Describe(state, statePath));
        }).RequireAuthorization();

        app.MapPost("/admin/api/onboarding/validate", (OnboardingInput input) =>
        {
            if (input.Plan == null) return Results.BadRequest(new { error = "Missing plan" });
            var issues = Validate(input.Plan, true);
            return Results.Ok(new { issues, warnings = Warnings(input.Plan), effect = "design-only" });
        }).RequireAuthorization(p => p.RequireRole("Administrator"));

        app.MapPost("/admin/api/onboarding", async (HttpContext http, OnboardingInput input) =>
        {
            if (input.Plan is null) return Results.BadRequest(new { error = "Plan is required" });
            // Limit the size and breadth of metadata independent of request size limits.
            var json = JsonSerializer.Serialize(input.Plan, JsonOptions);
            if (json.Length > 96_000) return Results.BadRequest(new { error = "Topology exceeds 96 KB" });
            var issues = Validate(input.Plan, input.ConfirmDesign);
            if (issues.Count != 0) return Results.BadRequest(new { error = "Topology validation failed", issues });
            await WriteGate.WaitAsync(http.RequestAborted);
            try
            {
                var revision = CurrentRevision(statePath);
                if (!string.Equals(input.ExpectedRevision, revision, StringComparison.Ordinal))
                    return Results.Conflict(new { error = "Topology was changed by another administrator. Refresh the setup page.", revision });
                // A saved design is not a deployed fleet and does not indicate network readiness.
                var next = new OnboardingState
                {
                    SchemaVersion = 1,
                    Status = input.ConfirmDesign ? "design-confirmed" : "draft",
                    Plan = input.Plan,
                    UpdatedUtc = DateTimeOffset.UtcNow,
                    UpdatedBy = http.User.Identity?.Name ?? "unknown"
                };
                Directory.CreateDirectory(backupDir);
                if (File.Exists(statePath))
                {
                    var backup = Path.Combine(backupDir, $"topology-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffffZ}.json");
                    File.Copy(statePath, backup, overwrite: false);
                }
                var temp = statePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    await File.WriteAllTextAsync(temp, JsonSerializer.Serialize(next, JsonOptions), http.RequestAborted);
                    File.Move(temp, statePath, overwrite: true);
                }
                finally { if (File.Exists(temp)) File.Delete(temp); }
                await File.AppendAllTextAsync(auditPath,
                    JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, actor = next.UpdatedBy,
                        action = input.ConfirmDesign ? "TOPOLOGY_DESIGN_CONFIRMED" : "TOPOLOGY_DRAFT_SAVED",
                        details = new { mode = next.Plan.Mode, gatewayCount = next.Plan.Gateways.Count,
                            workloadCount = next.Plan.Workloads.Count, note = "No YARP routes or Windows services changed" } }) + Environment.NewLine);
                return Results.Ok(Describe(next, statePath));
            }
            finally { WriteGate.Release(); }
        }).RequireAuthorization(p => p.RequireRole("Administrator"));
    }

    private static object Describe(OnboardingState state, string statePath) => new
    {
        state.SchemaVersion, state.Status, state.Plan, state.UpdatedBy, state.UpdatedUtc,
        revision = CurrentRevision(statePath),
        issues = Validate(state.Plan, true), warnings = Warnings(state.Plan),
        effect = "Design metadata only; no changes to YARP, Windows services, firewall, Pgpool, or PostgreSQL",
        operationallyVerified = false
    };

    private static string CurrentRevision(string path) => File.Exists(path)
        ? Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) : "EMPTY";

    private static OnboardingState ReadState(string path) => File.Exists(path)
        ? JsonSerializer.Deserialize<OnboardingState>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidDataException("Topology state file is invalid")
        : new OnboardingState();

    private static List<string> Validate(OnboardingPlan p, bool complete)
    {
        var issues = new List<string>();
        if (p.Mode is not ("standalone" or "ha-pair" or "fleet")) issues.Add("Select standalone, HA pair, or fleet topology.");
        if (p.ControlPlane is not ("local" or "single-controller" or "ha-controller")) issues.Add("Invalid control-plane strategy.");
        if (p.DataStore is not ("local-file" or "postgresql")) issues.Add("Invalid management data-store choice.");
        if (p.AccessPattern is not ("segmented" or "shared-restricted")) issues.Add("Invalid public/internal access pattern.");
        if (p.Gateways is null || p.Gateways.Count > 20) issues.Add("Gateway inventory is missing or exceeds 20 entries.");
        if (p.Workloads is null || p.Workloads.Count > 80) issues.Add("Application inventory is missing or exceeds 80 entries.");
        if (p.Notes?.Length > 2000) issues.Add("Notes must be 2,000 characters or less.");
        if (p.PublicVip?.Length > 255 || p.PgpoolEndpoint?.Length > 255 || p.PostgresEndpoint?.Length > 255) issues.Add("Endpoint fields must be under 256 characters.");
        if (!string.IsNullOrWhiteSpace(p.PublicVip) && !ValidHostname(p.PublicVip)) issues.Add("VIP must be a hostname or IP address, without scheme/port.");
        if (p.RequireIndependentApproval == false) issues.Add("Independent change approval cannot be disabled for this CA profile.");
        if (p.Gateways is not null)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var g in p.Gateways)
            {
                if (g is null) { issues.Add("Gateway record cannot be null."); continue; }
                if (!ValidId(g.Id)) issues.Add("Each gateway requires an ID of 1–64 letters, digits, hyphens or underscores.");
                if (!seen.Add(g.Id)) issues.Add($"Duplicate gateway ID: {g.Id}");
                if ((g.Hostname?.Length ?? 0) > 255 || (g.AgentUrl?.Length ?? 0) > 500) issues.Add("Gateway hostname or agent URL is too long.");
                if (!string.IsNullOrWhiteSpace(g.Hostname) && !ValidHostname(g.Hostname)) issues.Add($"Gateway {g.Id}: hostname must be a DNS name or IP address.");
                if (!string.IsNullOrWhiteSpace(g.AgentUrl) && !ValidHttpsOrigin(g.AgentUrl)) issues.Add($"Gateway {g.Id}: agent URL must be a valid HTTPS origin without credentials, query or fragment.");
            }
        }
        if (p.Workloads is not null)
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var w in p.Workloads)
            {
                if (w is null) { issues.Add("Application destination cannot be null."); continue; }
                if (!ValidId(w.Id)) issues.Add("Each application destination requires a valid ID.");
                if (!seen.Add(w.Id)) issues.Add($"Duplicate application destination ID: {w.Id}");
                if ((w.Application?.Length ?? 0) > 100) issues.Add("Application name exceeds 100 characters.");
                if (w.Zone is not ("public" or "restricted" or "trust")) issues.Add($"Invalid exposure zone for {w.Id}");
                if (!string.IsNullOrWhiteSpace(w.Url) && !ValidBackendUrl(w.Url)) issues.Add($"{w.Id}: invalid HTTP(S) backend URL.");
            }
        }
        if (!complete) return issues;
        var gatewayCount = p.Gateways?.Count ?? 0;
        if (p.Mode == "standalone" && gatewayCount != 1) issues.Add("Standalone requires exactly one YARP gateway.");
        if (p.Mode == "ha-pair" && gatewayCount != 2) issues.Add("HA pair requires exactly two YARP gateways.");
        if (p.Mode == "fleet" && gatewayCount < 3) issues.Add("Fleet requires three or more gateways.");
        if (p.Mode == "standalone" && p.ControlPlane != "local") issues.Add("Standalone uses local management in this design.");
        if (p.Mode != "standalone" && p.ControlPlane == "local") issues.Add("Multi-gateway design needs a separate controller strategy.");
        if (p.Mode != "standalone" && (string.IsNullOrWhiteSpace(p.PublicVip) || !p.UpstreamHealthAware))
            issues.Add("HA/fleet needs a named upstream health-aware load-balancer/VIP design.");
        if (p.Gateways != null && p.Gateways.Any(g => g is null || string.IsNullOrWhiteSpace(g.Hostname)))
            issues.Add("Gateway hostnames are required to confirm the design.");
        if (p.Mode != "standalone" && p.Gateways != null && p.Gateways.Any(g => g is null || string.IsNullOrWhiteSpace(g.AgentUrl)))
            issues.Add("Every remote gateway needs a planned HTTPS agent origin.");
        // A single-node laptop or standalone gateway can be tested against one IIS,
        // Apache, Nginx or other HTTP(S) origin. Multi-gateway designs retain
        // their two-destination Active-Active contract.
        var minimumWorkloads = p.Mode == "standalone" ? 1 : 2;
        if (p.Workloads == null || p.Workloads.Count < minimumWorkloads)
            issues.Add(p.Mode == "standalone"
                ? "Standalone requires at least one HTTP(S) application destination."
                : "At least two application destinations are required for the selected Active–Active application design.");
        else
        {
            if (p.Workloads.Any(w => w is null || string.IsNullOrWhiteSpace(w.Application) || string.IsNullOrWhiteSpace(w.Url)))
                issues.Add("Every application destination requires an application name and URL.");
            if (p.Mode != "standalone" &&
                !p.Workloads.Where(w => w is not null).GroupBy(w => w.Application ?? "", StringComparer.OrdinalIgnoreCase).Any(g => g.Count() >= 2))
                issues.Add("At least one application group must have two destinations for Active–Active serving.");
        }
        return issues;
    }

    private static string[] Warnings(OnboardingPlan p)
    {
        var messages = new List<string>
        {
            "Confirmation saves topology metadata; it does not deploy YARP, change firewall NAT, or enroll gateway agents.",
            "Existing Pgpool-II/PostgreSQL routing and CA trust services remain unchanged."
        };
        if (p.Mode != "standalone") messages.Add("YARP instances are Active–Active data-plane proxies; controller leader/standby is a separate, not-yet-activated management-plane design.");
        if (p.Mode != "standalone" && p.DataStore == "local-file") messages.Add("A shared resilient control-plane database is recommended before production operation; this wizard currently persists local metadata only.");
        if (p.DataStore == "postgresql") messages.Add("PostgreSQL is selected for the future management store, but this release does not connect to or migrate a database.");
        if (p.AccessPattern == "shared-restricted") messages.Add("Shared gateway machines require distinct, firewall-protected public and internal listeners; hostname routing alone does not isolate internal services.");
        if (p.Workloads?.Any(w => w != null && w.Zone == "trust") == true) messages.Add("OCSP/CRL endpoints require independent PKI protocol and cache validation before cutover.");
        return messages.ToArray();
    }

    private static bool ValidId(string? id) => id is not null && Regex.IsMatch(id, "^[a-zA-Z0-9_-]{1,64}$");
    private static bool ValidHostname(string value) =>
        IPAddress.TryParse(value, out _) ||
        (value.Length <= 253 && value.Split('.').All(part => part.Length is > 0 and <= 63 &&
          Regex.IsMatch(part, "^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$")));
    private static bool ValidHttpsOrigin(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var uri)) return false;
        return uri.Scheme == "https" && uri.UserInfo.Length == 0 && uri.Query.Length == 0 &&
            uri.Fragment.Length == 0 && uri.AbsolutePath == "/" && uri.Host.Length > 0 && raw.Length <= 500;
    }
    private static bool ValidBackendUrl(string raw)
    {
        if (!Uri.TryCreate(raw, UriKind.Absolute, out var u)) return false;
        return (u.Scheme == "https" || u.Scheme == "http") && u.UserInfo.Length == 0 && u.Query.Length == 0 && u.Fragment.Length == 0 &&
            u.AbsolutePath == "/" && u.Host.Length > 0 && raw.Length <= 500;
    }
}

public sealed class OnboardingInput
{
    public string ExpectedRevision { get; set; } = "EMPTY";
    public bool ConfirmDesign { get; set; }
    public OnboardingPlan? Plan { get; set; }
}
public sealed class OnboardingState
{
    public int SchemaVersion { get; set; } = 1;
    public string Status { get; set; } = "not-started";
    public OnboardingPlan Plan { get; set; } = new();
    public DateTimeOffset? UpdatedUtc { get; set; }
    public string UpdatedBy { get; set; } = "";
}
public sealed class OnboardingPlan
{
    public string Mode { get; set; } = "standalone";
    public string ControlPlane { get; set; } = "local";
    public string DataStore { get; set; } = "local-file";
    public string AccessPattern { get; set; } = "segmented";
    public string PublicVip { get; set; } = "";
    public bool UpstreamHealthAware { get; set; }
    public bool RequireIndependentApproval { get; set; } = true;
    public bool OfflineEnvironment { get; set; } = true;
    public string PgpoolEndpoint { get; set; } = "";
    public string PostgresEndpoint { get; set; } = "";
    public string Notes { get; set; } = "";
    public List<OnboardingGateway> Gateways { get; set; } = new() { new() { Id = "yarp-01" } };
    public List<OnboardingWorkload> Workloads { get; set; } = new();
}
public sealed class OnboardingGateway
{
    public string Id { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string AgentUrl { get; set; } = "";
}
public sealed class OnboardingWorkload
{
    public string Id { get; set; } = "";
    public string Application { get; set; } = "";
    public string Url { get; set; } = "";
    public string Zone { get; set; } = "public";
}
