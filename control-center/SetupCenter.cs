using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authorization;
using Yarp.ReverseProxy;

/// <summary>
/// Setup and operations-readiness API for YARP Control Center 0.1. Readiness indicators
/// reflect locally observable state. They are NOT declarations of CA production approval.
/// Changing the freeze flag affects local, authorized routing mutations; it is not a
/// distributed fleet lock.
/// </summary>
public static class SetupCenter
{
    public const string ProductVersion = "0.1";
    private static readonly SemaphoreSlim Lock = new(1, 1);
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public sealed record FreezeRequest(bool Frozen, string Reason);
    public sealed record FreezeState(bool Frozen = false, string Reason = "", string UpdatedBy = "", DateTimeOffset? UpdatedUtc = null);

    private static string FreezePath(string stateDir) => Path.Combine(stateDir, "setup-change-freeze.json");
    public static FreezeState ReadFreeze(string stateDir)
    {
        var path = FreezePath(stateDir);
        if (!File.Exists(path)) return new FreezeState();
        try { return JsonSerializer.Deserialize<FreezeState>(File.ReadAllText(path), JsonOptions) ?? new FreezeState(true, "Freeze state invalid: fail closed"); }
        catch { return new FreezeState(true, "Freeze state unreadable: fail closed"); }
    }

    public static void MapSetupCenter(this WebApplication app, string privateDir)
    {
        app.MapGet("/admin/api/setup/version", () => Results.Ok(new
        {
            product = "YARP Control Center", version = ProductVersion,
            channel = "development", deploymentCertified = false,
            yarpPackage = "2.3.0", framework = ".NET 10",
            note = "Version 0.1 is a development baseline; production readiness requires acceptance tests."
        })).RequireAuthorization();

        app.MapGet("/admin/api/setup/overview", (HttpContext ctx) =>
        {
            string file(string name) => Path.Combine(privateDir, name);
            JsonNode? Load(string name)
            {
                try { return File.Exists(file(name)) ? JsonNode.Parse(File.ReadAllText(file(name))) : null; }
                catch { return null; }
            }
            var organization = Load("organization-profile.json");
            var users = Load("admin-users.json") as JsonArray;
            var activeAdmins = users?.Count(x => !string.Equals(x?["Enabled"]?.ToString(), "false", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(x?["Role"]?.ToString(), "Administrator", StringComparison.OrdinalIgnoreCase)) ?? 0;
            var mail = Load("mail-settings.json");
            var directory = Load("active-directory.json");
            var topology = Load("onboarding-topology.json");
            var fleet = Load("fleet-gateways.json") as JsonArray;
            var proxy = app.Configuration.GetSection("ReverseProxy");
            var clusters = proxy.GetSection("Clusters").GetChildren().ToArray();
            var routeCount = proxy.GetSection("Routes").GetChildren().Count();
            var destinationCount = clusters.Sum(c => c.GetSection("Destinations").GetChildren().Count());
            var activeChecks = clusters.Count(c => bool.TryParse(c.GetSection("HealthCheck:Active:Enabled").Value, out var v) && v);
            var mode = topology?["Plan"]?["Mode"]?.ToString() ?? "unselected";
            var confirmed = string.Equals(topology?["Status"]?.ToString(), "design-confirmed", StringComparison.OrdinalIgnoreCase);
            var mailEnabled = bool.TryParse(mail?["Enabled"]?.ToString(), out var m) && m;
            var directoryEnabled = bool.TryParse(directory?["Enabled"]?.ToString(), out var d) && d;
            var stages = new object[]
            {
                Stage("organization", "Organization profile", !string.IsNullOrWhiteSpace(organization?["organizationName"]?.ToString()) ? "configured" : "action-required",
                    string.IsNullOrWhiteSpace(organization?["organizationName"]?.ToString()) ? "Set your organization and industry profile" : organization!["organizationName"]!.ToString(), "organization"),
                Stage("administrator", "Recovery administrator", activeAdmins > 0 ? "configured" : "action-required",
                    $"{activeAdmins} active local/directory administrator account(s)", "users"),
                Stage("topology", "Architecture and ingress", confirmed ? "design-confirmed" : "action-required",
                    confirmed ? $"{mode} topology saved (design only)" : "Save and confirm the topology design", "onboarding"),
                Stage("mail", "SMTP and email OTP", mailEnabled ? "configured-unverified" : "optional",
                    mailEnabled ? "Enabled in configuration; verify actual mailbox delivery" : "Configure the approved internal SMTP relay", "mail"),
                Stage("directory", "Active Directory / LDAPS", directoryEnabled ? "configured-unverified" : "optional",
                    directoryEnabled ? "LDAPS enabled; verify DC trust and group mapping" : "Configure directory connection and role groups", "directory"),
                Stage("routing", "YARP routes and clusters", routeCount > 0 && destinationCount > 0 ? "configured-unverified" : "action-required",
                    $"{routeCount} route(s), {clusters.Length} cluster(s), {destinationCount} enabled destination(s)", "routes"),
                Stage("health", "Destination readiness policies", clusters.Length > 0 && activeChecks == clusters.Length ? "configured-unverified" : "action-required",
                    $"{activeChecks}/{clusters.Length} clusters with active health checks; app endpoints must be tested", "health"),
                Stage("fleet", "Gateway fleet", mode == "standalone" ? "not-applicable" : (fleet?.Count ?? 0) >= 2 ? "registered-unverified" : "action-required",
                    $"{fleet?.Count ?? 0} gateway agent record(s); registration is not enrollment", "fleet"),
                Stage("change-control", "Two-person routing approval", "implemented-needs-test",
                    "Route/cluster changes use submit-review-approval; run two-user acceptance test", "approvals"),
                Stage("security", "Management transport and identity", ctx.Request.IsHttps ? "https-session-unverified" : "lab-only",
                    ctx.Request.IsHttps ? "HTTPS session observed; certificate/RBAC review pending" : "Loopback HTTP test only; do not expose remotely", "users"),
                Stage("audit", "Independent immutable audit", "not-implemented",
                    "Local JSONL audit exists; WORM/retention-protected export is not connected", "backups"),
                Stage("deployment", "Remote onboarding and service deployment", "not-implemented",
                    "Remote service provisioning needs approved agent and verified fleet workflow", "fleet"),
                Stage("sso", "Enterprise SSO with phishing-resistant MFA", "not-implemented",
                    "LDAPS password + email OTP is not OIDC/FIDO2 SSO", "directory")
            };
            return Results.Ok(new {
                version = ProductVersion, channel = "development", verifiedForProduction = false,
                gateway = Environment.MachineName, mode,
                topologyConfirmed = confirmed, routeCount, clusterCount = clusters.Length, destinationCount,
                activeHealthClusterCount = activeChecks, fleetEntries = fleet?.Count ?? 0,
                transport = ctx.Request.IsHttps ? "https" : "http-loopback",
                freeze = ReadFreeze(privateDir), stages,
                note = "Configured != live/healthy. Unverified steps require operator evidence. No live traffic is altered by this GET endpoint."
            });
        }).RequireAuthorization();

        app.MapGet("/admin/api/setup/freeze", () => Results.Ok(ReadFreeze(privateDir)))
            .RequireAuthorization();

        app.MapPost("/admin/api/setup/freeze", async (HttpContext ctx, FreezeRequest input) =>
        {
            if (string.IsNullOrWhiteSpace(input.Reason) || input.Reason.Trim().Length is < 12 or > 500)
                return Results.BadRequest(new { error = "Provide a change-control reason of 12–500 characters." });
            if (ctx.Request.ContentLength is > 4096)
                return Results.BadRequest(new { error = "Request is too large" });
            await Lock.WaitAsync(ctx.RequestAborted);
            try
            {
                var prior = ReadFreeze(privateDir);
                var next = new FreezeState(input.Frozen, input.Reason.Trim(), ctx.User.Identity?.Name ?? "unknown", DateTimeOffset.UtcNow);
                var path = FreezePath(privateDir);
                if (File.Exists(path)) File.Copy(path, path + ".previous", overwrite: true);
                var tmp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try { await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(next, JsonOptions), ctx.RequestAborted); File.Move(tmp, path, overwrite: true); }
                finally { if (File.Exists(tmp)) File.Delete(tmp); }
                var record = new { utc = DateTimeOffset.UtcNow, actor = next.UpdatedBy,
                    action = input.Frozen ? "ROUTING_CHANGE_FREEZE_ENABLED" : "ROUTING_CHANGE_FREEZE_DISABLED",
                    details = new { previous = prior.Frozen, current = next.Frozen, next.Reason } };
                await File.AppendAllTextAsync(Path.Combine(privateDir, "admin-audit.jsonl"),
                    JsonSerializer.Serialize(record) + Environment.NewLine, ctx.RequestAborted);
                return Results.Ok(next);
            }
            finally { Lock.Release(); }
        }).RequireAuthorization(p => p.RequireRole("Administrator"));

        // These are YARP's in-memory ACTIVE and PASSIVE destination states, not synthetic probes.
        // Unknown is a genuine state until policy probes/observes traffic. Values are per gateway.
        app.MapGet("/admin/api/runtime/destinations", (IProxyStateLookup lookup) =>
        {
            var clusters = lookup.GetClusters().Select(c => new {
                clusterId = c.ClusterId,
                destinations = c.Destinations.Values.Select(d => new {
                    destinationId = d.DestinationId,
                    activeHealth = d.Health.Active.ToString(),
                    passiveHealth = d.Health.Passive.ToString(),
                    concurrentRequests = d.ConcurrentRequestCount
                }).OrderBy(x => x.destinationId).ToArray()
            }).OrderBy(x => x.clusterId).ToArray();
            return Results.Ok(new { timestampUtc = DateTimeOffset.UtcNow, source = "YARP runtime state (local instance)", clusters });
        }).RequireAuthorization();
    }

    private static object Stage(string id, string title, string status, string evidence, string action) =>
        new { id, title, status, evidence, action };
}
