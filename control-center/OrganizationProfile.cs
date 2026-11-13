using System.Security.Claims;
using System.Text.Json;
using System.Text.RegularExpressions;

/// <summary>
/// Single-organization branding/profile for one local controller deployment.
/// Does NOT create multi-tenant authorization, configure traffic, or grant network access.
/// </summary>
public static class OrganizationProfileModule
{
    public sealed record Profile(
        string OrganizationName = "",
        string Sector = "general",
        string Region = "unspecified",
        string Notes = "",
        long Revision = 0,
        string UpdatedBy = "",
        DateTimeOffset? UpdatedUtc = null);
    public sealed record Update(string OrganizationName, string Sector, string Region, string Notes, long ExpectedRevision);

    private static readonly HashSet<string> Sectors = new(StringComparer.Ordinal)
    {
        "general", "finance", "healthcare", "government", "telecom",
        "ecommerce", "education", "ca-pki", "technology", "other"
    };
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private static string ProfilePath(string dir) => Path.Combine(dir, "organization-profile.json");
    public static Profile Read(string dir)
    {
        var path = ProfilePath(dir);
        if (!File.Exists(path)) return new Profile();
        // A corrupt profile must not be silently reset and overwritten.
        return JsonSerializer.Deserialize<Profile>(File.ReadAllText(path), Json)
               ?? throw new InvalidDataException("Organization profile is empty");
    }

    public static string? Validate(Update input)
    {
        if (input is null) return "Profile is required";
        var name = input.OrganizationName?.Trim() ?? "";
        if (name.Length is < 3 or > 100 || name.Any(char.IsControl))
            return "Organization name must be 3–100 characters without control characters";
        if (!Sectors.Contains(input.Sector ?? "")) return "Unrecognized organization sector";
        if (!Regex.IsMatch(input.Region ?? "", @"^[A-Za-z0-9 ._/-]{2,60}$"))
            return "Region must be 2–60 characters (letters, digits, spaces, . _ / -)";
        if ((input.Notes?.Length ?? 0) > 250 || (input.Notes ?? "").Any(char.IsControl))
            return "Notes must be at most 250 characters without control characters";
        if (input.ExpectedRevision < 0) return "Invalid revision";
        return null;
    }

    public static void MapOrganizationProfile(this WebApplication app, string stateDir)
    {
        app.MapGet("/admin/api/organization", () => Results.Ok(Read(stateDir)))
            .RequireAuthorization();
        app.MapGet("/admin/api/organization/sectors", () => Results.Ok(new {
            sectors = Sectors.OrderBy(x => x).ToArray(),
            scope = "Single organization per controller; industry profiles are labels, not automatic policy enforcement",
            multiTenantIsolation = false
        })).RequireAuthorization();
        app.MapPut("/admin/api/organization", async (HttpContext ctx, Update input) =>
        {
            var validation = Validate(input);
            if (validation != null) return (IResult)Results.BadRequest(new { error = validation });
            await Gate.WaitAsync(ctx.RequestAborted);
            try
            {
                var previous = Read(stateDir);
                if (previous.Revision != input.ExpectedRevision)
                    return (IResult)Results.Conflict(new { error = "Profile revision changed; reload before saving", currentRevision = previous.Revision });
                var next = new Profile(input.OrganizationName.Trim(), input.Sector,
                    input.Region.Trim(), (input.Notes ?? "").Trim(), previous.Revision + 1,
                    ctx.User.Identity?.Name ?? "unknown", DateTimeOffset.UtcNow);
                var dest = ProfilePath(stateDir);
                var tmp = dest + "." + Guid.NewGuid().ToString("N") + ".tmp";
                try
                {
                    await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(next, Json), ctx.RequestAborted);
                    File.Move(tmp, dest, true);
                }
                finally { if (File.Exists(tmp)) File.Delete(tmp); }
                // Local audit is informative, NOT independently immutable evidence.
                var audit = new { utc = DateTimeOffset.UtcNow, actor = next.UpdatedBy,
                    action = "ORGANIZATION_PROFILE_UPDATED", revision = next.Revision,
                    organizationName = next.OrganizationName, sector = next.Sector };
                await File.AppendAllTextAsync(Path.Combine(stateDir, "admin-audit.jsonl"),
                    JsonSerializer.Serialize(audit, Json) + Environment.NewLine, ctx.RequestAborted);
                return (IResult)Results.Ok(next);
            }
            finally { Gate.Release(); }
        }).RequireAuthorization(p => p.RequireRole("Administrator"));
    }
}
