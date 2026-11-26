using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Mvc;

// Candidate generation only. No signing keys, deployment, file writes,
// external probes, authority changes, or direct live configuration mutation.
public static class SpecialistDrafts
{
    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };
    private static bool Id(string? s) => s is not null && Regex.IsMatch(s, "^[A-Za-z0-9_.-]{3,64}$", RegexOptions.CultureInvariant);
    private static bool Hash(string? s) => s is not null && Regex.IsMatch(s, "^[A-F0-9]{64}$", RegexOptions.CultureInvariant);
    private static bool Host(string? s) => s is { Length: > 0 and <= 253 } &&
        s.TrimEnd('.').Split('.').All(x => x.Length is > 0 and <= 63 &&
            Regex.IsMatch(x, "^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?$", RegexOptions.CultureInvariant));
    private static bool LiteralPath(string s) => s.Length is >= 1 and <= 256 && s.StartsWith('/') &&
        !s.Contains("//", StringComparison.Ordinal) && !s.Split('/').Any(x => x is "." or "..") &&
        s.All(ch => ch >= 33 && ch <= 126 && !"*?#{\\}%;:".Contains(ch));
    private static string Utc(DateTimeOffset t) => t.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    private static string[][] Rows(string? raw, int max, int columns)
    {
        if (raw is null || raw.Length > 32000) throw new ArgumentException("Invalid or oversized rows.");
        var rows = raw.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(s => s.Split('|', StringSplitOptions.TrimEntries)).ToArray();
        if (rows.Length > max || rows.Any(x => x.Length != columns))
            throw new ArgumentException($"Use at most {max} rows with exactly {columns} pipe-separated fields.");
        return rows;
    }
    private static int Integer(string s, int min, int max) =>
        int.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n >= min && n <= max
            ? n : throw new ArgumentException($"Expected an integer from {min} to {max}.");
    private static IResult Candidate(JsonNode value, string filename)
    {
        var json = value.ToJsonString(Pretty) + "\n";
        var bytes = System.Text.Encoding.UTF8.GetBytes(json);
        // The offline WAF verifier accepts at most 64 KiB; enforce a
        // common bounded export and hash the exact UTF-8 bytes for review.
        if (bytes.Length > 65536)
            throw new ArgumentException("Serialized candidate exceeds 64 KiB.");
        return Results.Ok(new { filename, json, byteLength = bytes.Length,
            sha256 = Convert.ToHexString(SHA256.HashData(bytes)),
            status = "unsigned-draft-only", deploymentReady = false });
    }
    private static IResult Bad(Exception ex) => Results.BadRequest(new { error = ex.Message });

    public static void MapSpecialistDrafts(this WebApplication app)
    {
        app.MapPost("/admin/api/specialist/waf-draft", (WafDraftInput input) =>
        {
            try { return Candidate(Waf(input), "waf-policy-unsigned.json"); }
            catch (ArgumentException ex) { return Bad(ex); }
        }).WithMetadata(new RequestSizeLimitAttribute(65536))
          .RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
        app.MapPost("/admin/api/specialist/gslb-draft", (GslbDraftInput input) =>
        {
            try { return Candidate(Gslb(input), "gslb-zone-unsigned.json"); }
            catch (ArgumentException ex) { return Bad(ex); }
        }).WithMetadata(new RequestSizeLimitAttribute(65536))
          .RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
        app.MapPost("/admin/api/specialist/backend-certificate-check", (BackendCertificateCheck input) =>
        {
            if (!BackendMutualTls.TryNormalizeThumbprint(input.Thumbprint, out var canonical))
                return Results.BadRequest(new { error = "Enter an installed certificate's 40-hex thumbprint." });
            try
            {
                using var certificate = BackendMutualTls.Resolve(canonical);
                return Results.Ok(new { thumbprint = canonical, subject = certificate.Subject,
                    notAfterUtc = certificate.NotAfter.ToUniversalTime(), localResolverAccepted = true,
                    scope = "Local backend client certificate resolution only; remote trust and actual handshake not verified." });
            }
            catch (Exception ex) when (ex is CryptographicException or InvalidOperationException or
                PlatformNotSupportedException or UnauthorizedAccessException)
            {
                return Results.BadRequest(new { error = "Local certificate resolution failed. Check store, trust, validity, private key access and Client Authentication EKU." });
            }
        }).WithMetadata(new RequestSizeLimitAttribute(4096))
          .RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
    }
    internal static JsonObject Waf(WafDraftInput x)
    {
        if (x.Revision is < 1 or > 9007199254740992L || x.Mode is not ("detect" or "block") ||
            !Hash(x.RulesetSha256) || x.ValidDays is < 1 or > 45 ||
            (x.Mode == "block" ? !Hash(x.ShadowEvidenceSha256) : !string.IsNullOrEmpty(x.ShadowEvidenceSha256)))
            throw new ArgumentException("Enter a positive revision, observed uppercase ruleset digest, validity (1–45 days) and blocking evidence digest only for block mode.");
        var now = DateTimeOffset.UtcNow;
        var expires = now.AddDays(x.ValidDays);
        var exceptions = new JsonArray();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Rows(x.Exceptions ?? "", 64, 9))
        {
            if (!Id(r[0]) || !Id(r[1]) || !Id(r[2]) || !seen.Add(r[0]) ||
                r[3] is not ("GET" or "POST") || !LiteralPath(r[4]) ||
                r[5] is not ("application/json" or "application/xml" or "application/pkix-cert" or "text/plain" or "application/octet-stream") ||
                r[7].Length is < 10 or > 256)
                throw new ArgumentException("Invalid scoped exception: require unique ID, owner, route, GET/POST, literal path, supported content type and a 10–256 character reason.");
            var days = Integer(r[8], 1, Math.Min(30, x.ValidDays));
            exceptions.Add(new JsonObject { ["exceptionId"] = r[0], ["owner"] = r[1], ["routeId"] = r[2],
                ["httpMethod"] = r[3], ["path"] = r[4], ["contentType"] = r[5],
                ["ruleId"] = Integer(r[6], 1, 9999999), ["reason"] = r[7],
                ["issuedAtUtc"] = Utc(now), ["expiresAtUtc"] = Utc(now.AddDays(days)) });
        }
        return new JsonObject { ["schemaVersion"] = 1, ["revision"] = x.Revision, ["mode"] = x.Mode,
            ["rulesetSha256"] = x.RulesetSha256, ["shadowEvidenceSha256"] = x.Mode == "block" ? x.ShadowEvidenceSha256 : null,
            ["issuedAtUtc"] = Utc(now), ["expiresAtUtc"] = Utc(expires), ["exceptions"] = exceptions };
    }
    internal static JsonObject Gslb(GslbDraftInput x)
    {
        // Restricted initial zone builder. Advanced DNSSEC, ECS and authority
        // settings must be incorporated through the separate signed workflow.
        if (!Host(x.Name) || !Host(x.SoaContact) || x.Serial == 0 || x.Ttl is < 5 or > 300 ||
            x.Policy is not ("Weighted" or "Failover" or "WeightedFailover") ||
            x.ProbeInterval is < 1 or > 60 || x.FailureThreshold is < 1 or > 10 || x.SuccessThreshold is < 1 or > 10)
            throw new ArgumentException("Enter valid zone/SOA DNS names, positive serial, TTL (5–300), health intervals and a supported policy.");
        var sites = new JsonArray();
        var addresses = new HashSet<IPAddress>();
        foreach (var r in Rows(x.Sites, 16, 4))
        {
            if (!IPAddress.TryParse(r[0], out var address) || !addresses.Add(address) ||
                !Uri.TryCreate(r[1], UriKind.Absolute, out var uri) || uri.Scheme != "https" ||
                uri.UserInfo.Length != 0 || uri.Fragment.Length != 0 || uri.Query.Length != 0)
                throw new ArgumentException("Sites require distinct IP addresses and HTTPS readiness URLs without credentials, query or fragment.");
            sites.Add(new JsonObject { ["Address"] = address.ToString(), ["HealthUrl"] = uri.AbsoluteUri,
                ["Weight"] = Integer(r[2], 1, 100), ["Priority"] = Integer(r[3], 0, 1000) });
        }
        var servers = new JsonArray();
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in Rows(x.NameServers, 8, 2))
        {
            if (!Host(r[0]) || !names.Add(r[0].TrimEnd('.')) || !IPAddress.TryParse(r[1], out var address))
                throw new ArgumentException("Nameservers require distinct DNS names and IP addresses.");
            servers.Add(new JsonObject { ["Host"] = r[0].TrimEnd('.'), ["Address"] = address.ToString() });
        }
        if (sites.Count == 0 || servers.Count == 0) throw new ArgumentException("Enter at least one site and authoritative nameserver.");
        var zone = new JsonObject { ["Name"] = x.Name!.TrimEnd('.'), ["SoaContact"] = x.SoaContact!.TrimEnd('.'),
            ["SoaSerial"] = x.Serial, ["TtlSeconds"] = x.Ttl, ["RoutingPolicy"] = x.Policy,
            ["FailureThreshold"] = x.FailureThreshold, ["SuccessThreshold"] = x.SuccessThreshold,
            ["FailClosedWhenAllSitesDown"] = true, ["Sites"] = sites, ["NameServers"] = servers };
        // Safe loopback candidate: operator must review actual interface,
        // authority fencing, DNSSEC and signed activation separately.
        var config = new JsonObject { ["AllowNonLoopbackListeners"] = false, ["ListenHost"] = "127.0.0.1",
            ["ListenPort"] = 15353, ["ProbeIntervalSeconds"] = x.ProbeInterval, ["Zones"] = new JsonArray(zone) };
        if (!EngineConfigContract.Validate("gslb", config, allowPublicBind: false))
            throw new ArgumentException("The existing signed agent staging schema rejected the candidate; check addresses and values.");
        return config;
    }
}
public sealed record WafDraftInput(long Revision, string? Mode, string? RulesetSha256,
    string? ShadowEvidenceSha256, int ValidDays, string? Exceptions);
public sealed record GslbDraftInput(string? Name, string? SoaContact, uint Serial, int Ttl,
    string? Policy, int ProbeInterval, int FailureThreshold, int SuccessThreshold, string? Sites, string? NameServers);
public sealed record BackendCertificateCheck(string? Thumbprint);
