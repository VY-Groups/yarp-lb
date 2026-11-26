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
            try { return ValidatedGslbCandidate(input); }
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
        if (x.RollbackFromRevision is { } previous && (previous < 1 || previous >= x.Revision))
            throw new ArgumentException("Rollback must be prepared as a fresh revision greater than the previously deployed revision.");
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
    private static string KeyReference(string value)
    {
        // Accept an absolute POSIX or drive-qualified Windows reference, not
        // a URI, UNC/device path, relative path, PEM content or traversal.
        if (value.Length is < 2 or > 512 || value.Any(char.IsControl) ||
            value.Contains("-----", StringComparison.Ordinal) ||
            !(value.StartsWith('/') && !value.StartsWith("//", StringComparison.Ordinal) ||
              Regex.IsMatch(value, @"^[A-Za-z]:\\[^\\]")) ||
            value.Split('/', '\\').Any(piece => piece is "." or ".."))
            throw new ArgumentException("DNSSEC requires absolute host key references, never private key contents.");
        return value;
    }
    private static void AddAuthorityDraft(GslbDraftInput x, JsonObject zone)
    {
        var mode = string.IsNullOrEmpty(x.DnssecMode) ? "Disabled" : x.DnssecMode;
        if (mode is not ("Disabled" or "Nsec" or "Nsec3"))
            throw new ArgumentException("Unsupported DNSSEC denial mode.");
        var primary = x.DnssecKeyPath ?? "";
        var prepublish = Rows(x.DnssecPrepublishPaths ?? "", 2, 1).Select(r => KeyReference(r[0])).ToArray();
        var additional = Rows(x.DnssecAdditionalPaths ?? "", 2, 1).Select(r => KeyReference(r[0])).ToArray();
        if (mode == "Disabled")
        {
            if (primary.Length != 0 || prepublish.Length != 0 || additional.Length != 0 ||
                !string.IsNullOrEmpty(x.DnssecSalt) || x.DnssecIterations is not null)
                throw new ArgumentException("Remove signing references and NSEC3 parameters when DNSSEC is disabled.");
        }
        else
        {
            primary = KeyReference(primary);
            var paths = new[] { primary }.Concat(prepublish).Concat(additional).ToArray();
            if (paths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != paths.Length)
                throw new ArgumentException("Active, prepublish and additional signing key references must be distinct.");
            zone["DnssecPrivateKeyPath"] = primary;
            zone["DnssecDenialMode"] = mode;
            if (prepublish.Length > 0) zone["DnssecPrepublishPublicKeyPaths"] = new JsonArray(prepublish.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
            if (additional.Length > 0) zone["DnssecAdditionalSigningKeyPaths"] = new JsonArray(additional.Select(p => (JsonNode?)JsonValue.Create(p)).ToArray());
            if (mode == "Nsec3")
            {
                if (x.DnssecSalt is not { Length: >= 16 and <= 64 } salt || salt.Length % 2 != 0 ||
                    !salt.All(Uri.IsHexDigit) || x.DnssecIterations is null or < 0 or > 50)
                    throw new ArgumentException("NSEC3 requires an explicit 8–32 byte hex salt and 0–50 iterations.");
                zone["DnssecNsec3SaltHex"] = salt.ToUpperInvariant();
                zone["DnssecNsec3Iterations"] = x.DnssecIterations.Value;
            }
            else if (!string.IsNullOrEmpty(x.DnssecSalt) || x.DnssecIterations is not null)
                throw new ArgumentException("Salt and iterations are only valid for NSEC3.");
        }
        var origin = x.Name!.TrimEnd('.');
        var cuts = new Dictionary<string, JsonObject>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in Rows(x.Delegations ?? "", 64, 3))
        {
            var cut = row[0].TrimEnd('.');
            if (!Host(row[0]) || !cut.EndsWith("." + origin, StringComparison.OrdinalIgnoreCase) ||
                !Host(row[1]) || !IPAddress.TryParse(row[2], out var address))
                throw new ArgumentException("Delegation requires a strict child zone, DNS nameserver and unicast address.");
            if (!cuts.TryGetValue(cut, out var entry))
                cuts.Add(cut, entry = new JsonObject { ["Name"] = cut, ["NameServers"] = new JsonArray(), ["DsRecords"] = new JsonArray() });
            var servers = (JsonArray)entry["NameServers"]!;
            if (servers.Count >= 4 || servers.Any(s => string.Equals(s!["Host"]!.GetValue<string>(), row[1].TrimEnd('.'), StringComparison.OrdinalIgnoreCase)))
                throw new ArgumentException("Each delegation permits at most four distinct nameservers in this editor.");
            servers.Add(new JsonObject { ["Host"] = row[1].TrimEnd('.'), ["Address"] = address.ToString() });
        }
        if (cuts.Keys.Any(c => cuts.Keys.Any(other => !c.Equals(other, StringComparison.OrdinalIgnoreCase) &&
                c.EndsWith("." + other, StringComparison.OrdinalIgnoreCase))) ||
            ((JsonArray)zone["NameServers"]!).Any(ns => cuts.Keys.Any(cut =>
                ns!["Host"]!.GetValue<string>().Equals(cut, StringComparison.OrdinalIgnoreCase) ||
                ns["Host"]!.GetValue<string>().EndsWith("." + cut, StringComparison.OrdinalIgnoreCase))))
            throw new ArgumentException("Nested cuts or parent nameservers below a child delegation are unsupported.");
        foreach (var row in Rows(x.DelegationDs ?? "", 64, 5))
        {
            if (mode == "Disabled" || !cuts.TryGetValue(row[0].TrimEnd('.'), out var entry))
                throw new ArgumentException("DS records require a signed parent and a configured delegation.");
            var tag = Integer(row[1], 0, 65535);
            var algorithm = Integer(row[2], 1, 255);
            var digestType = Integer(row[3], 2, 4);
            if (algorithm is not (1 or 3 or 5 or 6 or 7 or 8 or 10 or 12 or 13 or 14 or 15 or 16) ||
                digestType is not (2 or 4) || row[4].Length != (digestType == 2 ? 64 : 96) || !row[4].All(Uri.IsHexDigit))
                throw new ArgumentException("DS requires a supported algorithm and exact SHA-256 or SHA-384 hex digest.");
            var ds = (JsonArray)entry["DsRecords"]!;
            var candidate = new JsonObject { ["KeyTag"] = tag, ["Algorithm"] = algorithm, ["DigestType"] = digestType, ["DigestHex"] = row[4].ToUpperInvariant() };
            if (ds.Count >= 8 || ds.Any(item => JsonNode.DeepEquals(item, candidate)))
                throw new ArgumentException("Duplicate or excessive DS records.");
            ds.Add(candidate);
        }
        if (cuts.Count > 0) zone["Delegations"] = new JsonArray(cuts.Values.Select(v => (JsonNode?)v).ToArray());
    }
    // Untrusted fields may reject draft construction, but cannot choose
    // whether a constructed draft is checked by the signed-agent schema.
    private static IResult ValidatedGslbCandidate(GslbDraftInput input)
    {
        var config = BuildGslbDraft(input);
        if (!EngineConfigContract.Validate("gslb", config, allowPublicBind: false))
            throw new ArgumentException("The existing signed agent staging schema rejected the candidate; check addresses and values.");
        return Candidate(config, "gslb-zone-unsigned.json");
    }
    internal static JsonObject BuildGslbDraft(GslbDraftInput x)
    {
        // Initial loopback configuration; key paths are references only.
        // This process never reads or provisions DNS signing keys.
        // Evaluate every independent input predicate. No supplied field can
        // short-circuit another check, and endpoint authorization is separate.
        var namesValid = Host(x.Name) & Host(x.SoaContact);
        var timingValid = (x.Serial != 0) & (x.Ttl is >= 5 and <= 300) &
            (x.ProbeInterval is >= 1 and <= 60) & (x.FailureThreshold is >= 1 and <= 10) &
            (x.SuccessThreshold is >= 1 and <= 10);
        var policyValid = x.Policy is "Weighted" or "Failover" or "WeightedFailover";
        if (!(namesValid & timingValid & policyValid))
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
        if (names.Count > 4) throw new ArgumentException("At most four authoritative nameservers are supported.");
        if (sites.Count == 0 || servers.Count == 0) throw new ArgumentException("Enter at least one site and authoritative nameserver.");
        var zone = new JsonObject { ["Name"] = x.Name!.TrimEnd('.'), ["SoaContact"] = x.SoaContact!.TrimEnd('.'),
            ["SoaSerial"] = x.Serial, ["TtlSeconds"] = x.Ttl, ["RoutingPolicy"] = x.Policy,
            ["FailureThreshold"] = x.FailureThreshold, ["SuccessThreshold"] = x.SuccessThreshold,
            ["FailClosedWhenAllSitesDown"] = true, ["Sites"] = sites, ["NameServers"] = servers };
        AddAuthorityDraft(x, zone);
        // Safe loopback candidate: operator must review actual interface,
        // authority fencing, DNSSEC and signed activation separately.
        var config = new JsonObject { ["AllowNonLoopbackListeners"] = false, ["ListenHost"] = "127.0.0.1",
            ["ListenPort"] = 15353, ["ProbeIntervalSeconds"] = x.ProbeInterval, ["Zones"] = new JsonArray(zone) };
        if (!string.IsNullOrWhiteSpace(x.BlockedResolverCidrs))
        {
            if (x.BlockedResolverCidrs.Length > 8500)
                throw new ArgumentException("DNS firewall list is too long.");
            var blocked = new JsonArray();
            foreach (var row in Rows(x.BlockedResolverCidrs, 128, 1))
                blocked.Add(JsonValue.Create(row[0]));
            config["BlockedResolverCidrs"] = blocked;
        }
        // ValidatedGslbCandidate applies the exact signed agent schema.
        return config;
    }
}
public sealed record WafDraftInput(long Revision, string? Mode, string? RulesetSha256,
    string? ShadowEvidenceSha256, int ValidDays, string? Exceptions, long? RollbackFromRevision = null);
public sealed record GslbDraftInput(string? Name, string? SoaContact, uint Serial, int Ttl,
    string? Policy, int ProbeInterval, int FailureThreshold, int SuccessThreshold, string? Sites, string? NameServers,
    string? DnssecMode = null, string? DnssecKeyPath = null, string? DnssecPrepublishPaths = null,
    string? DnssecAdditionalPaths = null, string? DnssecSalt = null, int? DnssecIterations = null,
    string? Delegations = null, string? DelegationDs = null, string? BlockedResolverCidrs = null);
public sealed record BackendCertificateCheck(string? Thumbprint);
