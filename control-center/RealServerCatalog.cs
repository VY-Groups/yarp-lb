using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>Independent named HTTP(S) origin templates. Assignments are explicit
/// snapshots, not a hidden runtime address rewrite or automatic deployment.</summary>
public static class RealServerCatalog
{
    public const string PayloadKey = "realServers";
    public const string StorageKey = "AdminRealServers";

    public static bool ValidOrigin(string? value) =>
        value is { Length: > 0 and <= 2048 } &&
        !value.Any(char.IsControl) && !value.Contains('\\') &&
        Uri.TryCreate(value, UriKind.Absolute, out var uri) &&
        uri.Scheme is "http" or "https" &&
        !string.IsNullOrWhiteSpace(uri.Host) && uri.UserInfo.Length == 0 &&
        uri.Query.Length == 0 && uri.Fragment.Length == 0 &&
        value.EndsWith("/", StringComparison.Ordinal);

    public static string? Validate(JsonObject payload)
    {
        if (!payload.ContainsKey(PayloadKey)) return null;
        if (payload[PayloadKey] is not JsonObject servers || servers.Count > 200)
            return "Real server catalog must contain at most 200 named servers.";
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, node) in servers)
        {
            if (!Regex.IsMatch(id, @"\A[A-Za-z0-9_-]{1,80}\z") || !ids.Add(id) ||
                node is not JsonObject server || server.Count != 2 ||
                server["Address"] is not JsonValue address || !address.TryGetValue<string>(out var origin) ||
                !ValidOrigin(origin) || server["Description"] is not JsonValue description ||
                !description.TryGetValue<string>(out var note) || note is null ||
                note.Length > 250 || note.Any(char.IsControl))
                return "Invalid real server ID, origin address or description.";
        }
        return null;
    }
}
