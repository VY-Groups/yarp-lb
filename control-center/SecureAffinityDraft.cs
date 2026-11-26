using System.Globalization;
using System.Text.Json.Nodes;

/// <summary>Pure reviewed and signed-agent validation for secure affinity.</summary>
public static class SecureAffinityDraft
{
    public const string Marker = "ADC.Persistence.Profile";
    public const string SecureCookie = "SecureCookie";
    public static string KeyName(string id) => "__Host-GatewayCore-" + id;

    public static string? Validate(JsonObject clusters)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var (id, node) in clusters)
        {
            if (node is not JsonObject cluster) continue;
            var affinity = cluster["SessionAffinity"] as JsonObject;
            var key = affinity?["AffinityKeyName"]?.ToString();
            var enabled = affinity?["Enabled"]?.ToString()?.Equals("true", StringComparison.OrdinalIgnoreCase) == true;
            // Enforce the reserved namespace, even if a hand-edited draft omits the marker.
            var marked = cluster["Metadata"]?[Marker]?.ToString() == SecureCookie;
            if (!marked && affinity?["Policy"]?.ToString() != "GatewayCoreExpiringCookie" &&
                !(key?.StartsWith("__Host-GatewayCore-", StringComparison.Ordinal) ?? false)) continue;
            var cookie = affinity?["Cookie"] as JsonObject;
            if (!marked || !enabled || key != KeyName(id) || !names.Add(key) ||
                affinity?["Policy"]?.ToString() is not ("Cookie" or "GatewayCoreExpiringCookie") ||
                affinity?["FailurePolicy"]?.ToString() is not ("Redistribute" or "Return503Error") ||
                cookie is null || cookie.ContainsKey("Domain") ||
                cookie["Path"]?.ToString() != "/" ||
                cookie["HttpOnly"]?.ToString()?.Equals("true", StringComparison.OrdinalIgnoreCase) != true ||
                cookie["SecurePolicy"]?.ToString() != "Always" ||
                cookie["SameSite"]?.ToString() is not ("Lax" or "Strict") ||
                !TimeSpan.TryParseExact(cookie["MaxAge"]?.ToString(), "c", CultureInfo.InvariantCulture, out var age) ||
                !ValidAge(age))
                return "Invalid secure persistence profile: require encrypted host-only HTTPS cookie, bounded lifetime, unique cluster name and explicit failure policy.";
        }
        return null;
    }

    public static bool ValidAge(TimeSpan age) =>
        age >= TimeSpan.FromMinutes(1) && age <= TimeSpan.FromHours(24) &&
        age.Ticks % TimeSpan.TicksPerMinute == 0;

}
