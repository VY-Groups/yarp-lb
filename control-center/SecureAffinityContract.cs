using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Configuration;

public sealed class SecureAffinityContract : IProxyConfigFilter
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
            if (!marked && !(key?.StartsWith("__Host-GatewayCore-", StringComparison.Ordinal) ?? false)) continue;
            var cookie = affinity?["Cookie"] as JsonObject;
            if (!marked || !enabled || key != KeyName(id) || !names.Add(key) ||
                affinity?["Policy"]?.ToString() != "Cookie" ||
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

    private static bool ValidAge(TimeSpan age) =>
        age >= TimeSpan.FromMinutes(1) && age <= TimeSpan.FromHours(24) &&
        age.Ticks % TimeSpan.TicksPerMinute == 0;

    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel)
    {
        var affinity = cluster.SessionAffinity;
        var key = affinity?.AffinityKeyName;
        var marked = cluster.Metadata?.TryGetValue(Marker, out var mode) == true && mode == SecureCookie;
        if (marked || (key?.StartsWith("__Host-GatewayCore-", StringComparison.Ordinal) ?? false))
        {
            var cookie = affinity?.Cookie;
            if (!marked || affinity?.Enabled != true || key != KeyName(cluster.ClusterId) ||
                affinity.Policy != "Cookie" || affinity.FailurePolicy is not ("Redistribute" or "Return503Error") ||
                cookie?.Domain is not null || cookie?.Path != "/" || cookie.HttpOnly != true ||
                cookie.SecurePolicy != CookieSecurePolicy.Always ||
                cookie.SameSite is not (SameSiteMode.Lax or SameSiteMode.Strict) ||
                cookie.MaxAge is not { } age || !ValidAge(age))
                throw new InvalidOperationException("Invalid secure persistence profile.");
        }
        return ValueTask.FromResult(cluster);
    }

    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel) =>
        ValueTask.FromResult(route);
}
