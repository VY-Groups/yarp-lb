using System.Globalization;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Configuration;

public sealed class SecureAffinityContract : IProxyConfigFilter
{
    public const string Marker = "ADC.Persistence.Profile";
    public const string SecureCookie = "SecureCookie";
    public static string KeyName(string id) => "__Host-GatewayCore-" + id;

    public static string? Validate(JsonObject clusters) => SecureAffinityDraft.Validate(clusters);

    private static bool ValidAge(TimeSpan age) => SecureAffinityDraft.ValidAge(age);

    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel)
    {
        var affinity = cluster.SessionAffinity;
        var key = affinity?.AffinityKeyName;
        var marked = cluster.Metadata?.TryGetValue(Marker, out var mode) == true && mode == SecureCookie;
        if (marked || affinity?.Policy == ExpiringCookieAffinityPolicy.PolicyName ||
            (key?.StartsWith("__Host-GatewayCore-", StringComparison.Ordinal) ?? false))
        {
            var cookie = affinity?.Cookie;
            if (!marked || affinity?.Enabled != true || key != KeyName(cluster.ClusterId) ||
                affinity.Policy is not ("Cookie" or ExpiringCookieAffinityPolicy.PolicyName) || affinity.FailurePolicy is not ("Redistribute" or "Return503Error") ||
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
