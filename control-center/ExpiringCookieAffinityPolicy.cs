using System.Globalization;
using System.Security.Cryptography;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.SessionAffinity;

/// <summary>Time-limited affinity credentials only, never authentication.
/// Identical application name, purpose and authorized DP key ring are required
/// across peers. No key material is copied or exposed by this policy.</summary>
public sealed class ExpiringAffinityTokens(IDataProtectionProvider provider)
{
    private ITimeLimitedDataProtector For(string clusterId, string cookieName, TimeSpan lifetime) =>
        provider.CreateProtector("GatewayCore.Affinity.v1", clusterId, cookieName,
            lifetime.Ticks.ToString(CultureInfo.InvariantCulture)).ToTimeLimitedDataProtector();

    public string Issue(string clusterId, string cookieName, TimeSpan lifetime, string destinationId,
        DateTimeOffset expiry) => For(clusterId, cookieName, lifetime).Protect(destinationId, expiry);

    public string? Read(string clusterId, string cookieName, TimeSpan lifetime, string token)
    {
        if (string.IsNullOrEmpty(token) || token.Length > 2048) return null;
        try
        {
            var id = For(clusterId, cookieName, lifetime).Unprotect(token, out _);
            return id.Length is > 0 and <= 80 ? id : null;
        }
        catch (CryptographicException) { return null; }
        catch (FormatException) { return null; }
        catch (ArgumentException) { return null; }
    }
}

public sealed class ExpiringCookieAffinityPolicy(ExpiringAffinityTokens tokens, TimeProvider clock) : ISessionAffinityPolicy
{
    public const string PolicyName = "GatewayCoreExpiringCookie";
    private static readonly object Affinitized = new();
    public string Name => PolicyName;

    public AffinityResult FindAffinitizedDestinations(HttpContext context, ClusterState cluster,
        SessionAffinityConfig config, IReadOnlyList<DestinationState> destinations)
    {
        if (!context.Request.IsHttps || config.Cookie?.MaxAge is not { } lifetime)
            return new(null, AffinityStatus.AffinityKeyExtractionFailed);
        if (!context.Request.Cookies.TryGetValue(config.AffinityKeyName, out var token))
            return new(null, AffinityStatus.AffinityKeyNotSet);
        var id = tokens.Read(cluster.ClusterId, config.AffinityKeyName, lifetime, token);
        if (id is null) return new(null, AffinityStatus.AffinityKeyExtractionFailed);
        foreach (var destination in destinations)
        {
            if (!string.Equals(destination.DestinationId, id, StringComparison.Ordinal) ||
                TrafficLifecycle.IsDraining(destination)) continue;
            context.Items[Affinitized] = true;
            return new(new[] { destination }, AffinityStatus.OK);
        }
        return new(null, AffinityStatus.DestinationNotFound);
    }

    public void AffinitizeResponse(HttpContext context, ClusterState cluster, SessionAffinityConfig config,
        DestinationState destination)
    {
        if (context.RequestAborted.IsCancellationRequested || !context.Request.IsHttps ||
            context.Items.ContainsKey(Affinitized) || TrafficLifecycle.IsDraining(destination) ||
            config.Cookie?.MaxAge is not { } lifetime) return;
        var value = tokens.Issue(cluster.ClusterId, config.AffinityKeyName, lifetime,
            destination.DestinationId, clock.GetUtcNow().Add(lifetime));
        context.Response.Cookies.Append(config.AffinityKeyName, value, new CookieOptions
        {
            Path = "/", Secure = true, HttpOnly = true, MaxAge = lifetime,
            SameSite = config.Cookie.SameSite == SameSiteMode.Strict ? SameSiteMode.Strict : SameSiteMode.Lax
        });
    }
}
