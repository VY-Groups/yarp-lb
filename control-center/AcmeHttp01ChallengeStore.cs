using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Short-lived, bounded, process-local HTTP-01 response storage. An ACME issuer
/// may publish a challenge in-process; this type does not persist account keys,
/// accept remote writes, or issue certificates.
/// </summary>
public sealed class AcmeHttp01ChallengeStore
{
    public const int MaximumEntries = 128;
    public const int MaximumTokenLength = 256;
    private static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(10);
    private readonly object gate = new();
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private readonly TimeProvider timeProvider;

    private sealed record Entry(string DnsName, string KeyAuthorization, long PublishedAt, TimeSpan Lifetime);

    public AcmeHttp01ChallengeStore(TimeProvider? timeProvider = null) =>
        this.timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Publish one RFC 8555 HTTP-01 token/key-authorization pair for a bounded lifetime.</summary>
    public bool TryPublish(string dnsName, string token, string keyAuthorization, TimeSpan lifetime)
    {
        var target = AcmeTargetPolicy.ValidateDnsName(dnsName);
        if (!target.Allowed || !ValidToken(token) || !ValidKeyAuthorization(token, keyAuthorization) ||
            lifetime < MinimumLifetime || lifetime > MaximumLifetime)
            return false;

        lock (gate)
        {
            var now = timeProvider.GetTimestamp();
            RemoveExpired(now);
            // A live token is owned by its original authorization. A
            // concurrent issuer may safely retry the identical publication,
            // but must not replace it or silently extend its lifetime.
            if (entries.TryGetValue(token, out var existing))
                return string.Equals(existing.DnsName, target.NormalizedDnsName, StringComparison.Ordinal) &&
                    string.Equals(existing.KeyAuthorization, keyAuthorization, StringComparison.Ordinal);
            if (entries.Count >= MaximumEntries)
                return false;
            entries[token] = new Entry(target.NormalizedDnsName!, keyAuthorization, now, lifetime);
            return true;
        }
    }

    public bool TryGet(string dnsName, string token, out string keyAuthorization)
    {
        keyAuthorization = string.Empty;
        var target = AcmeTargetPolicy.ValidateDnsName(dnsName);
        if (!target.Allowed || !ValidToken(token)) return false;
        lock (gate)
        {
            var now = timeProvider.GetTimestamp();
            RemoveExpired(now);
            if (!entries.TryGetValue(token, out var entry) ||
                !string.Equals(entry.DnsName, target.NormalizedDnsName, StringComparison.Ordinal)) return false;
            keyAuthorization = entry.KeyAuthorization;
            return true;
        }
    }

    public void Remove(string dnsName, string token)
    {
        var target = AcmeTargetPolicy.ValidateDnsName(dnsName);
        if (!target.Allowed || !ValidToken(token)) return;
        lock (gate)
            if (entries.TryGetValue(token, out var entry) &&
                string.Equals(entry.DnsName, target.NormalizedDnsName, StringComparison.Ordinal))
                entries.Remove(token);
    }

    // Challenge lifetimes are relative; NTP or administrator wall-clock changes
    // must not extend or prematurely expire a published authorization.
    private void RemoveExpired(long now)
    {
        foreach (var expired in entries.Where(pair =>
                         timeProvider.GetElapsedTime(pair.Value.PublishedAt, now) >= pair.Value.Lifetime)
                     .Select(pair => pair.Key).ToArray())
            entries.Remove(expired);
    }

    private static bool ValidToken(string? token) =>
        token is { Length: >= 16 and <= MaximumTokenLength } &&
        token.All(IsBase64UrlCharacter);

    // RFC 8555 keyAuthorization = token "." base64url(JWK thumbprint); a SHA-256
    // thumbprint is exactly 43 unpadded base64url characters.
    private static bool ValidKeyAuthorization(string token, string? value) =>
        value is { Length: > 0 } && value.StartsWith(token + ".", StringComparison.Ordinal) &&
        value.Length == token.Length + 1 + 43 &&
        value.AsSpan(token.Length + 1).ToArray().All(IsBase64UrlCharacter);

    private static bool IsBase64UrlCharacter(char value) =>
        value is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_';
}

public static class AcmeHttp01Endpoint
{
    private const string Route = "/.well-known/acme-challenge/{token}";

    /// <summary>
    /// Register the exact public challenge path. The caller must enable this only
    /// when the Kestrel traffic listener is externally reachable on TCP/80.
    /// Management listener isolation continues to reject requests on admin sockets.
    /// </summary>
    public static void MapHttp01Challenge(this WebApplication app, bool publicChallengeEntrypointEnabled,
        Func<HttpContext, bool>? isPublicTrafficHttpListener = null)
    {
        app.MapGet(Route, (string token, AcmeHttp01ChallengeStore store, HttpContext context) =>
        {
            if (!publicChallengeEntrypointEnabled || context.Request.IsHttps ||
                isPublicTrafficHttpListener?.Invoke(context) != true ||
                !store.TryGet(context.Request.Host.Host, token, out var keyAuthorization))
                return Results.NotFound();
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Content-Type-Options"] = "nosniff";
            return Results.Text(keyAuthorization, "text/plain; charset=utf-8");
        });
    }

    /// <summary>Exact socket/scheme predicate shared with isolated listener routing.</summary>
    public static bool IsPublicTrafficHttpListener(HttpContext context, IPAddress expectedLocalAddress,
        int expectedLocalPort) =>
        !context.Request.IsHttps && context.Connection.LocalIpAddress?.Equals(expectedLocalAddress) == true &&
        context.Connection.LocalPort == expectedLocalPort;
}
