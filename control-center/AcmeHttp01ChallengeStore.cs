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

    private sealed record Entry(string KeyAuthorization, DateTimeOffset ExpiresAt);

    public AcmeHttp01ChallengeStore(TimeProvider? timeProvider = null) =>
        this.timeProvider = timeProvider ?? TimeProvider.System;

    /// <summary>Publish one RFC 8555 HTTP-01 token/key-authorization pair for a bounded lifetime.</summary>
    public bool TryPublish(string token, string keyAuthorization, TimeSpan lifetime)
    {
        if (!ValidToken(token) || !ValidKeyAuthorization(token, keyAuthorization) ||
            lifetime < MinimumLifetime || lifetime > MaximumLifetime)
            return false;

        lock (gate)
        {
            RemoveExpired(timeProvider.GetUtcNow());
            if (!entries.ContainsKey(token) && entries.Count >= MaximumEntries)
                return false;
            entries[token] = new Entry(keyAuthorization, timeProvider.GetUtcNow() + lifetime);
            return true;
        }
    }

    public bool TryGet(string token, out string keyAuthorization)
    {
        keyAuthorization = string.Empty;
        if (!ValidToken(token)) return false;
        lock (gate)
        {
            var now = timeProvider.GetUtcNow();
            RemoveExpired(now);
            if (!entries.TryGetValue(token, out var entry)) return false;
            keyAuthorization = entry.KeyAuthorization;
            return true;
        }
    }

    public void Remove(string token)
    {
        if (!ValidToken(token)) return;
        lock (gate) entries.Remove(token);
    }

    private void RemoveExpired(DateTimeOffset now)
    {
        foreach (var expired in entries.Where(pair => pair.Value.ExpiresAt <= now)
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
                !store.TryGet(token, out var keyAuthorization))
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
