using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The Kestrel TLS layer still must require a valid client certificate chain
/// and revocation checks. This additional gate pins controller identities.
/// </summary>
public static class AgentClientCertificatePolicy
{
    public static IReadOnlySet<string> ParsePinnedThumbprints(IEnumerable<string> configured)
    {
        var pins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pin in configured)
        {
            if (string.IsNullOrWhiteSpace(pin))
                throw new InvalidOperationException("Empty client certificate thumbprint");
            var normalized = pin.Replace(" ", "").ToUpperInvariant();
            if (normalized.Length != 40 || normalized.Any(c => !Uri.IsHexDigit(c)) ||
                !pins.Add(normalized))
                throw new InvalidOperationException("Invalid or duplicate SHA-1 certificate thumbprint");
        }
        if (pins.Count is < 1 or > 8)
            throw new InvalidOperationException("Require 1..8 pinned controller certificate thumbprints");
        return pins;
    }

    private static bool ValidTime(X509Certificate2 cert, DateTimeOffset now) =>
        cert.NotBefore.ToUniversalTime() <= now.UtcDateTime &&
        cert.NotAfter.ToUniversalTime() > now.UtcDateTime;

    public static bool IsAuthorized(HttpContext context, IReadOnlySet<string> pins)
    {
        if (!context.Request.IsHttps) return false;
        X509Certificate2? cert = context.Connection.ClientCertificate;
        var hash = cert?.Thumbprint;
        return !string.IsNullOrEmpty(hash) && ValidTime(cert!,DateTimeOffset.UtcNow) &&
            pins.Contains(hash.ToUpperInvariant());
    }

    /// <summary>
    /// Read the current pin overlap and emergency-denylist on EACH management
    /// request. The configuration system can reload an ACL-protected JSON file
    /// without requiring a Kestrel restart, certificate renegotiation or an
    /// agent process restart. Malformed/empty replacement configuration fails
    /// closed; it never restores an older trusted set.
    /// </summary>
    public static bool IsAuthorizedLive(HttpContext context, IConfiguration config)
    {
        if (!context.Request.IsHttps || context.Connection.ClientCertificate is null) return false;
        try
        {
            var pins = ParsePinnedThumbprints(
                config.GetSection("Agent:TrustedClientThumbprints").Get<string[]>() ?? []);
            var deny = config.GetSection("Agent:RevokedClientThumbprints").Get<string[]>() ?? [];
            if (deny.Length > 128) return false;
            var revoked = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in deny)
            {
                if (string.IsNullOrWhiteSpace(item)) return false;
                var normalized = item.Replace(" ", "").ToUpperInvariant();
                if (normalized.Length != 40 ||
                    normalized.Any(c => !Uri.IsHexDigit(c)) ||
                    !revoked.Add(normalized)) return false;
            }
            var hash = context.Connection.ClientCertificate.Thumbprint.ToUpperInvariant();
            return !revoked.Contains(hash) && IsAuthorized(context,pins);
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }
}
