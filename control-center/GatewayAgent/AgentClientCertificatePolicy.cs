using Microsoft.AspNetCore.Http;
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

    public static bool IsAuthorized(HttpContext context, IReadOnlySet<string> pins)
    {
        if (!context.Request.IsHttps) return false;
        X509Certificate2? cert = context.Connection.ClientCertificate;
        var hash = cert?.Thumbprint;
        return !string.IsNullOrEmpty(hash) && pins.Contains(hash.ToUpperInvariant());
    }
}
