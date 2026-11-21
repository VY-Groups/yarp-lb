using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// The Kestrel TLS layer still must require a valid client certificate chain
/// and revocation checks. This additional gate pins controller identities.
/// </summary>
public static class AgentClientCertificatePolicy
{
    private const string Sha1Prefix = "SHA1:";
    private const string Sha256Prefix = "SHA256:";

    /// <summary>
    /// Parse certificate identity pins. Unprefixed 40-character values remain
    /// supported as legacy X.509 SHA-1 thumbprints; new pins must use the
    /// explicit SHA256:<64 hex characters> form. A SHA-256 pin is never
    /// retried as SHA-1, so malformed or mismatched modern pins cannot downgrade.
    /// </summary>
    public static IReadOnlySet<string> ParsePinnedThumbprints(IEnumerable<string> configured)
        => ParsePins(configured, 1, 8, "controller certificate pin");

    private static IReadOnlySet<string> ParsePins(IEnumerable<string> configured,
        int minCount, int maxCount, string description)
    {
        var pins = new HashSet<string>(StringComparer.Ordinal);
        foreach (var pin in configured)
        {
            if (string.IsNullOrWhiteSpace(pin))
                throw new InvalidOperationException($"Empty {description}");

            var value = pin.Replace(" ", "").ToUpperInvariant();
            string algorithm;
            string hex;
            if (value.StartsWith(Sha256Prefix, StringComparison.Ordinal))
            {
                algorithm = Sha256Prefix;
                hex = value[Sha256Prefix.Length..];
                if (hex.Length != 64 || hex.Any(c => !Uri.IsHexDigit(c)))
                    throw new InvalidOperationException($"Invalid SHA-256 {description}");
            }
            else
            {
                if (value.StartsWith(Sha1Prefix, StringComparison.Ordinal))
                    value = value[Sha1Prefix.Length..];
                algorithm = Sha1Prefix;
                hex = value;
                if (hex.Length != 40 || hex.Any(c => !Uri.IsHexDigit(c)))
                    throw new InvalidOperationException($"Invalid SHA-1 {description}");
            }

            if (!pins.Add(algorithm + hex))
                throw new InvalidOperationException($"Duplicate {description}");
        }
        if (pins.Count < minCount || pins.Count > maxCount)
            throw new InvalidOperationException($"Require {minCount}..{maxCount} {description}s");
        return pins;
    }

    private static bool ValidTime(X509Certificate2 cert, DateTimeOffset now) =>
        cert.NotBefore.ToUniversalTime() <= now.UtcDateTime &&
        cert.NotAfter.ToUniversalTime() > now.UtcDateTime;

    public static bool IsAuthorized(HttpContext context, IReadOnlySet<string> pins)
    {
        if (!context.Request.IsHttps) return false;
        X509Certificate2? cert = context.Connection.ClientCertificate;
        if (cert is null || !ValidTime(cert, DateTimeOffset.UtcNow)) return false;

        return MatchesPins(cert, pins);
    }

    // A pin match is an identity comparison, not independent authorization.
    // The request policy checks TLS, time, trust and revocation separately.
    private static bool MatchesPins(X509Certificate2 cert, IReadOnlySet<string> pins)
    {
        var sha1 = Convert.FromHexString(cert.Thumbprint);
        var sha256 = SHA256.HashData(cert.RawData);
        var matched = false;
        foreach (var pin in pins)
        {
            var separator = pin.IndexOf(':');
            if (separator < 0) continue; // Reject non-canonical entries defensively.
            var algorithm = pin[..(separator + 1)];
            var expected = Convert.FromHexString(pin[(separator + 1)..]);
            var actual = algorithm switch
            {
                Sha1Prefix => sha1,
                Sha256Prefix => sha256,
                _ => Array.Empty<byte>()
            };
            if (actual.Length == expected.Length)
                matched |= CryptographicOperations.FixedTimeEquals(actual, expected);
        }
        return matched;
    }

    /// <summary>
    /// Read the current pin overlap and emergency-denylist on EACH management
    /// request. The configuration system can reload an ACL-protected JSON file
    /// without requiring a Kestrel restart, certificate renegotiation or an
    /// agent process restart. Malformed/empty replacement configuration fails
    /// closed; it never restores an older trusted set.
    /// </summary>
    public static bool IsAuthorizedLive(HttpContext context, IConfiguration config,
        Action<string>? pinSetRevisionObserved = null)
    {
        if (!context.Request.IsHttps) return false;
        var cert = context.Connection.ClientCertificate;
        if (cert is null || !ValidTime(cert, DateTimeOffset.UtcNow)) return false;
        try
        {
            var pins = ParsePinnedThumbprints(
                config.GetSection("Agent:TrustedClientThumbprints").Get<string[]>() ?? []);
            pinSetRevisionObserved?.Invoke(AgentPinSetRevisionAudit.Fingerprint(pins));
            var deny = config.GetSection("Agent:RevokedClientThumbprints").Get<string[]>() ?? [];
            if (deny.Length > 128) return false;
            var revoked = deny.Length == 0
                ? new HashSet<string>(StringComparer.Ordinal)
                : ParsePins(deny, 1, 128, "revoked client certificate pin");
            // Evaluate both sets against the same TLS certificate. A denylist
            // match can only reject, and an empty denylist never grants trust.
            var trusted = MatchesPins(cert, pins);
            var denied = MatchesPins(cert, revoked);
            return trusted && !denied;
        }
        catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }
}
