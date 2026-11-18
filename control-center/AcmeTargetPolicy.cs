using System.Globalization;
using System.Net;

/// <summary>
/// Narrow preflight contract for a future ACME issuer. This does not issue or rotate
/// certificates; it rejects unsafe target and directory inputs before an issuer is added.
/// </summary>
public static class AcmeTargetPolicy
{
    private static readonly HashSet<string> OfficialDirectories = new(StringComparer.OrdinalIgnoreCase)
    {
        "acme-v02.api.letsencrypt.org",
        "acme-staging-v02.api.letsencrypt.org"
    };

    private static readonly string[] NonPublicSuffixes =
        [".localhost", ".local", ".internal", ".test", ".invalid", ".example"];

    public sealed record Validation(bool Allowed, string? NormalizedDnsName, string Reason);

    public static Validation Validate(string? directoryUrl, string? dnsName, bool http01,
        bool publicChallengeEntrypointEnabled, bool allowLoopbackTestAuthority = false)
    {
        if (!Uri.TryCreate(directoryUrl, UriKind.Absolute, out var directory) ||
            directory.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(directory.UserInfo) ||
            !string.IsNullOrEmpty(directory.Query) || !string.IsNullOrEmpty(directory.Fragment) ||
            directory.AbsolutePath != "/directory")
            return Reject("directory-must-be-an-https-url-without-credentials-query-or-fragment");

        var officialDirectory = OfficialDirectories.Contains(directory.IdnHost);
        var loopbackTestDirectory = allowLoopbackTestAuthority &&
            IPAddress.TryParse(directory.Host.Trim('[', ']'), out var directoryIp) &&
            IPAddress.IsLoopback(directoryIp);
        if ((!officialDirectory && !loopbackTestDirectory) ||
            (officialDirectory && !directory.IsDefaultPort))
            return Reject("directory-host-is-not-an-approved-acme-authority");

        if (string.IsNullOrWhiteSpace(dnsName) || dnsName.Contains('*') || dnsName.EndsWith('.'))
            return Reject("dns-name-must-be-a-single-explicit-hostname-without-wildcard-or-trailing-dot");

        string asciiName;
        try
        {
            asciiName = new IdnMapping().GetAscii(dnsName).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return Reject("dns-name-is-not-valid-idna");
        }

        if (asciiName.Length > 253 || IPAddress.TryParse(asciiName, out _) ||
            asciiName.Contains(':') || asciiName.Contains('/') || asciiName.Contains('@') ||
            asciiName.Split('.').Length < 2 ||
            asciiName.Split('.').Any(label => label.Length is < 1 or > 63 || label[0] == '-' ||
                label[^1] == '-' || label.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-'))) ||
            NonPublicSuffixes.Any(suffix => asciiName.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)))
            return Reject("dns-name-is-not-an-eligible-public-hostname");

        if (http01 && !publicChallengeEntrypointEnabled)
            return Reject("http-01-requires-an-explicit-public-challenge-entrypoint");

        return new Validation(true, asciiName, "eligible-for-preflight-only");

        static Validation Reject(string reason) => new(false, null, reason);
    }
}
