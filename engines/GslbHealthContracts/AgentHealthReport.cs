using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace GatewayCore.Gslb.Contracts;

/// <summary>
/// Versioned report emitted by an independently configured health observer.
/// A receiver must still apply local probes, freshness, replay and quorum
/// policy before a site can receive DNS traffic.
/// </summary>
public sealed record AgentHealthReport(
    int Version,
    string AgentId,
    string KeyId,
    string Zone,
    string SiteId,
    long Epoch,
    long Sequence,
    long ObservedAtUnixSeconds,
    long ExpiresAtUnixSeconds,
    string ProbeType,
    string Verdict,
    int ConfidencePermille,
    int? LatencyMilliseconds,
    string Signature);

/// <summary>Canonical signing rules shared by report producers and receivers.</summary>
public static class AgentHealthReportContract
{
    public const int CurrentVersion = 1;
    public const int MaximumSerializedBytes = 8192;
    private static readonly Regex Identifier = new("^[A-Za-z0-9_][A-Za-z0-9_-]{0,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex DnsLabel = new("^[A-Za-z0-9_-]{1,63}$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly IReadOnlySet<string> RequiredWireProperties =
        new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            nameof(AgentHealthReport.Version), nameof(AgentHealthReport.AgentId),
            nameof(AgentHealthReport.KeyId), nameof(AgentHealthReport.Zone),
            nameof(AgentHealthReport.SiteId), nameof(AgentHealthReport.Epoch),
            nameof(AgentHealthReport.Sequence), nameof(AgentHealthReport.ObservedAtUnixSeconds),
            nameof(AgentHealthReport.ExpiresAtUnixSeconds), nameof(AgentHealthReport.ProbeType),
            nameof(AgentHealthReport.Verdict), nameof(AgentHealthReport.ConfidencePermille),
            nameof(AgentHealthReport.LatencyMilliseconds), nameof(AgentHealthReport.Signature)
        };

    public static bool HasExactSerializedFields(ReadOnlyMemory<byte> utf8Json) =>
        StrictJsonPropertyNames.HasExactTopLevelProperties(utf8Json, RequiredWireProperties);

    public static bool IsValidIdentifier(string? value) =>
        value is not null && Identifier.IsMatch(value);

    public static bool IsValid(AgentHealthReport? report, int maxTtlSeconds)
    {
        if (report is null || report.Version != CurrentVersion ||
            !IsValidIdentifier(report.AgentId) || !IsValidZone(report.Zone) ||
            string.IsNullOrEmpty(report.KeyId) || report.KeyId.Length != 64 ||
            report.KeyId.Any(ch => !Uri.IsHexDigit(ch)) ||
            !IsValidIdentifier(report.SiteId) || report.Epoch <= 0 || report.Sequence <= 0 ||
            report.ObservedAtUnixSeconds <= 0 ||
            report.ExpiresAtUnixSeconds <= report.ObservedAtUnixSeconds ||
            maxTtlSeconds <= 0 ||
            report.ExpiresAtUnixSeconds - report.ObservedAtUnixSeconds > maxTtlSeconds ||
            report.ProbeType is not ("http" or "tcp") ||
            report.Verdict is not ("healthy" or "unhealthy" or "unknown") ||
            report.ConfidencePermille is < 0 or > 1000 ||
            (report.Verdict == "unknown" && report.ConfidencePermille != 0) ||
            (report.Verdict != "unknown" && report.ConfidencePermille == 0) ||
            report.LatencyMilliseconds is < 0 ||
            (report.Verdict == "healthy" && report.LatencyMilliseconds is null) ||
            (report.Verdict == "unknown" && report.LatencyMilliseconds is not null) ||
            string.IsNullOrEmpty(report.Signature) || report.Signature.Length > 128)
            return false;

        try { return Convert.FromBase64String(report.Signature).Length is > 0 and <= 96; }
        catch (FormatException) { return false; }
    }

    public static string CanonicalPayload(AgentHealthReport report)
    {
        ArgumentNullException.ThrowIfNull(report);
        return string.Join('\n',
            "GatewayCore.AgentHealth.v1",
            report.AgentId,
            report.KeyId.ToUpperInvariant(),
            report.Zone.TrimEnd('.').ToLowerInvariant(),
            report.SiteId,
            report.Epoch.ToString(CultureInfo.InvariantCulture),
            report.Sequence.ToString(CultureInfo.InvariantCulture),
            report.ObservedAtUnixSeconds.ToString(CultureInfo.InvariantCulture),
            report.ExpiresAtUnixSeconds.ToString(CultureInfo.InvariantCulture),
            report.ProbeType,
            report.Verdict,
            report.ConfidencePermille.ToString(CultureInfo.InvariantCulture),
            report.LatencyMilliseconds?.ToString(CultureInfo.InvariantCulture) ?? "-");
    }

    public static string Sign(AgentHealthReport report, ECDsa privateKey)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        if (privateKey.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
            throw new CryptographicException("Agent health reports require an ECDSA P-256 key");
        if (!KeyId(privateKey).Equals(report.KeyId, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Agent report key ID does not match the signing key");
        return Convert.ToBase64String(privateKey.SignData(Encoding.UTF8.GetBytes(CanonicalPayload(report)),
            HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence));
    }

    public static bool Verify(AgentHealthReport report, ECDsa publicKey, int maxTtlSeconds)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        if (!IsValid(report, maxTtlSeconds) ||
            publicKey.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
            !KeyId(publicKey).Equals(report.KeyId, StringComparison.OrdinalIgnoreCase))
            return false;
        try
        {
            return publicKey.VerifyData(Encoding.UTF8.GetBytes(CanonicalPayload(report)),
                Convert.FromBase64String(report.Signature), HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException) { return false; }
    }

    public static string KeyId(ECDsa key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return Convert.ToHexString(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
    }

    public static bool IsValidZone(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 253) return false;
        var zone = value.TrimEnd('.');
        return zone.Length is > 0 and <= 253 && zone.Split('.').All(label =>
            DnsLabel.IsMatch(label) && label[0] != '-' && label[^1] != '-');
    }
}
