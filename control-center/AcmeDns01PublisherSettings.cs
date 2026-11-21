using System.Net;

/// <summary>
/// Privileged-only DNS-01 update and authority evidence configuration.
/// Paths identify operator-installed files; no TSIG secret is accepted in
/// JSON or in a public request. This is not a dynamic admin/API contract.
/// </summary>
public sealed record AcmeDns01AuthoritySettings(string AuthorityId, string Address);

public sealed record AcmeDns01PublisherSettings(
    string ZoneName,
    string UpdateServerAddress,
    string NsupdateExecutablePath,
    string NsupdateExecutableSha256,
    string TsigKeyFilePath,
    AcmeDns01AuthoritySettings[] Authorities)
{
    /// <summary>
    /// Fail startup for an invalid publication trust boundary before a
    /// background renewal order can be queued. Create an immutable writer
    /// and a *separate* authoritative TCP verifier. The writer's own
    /// claimed DNS visibility can never be trusted as readiness.
    /// </summary>
    public IAcmeDns01Publisher CreateVerifiedPublisher()
    {
        if (string.IsNullOrWhiteSpace(UpdateServerAddress) ||
            !IPAddress.TryParse(UpdateServerAddress, out var updateAddress) ||
            Authorities is not { Length: >= 2 and <= 16 } ||
            Authorities.Any(a => a is null ||
                string.IsNullOrWhiteSpace(a.Address) ||
                !IPAddress.TryParse(a.Address, out _)))
            throw new InvalidOperationException(
                "DNS-01 publication requires a pinned update IP and 2..16 literal authority IPs");
        var writer = new AcmeDns01NsupdateWriter(
            new AcmeDns01NsupdateOptions(ZoneName, updateAddress,
                NsupdateExecutablePath, NsupdateExecutableSha256, TsigKeyFilePath));
        var authorityEndpoints = Authorities.Select(a =>
        {
            if (!IPAddress.TryParse(a.Address, out var address))
                throw new InvalidOperationException("DNS-01 authority must have a literal IP address");
            return new AcmeDns01AuthorityServer(a.AuthorityId, address);
        });
        var verified = new AcmeDns01WireVerifiedPublisher(writer, authorityEndpoints);
        writer.VerifyPreflight();
        return verified;
    }
}
