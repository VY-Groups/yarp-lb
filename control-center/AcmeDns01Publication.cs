using System.Security.Cryptography;

/// <summary>A single authoritative nameserver's observed TXT RRset.</summary>
public sealed record AcmeDns01AuthorityObservation(string AuthorityId,
    IReadOnlyList<string> TxtValues);

/// <summary>
/// DNS-01 provider boundary. Implementations must authenticate their update
/// target, publish only the supplied exact TXT owner/value, and enumerate every
/// configured independently operated authority (not recursive cache results).
/// No implementation is registered by default; account/zone credentials must
/// never be accepted through the public Control Center request body.
/// </summary>
public interface IAcmeDns01PublicationLease : IAsyncDisposable
{
    /// <summary>
    /// Publish the exact TXT value. The lease already exists so DisposeAsync
    /// can compensate if this partially fails. Disposal must be idempotent,
    /// remove only this lease's exact owner/value, and preserve unrelated TXT
    /// values that another validation may have published concurrently.
    /// </summary>
    Task PublishAsync(CancellationToken cancellationToken);
}

public interface IAcmeDns01Publisher
{
    /// <summary>Acquire a cleanup handle without publishing. If acquisition fails, no DNS side effect may remain.</summary>
    Task<IAcmeDns01PublicationLease> AcquirePublicationLeaseAsync(string fqdn, string txtValue,
        TimeSpan lifetime, CancellationToken cancellationToken);

    Task<IReadOnlyList<AcmeDns01AuthorityObservation>> ProbeAuthoritativeAsync(
        string fqdn, string txtValue, CancellationToken cancellationToken);
}

/// <summary>
/// Fail-closed DNS-01 publication and readiness gate. The ACME client may
/// request validation only when at least two distinct authoritative servers
/// confirm the exact SHA-256 TXT value. A failed/cancelled attempt releases
/// its publication lease; a successful caller must dispose the returned lease
/// once the authorization is complete.
/// </summary>
public static class AcmeDns01Publication
{
    private static readonly TimeSpan MinimumLifetime = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan MaximumLifetime = TimeSpan.FromMinutes(10);

    public static bool IsDns01Value(string? txt)
    {
        if (txt is not { Length: 43 } || !txt.All(c =>
                c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or
                    >= '0' and <= '9' or '-' or '_'))
            return false;
        try
        {
            // 43 unpadded base64url characters encode exactly 32 SHA-256 bytes.
            var decoded = Convert.FromBase64String(
                txt.Replace('-', '+').Replace('_', '/') + "=");
            return decoded.Length == 32 &&
                Convert.ToBase64String(decoded).TrimEnd('=')
                    .Replace('+', '-').Replace('/', '_') == txt;
        }
        catch (FormatException) { return false; }
    }

    public static string ChallengeOwner(string dnsName)
    {
        var target = AcmeTargetPolicy.ValidateDnsName(dnsName);
        if (!target.Allowed)
            throw new InvalidOperationException("DNS-01 requires one eligible public DNS hostname");
        var fqdn = "_acme-challenge." + target.NormalizedDnsName;
        if (fqdn.Length > 253)
            throw new InvalidOperationException("DNS-01 TXT owner exceeds the DNS name length limit");
        return fqdn;
    }

    public static bool HasVerifiedAuthorities(
        IReadOnlyList<AcmeDns01AuthorityObservation>? observations, string expectedTxt)
    {
        if (!IsDns01Value(expectedTxt) || observations is not { Count: >= 2 and <= 16 })
            return false;
        var unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var observed in observations)
        {
            if (observed is null || string.IsNullOrEmpty(observed.AuthorityId) ||
                observed.AuthorityId.Length > 128 ||
                observed.AuthorityId.Any(c => !(char.IsAsciiLetterOrDigit(c) ||
                    c is '.' or '-' or '_' or ':' )) ||
                !unique.Add(observed.AuthorityId) ||
                observed.TxtValues is not { Count: >= 1 and <= 32 } ||
                !observed.TxtValues.Any(value =>
                    string.Equals(value, expectedTxt, StringComparison.Ordinal)))
                return false;
        }
        return unique.Count >= 2;
    }

    public static async Task<IAsyncDisposable> PublishAndVerifyAsync(
        string dnsName, string expectedTxt, IAcmeDns01Publisher publisher,
        CancellationToken cancellationToken, int maximumProbes = 30,
        TimeSpan? probeInterval = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(publisher);
        if (!IsDns01Value(expectedTxt) || maximumProbes is < 1 or > 30)
            throw new InvalidOperationException("Invalid DNS-01 challenge value or polling budget");
        var interval = probeInterval ?? TimeSpan.FromSeconds(3);
        if (interval < TimeSpan.Zero || interval > TimeSpan.FromSeconds(10))
            throw new InvalidOperationException("DNS-01 probe interval must be bounded");
        var owner = ChallengeOwner(dnsName);
        cancellationToken.ThrowIfCancellationRequested();

        // Acquire the compensating handle before the provider can mutate DNS.
        var lease = await publisher.AcquirePublicationLeaseAsync(owner, expectedTxt,
            TimeSpan.FromMinutes(8), cancellationToken)
            ?? throw new InvalidOperationException("DNS-01 publisher did not return a cleanup lease");
        try
        {
            await lease.PublishAsync(cancellationToken);
            for (var attempt = 0; attempt < maximumProbes; attempt++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var observations = await publisher.ProbeAuthoritativeAsync(
                    owner, expectedTxt, cancellationToken);
                if (HasVerifiedAuthorities(observations, expectedTxt))
                    return lease;
                if (attempt + 1 < maximumProbes)
                    await Task.Delay(interval, timeProvider ?? TimeProvider.System, cancellationToken);
            }
            throw new InvalidOperationException(
                "DNS-01 TXT not verified on at least two independent authoritative nameservers");
        }
        catch
        {
            await lease.DisposeAsync();
            throw;
        }
    }
}
