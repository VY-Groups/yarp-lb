using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Licensing;

namespace GatewayCore.LicenseAuthority;

// Operator-approved terms. The customer request never supplies these.
public sealed record Subscription(string LicenseId, string CustomerId, string DeploymentId,
    string Edition, int MaxNodes, int MaxSites, long ExpiresAt, string[] Features);
public sealed record Allocation(string AllocationId, string SiteId, string InstallationKeySha256, long Revision, string? RevocationEnvelope = null);
public sealed record IssuedRequest(string RequestId, string RequestSha256, string SiteId, string Envelope);
public sealed record IssuerLedger(Subscription Terms, string KeySha256, string KeyId,
    List<Allocation> Allocations, List<IssuedRequest> Requests);

// Company-side prototype, never part of the customer package. One private
// local ledger per subscription, one filesystem authority. A future PostgreSQL
// implementation must preserve the same transaction and uniqueness semantics.
public sealed class OfflineIssuer
{
    private readonly string path;
    private readonly ECDsa signer;
    private readonly string keyId;
    private readonly string keyHash;
    private readonly OfflineLicenseVerifier verifier;
    private const int MaxLedgerBytes = 64 * 1024 * 1024;

    public OfflineIssuer(string path, ECDsa signer, string keyId)
    {
        this.path = Path.GetFullPath(path);
        this.signer = signer;
        this.keyId = keyId;
        var pub = signer.ExportSubjectPublicKeyInfo();
        keyHash = Convert.ToHexString(SHA256.HashData(pub));
        verifier = new OfflineLicenseVerifier(new Dictionary<string, byte[]> { [keyId] = pub });
    }

    public void Initialize(Subscription terms, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(terms);
        using var gate = Lock();
        if (File.Exists(path)) throw new InvalidOperationException("Subscription already exists.");
        ValidateTerms(terms, now);
        Save(new(terms, keyHash, keyId, new(), new()), false);
    }

    // Explicit operator action. Existing allocations cannot silently change
    // customer/deployment identity, nor shrink below their committed seats.
    public void RenewSubscription(Subscription terms, DateTimeOffset now)
    {
        using var gate = Lock();
        var ledger = Read();
        ValidateTerms(terms, now);
        if (terms.LicenseId != ledger.Terms.LicenseId || terms.CustomerId != ledger.Terms.CustomerId ||
            terms.DeploymentId != ledger.Terms.DeploymentId ||
            terms.MaxNodes < ledger.Allocations.Count ||
            terms.MaxSites < ledger.Allocations.Select(a => a.SiteId).Distinct(StringComparer.Ordinal).Count())
            throw new InvalidOperationException("Subscription change conflicts with committed allocations.");
        Save(ledger with { Terms = terms }, true);
    }

    public byte[] Issue(ReadOnlySpan<byte> requestBytes, string siteId, DateTimeOffset now)
    {
        if (!ValidId(siteId)) throw new InvalidDataException("Invalid site ID.");
        var request = OfflineActivationRequest.Verify(requestBytes);
        var requestHash = Convert.ToHexString(SHA256.HashData(requestBytes));
        using var gate = Lock();
        var ledger = Read();
        if (ledger.Allocations.Any(a => a.InstallationKeySha256 == request.InstallationKeySha256 &&
            a.RevocationEnvelope is not null))
            throw new InvalidOperationException("Revoked allocation cannot renew or replay issuance.");
        var prior = ledger.Requests.SingleOrDefault(r => r.RequestId == request.RequestId);
        if (prior is not null)
        {
            if (prior.RequestSha256 != requestHash || prior.SiteId != siteId)
                throw new CryptographicException("Request ID replay with different data.");
            // Return the original committed bytes, never spend another seat.
            return Encoding.ASCII.GetBytes(prior.Envelope);
        }
        var terms = ledger.Terms;
        ValidateTerms(terms, now);
        if (ledger.Requests.Count >= 10000) throw new InvalidOperationException("Ledger retention limit reached.");
        var existing = ledger.Allocations.SingleOrDefault(a => a.InstallationKeySha256 == request.InstallationKeySha256);
        Allocation next;
        if (existing is null)
        {
            if (ledger.Allocations.Count >= terms.MaxNodes)
                throw new InvalidOperationException("Subscription node allocation exhausted.");
            var sites = ledger.Allocations.Select(a => a.SiteId).ToHashSet(StringComparer.Ordinal);
            if (!sites.Contains(siteId) && sites.Count >= terms.MaxSites)
                throw new InvalidOperationException("Subscription site allocation exhausted.");
            next = new("node-" + Guid.NewGuid().ToString("N"), siteId, request.InstallationKeySha256, 1);
        }
        else
        {
            if (existing.SiteId != siteId) throw new InvalidOperationException("Site transfer requires an approved reallocation.");
            next = existing with { Revision = checked(existing.Revision + 1) };
        }

        var file = MakeLicense(terms, next, now);
        var verified = verifier.Verify(file, request.InstallationKeySha256, now);
        if (verified.Validity != LicenseValidity.Active) throw new InvalidOperationException("Cannot issue an inactive license.");
        if (existing is not null) ledger.Allocations.Remove(existing);
        ledger.Allocations.Add(next);
        ledger.Requests.Add(new(request.RequestId, requestHash, siteId, Encoding.ASCII.GetString(file)));
        // Commit seat and response before returning it. If output transfer
        // fails, repeat the exact request to retrieve the committed envelope.
        Save(ledger, true);
        return file;
    }

    // Revocation does not free an offline seat: the old node may still run
    // until it receives the document or expires. A separate approved recovery
    // policy is required for replacement/reallocation.
    public byte[] Revoke(string allocationId, DateTimeOffset now)
    {
        if (!ValidId(allocationId)) throw new InvalidDataException("Invalid allocation ID.");
        using var gate = Lock();
        var ledger = Read();
        var node = ledger.Allocations.SingleOrDefault(a => a.AllocationId == allocationId)
            ?? throw new InvalidOperationException("Unknown allocation.");
        if (node.RevocationEnvelope is not null) return Encoding.ASCII.GetBytes(node.RevocationEnvelope);
        var terms = ledger.Terms;
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1, product = "GatewayCore", licenseId = terms.LicenseId,
            customerId = terms.CustomerId, deploymentId = terms.DeploymentId,
            allocationId = node.AllocationId, installationKeySha256 = node.InstallationKeySha256,
            revokedAt = now.ToUnixTimeSeconds()
        });
        var prefix = "GCV1." + keyId + "." + Encode(payload);
        var envelope = prefix + "." + Encode(signer.SignData(Encoding.ASCII.GetBytes(prefix),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
        ledger.Allocations.Remove(node);
        ledger.Allocations.Add(node with { RevocationEnvelope = envelope });
        Save(ledger, true);
        return Encoding.ASCII.GetBytes(envelope);
    }

    private byte[] MakeLicense(Subscription terms, Allocation node, DateTimeOffset now)
    {
        var utc = now.ToUnixTimeSeconds();
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1, product = "GatewayCore", licenseId = terms.LicenseId,
            customerId = terms.CustomerId, deploymentId = terms.DeploymentId,
            allocationId = node.AllocationId, installationKeySha256 = node.InstallationKeySha256,
            edition = terms.Edition, revision = node.Revision, maxNodes = terms.MaxNodes,
            maxSites = terms.MaxSites, issuedAt = utc, notBefore = utc, expiresAt = terms.ExpiresAt,
            features = terms.Features
        });
        var prefix = "GCL1." + keyId + "." + Encode(payload);
        return Encoding.ASCII.GetBytes(prefix + "." + Encode(signer.SignData(Encoding.ASCII.GetBytes(prefix),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
    }

    private void ValidateTerms(Subscription terms, DateTimeOffset now)
    {
        var node = new Allocation("validation", "validation", new string('A', 64), 1);
        var validated = verifier.Verify(MakeLicense(terms, node, now), node.InstallationKeySha256, now);
        if (validated.Validity != LicenseValidity.Active)
            throw new InvalidDataException("Subscription must be currently active.");
    }

    private static string Encode(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static bool ValidId(string? s) => s is { Length: >= 1 and <= 80 } &&
        s.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');

    private FileStream Lock()
    {
        var parent = Path.GetDirectoryName(path)!;
        var info = new DirectoryInfo(parent);
        if (!info.Exists || (info.Attributes & FileAttributes.ReparsePoint) != 0 ||
            (OperatingSystem.IsLinux() && File.GetUnixFileMode(parent) !=
             (UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute)))
            throw new InvalidDataException("Issuer requires a provisioned private directory.");
        return new FileStream(path + ".lock", Options(FileMode.OpenOrCreate));
    }

    private static FileStreamOptions Options(FileMode mode)
    {
        var result = new FileStreamOptions { Mode = mode, Access = FileAccess.ReadWrite, Share = FileShare.None };
        if (OperatingSystem.IsLinux()) result.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        return result;
    }

    private IssuerLedger Read()
    {
        if ((File.GetAttributes(path) & (FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0 ||
            (OperatingSystem.IsLinux() && File.GetUnixFileMode(path) != (UnixFileMode.UserRead | UnixFileMode.UserWrite)))
            throw new InvalidDataException("Unsafe issuer ledger.");
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is < 1 or > MaxLedgerBytes) throw new InvalidDataException("Invalid ledger size.");
        var ledger = JsonSerializer.Deserialize<IssuerLedger>(input) ?? throw new InvalidDataException("Invalid ledger.");
        if (ledger.KeyId != keyId || ledger.KeySha256 != keyHash ||
            ledger.Allocations.Count > 10000 || ledger.Requests.Count > 10000 ||
            ledger.Allocations.Select(x => x.AllocationId).Distinct(StringComparer.Ordinal).Count() != ledger.Allocations.Count ||
            ledger.Allocations.Select(x => x.InstallationKeySha256).Distinct(StringComparer.Ordinal).Count() != ledger.Allocations.Count ||
            ledger.Requests.Select(x => x.RequestId).Distinct(StringComparer.Ordinal).Count() != ledger.Requests.Count)
            throw new InvalidDataException("Ledger authority mismatch or duplicate allocations.");
        return ledger;
    }

    private void Save(IssuerLedger ledger, bool overwrite)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(ledger);
        if (bytes.Length > MaxLedgerBytes) throw new InvalidDataException("Ledger size limit exceeded.");
        var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var file = new FileStream(temp, Options(FileMode.CreateNew)))
            {
                file.Write(bytes);
                file.Flush(true);
            }
            File.Move(temp, path, overwrite);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }
}
