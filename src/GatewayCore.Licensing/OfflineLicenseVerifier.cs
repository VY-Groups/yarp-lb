using System.Collections.Frozen;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GatewayCore.Licensing;

public enum LicenseValidity { NotYetValid, Active, Expired, Revoked }

// A checkpoint is an input from a trusted local state store, not proof of
// rollback resistance by itself. Persistence and replacement are separate gates.
public sealed record LicenseCheckpoint(string LicenseId, string AllocationId,
    string CustomerId, string DeploymentId, long Revision, string PayloadSha256);

public sealed record VerifiedLicense(
    string LicenseId, string CustomerId, string DeploymentId, string AllocationId,
    string InstallationKeySha256, string Edition, long Revision, int MaxNodes,
    int MaxSites, DateTimeOffset IssuedAt, DateTimeOffset NotBefore,
    DateTimeOffset ExpiresAt, FrozenSet<string> Features, string PayloadSha256,
    LicenseValidity Validity)
{
    public bool Allows(string feature) => Validity == LicenseValidity.Active && Features.Contains(feature);
    public LicenseCheckpoint Checkpoint => new(LicenseId, AllocationId, CustomerId, DeploymentId, Revision, PayloadSha256);
}

// Customer-side verification only. No production signing secret, network
// client, fallback entitlement, or authority-provided key embedded in a license.
public sealed class OfflineLicenseVerifier
{
    public const int MaxLicenseBytes = 16384;
    private const string P256 = "1.2.840.10045.3.1.7";
    private static readonly FrozenSet<string> SupportedFeatures = new[]
    {
        "l7", "tls", "monitoring", "ha", "fleet", "gslb", "waf", "l4",
        "dc-dr", "enterprise-sso", "audit", "gitops"
    }.ToFrozenSet(StringComparer.Ordinal);
    private static readonly FrozenSet<string> Fields = new[]
    {
        "schemaVersion", "product", "licenseId", "customerId", "deploymentId",
        "allocationId", "installationKeySha256", "edition", "revision",
        "maxNodes", "maxSites", "issuedAt", "notBefore", "expiresAt", "features"
    }.ToFrozenSet(StringComparer.Ordinal);

    private readonly FrozenDictionary<string, byte[]> keys;

    public OfflineLicenseVerifier(IReadOnlyDictionary<string, byte[]> trustedPublicKeys)
    {
        ArgumentNullException.ThrowIfNull(trustedPublicKeys);
        if (trustedPublicKeys.Count is < 1 or > 16)
            throw new ArgumentException("A bounded, nonempty trusted signing key set is required.");
        var copy = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var (id, bytes) in trustedPublicKeys)
        {
            if (!ValidId(id) || bytes is null || bytes.Length is < 1 or > 256)
                throw new ArgumentException("Invalid trusted key configuration.");
            var spki = bytes.ToArray();
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(spki, out var read);
            if (read != spki.Length || key.ExportParameters(false).Curve.Oid.Value != P256)
                throw new ArgumentException("Only complete P-256 public keys are supported.");
            copy.Add(id, spki);
        }
        keys = copy.ToFrozenDictionary(StringComparer.Ordinal);
    }

    // Input is exact ASCII GCL1.<key-id>.<base64url JSON>.<base64url signature>.
    // Signature covers the first three segments verbatim, including format
    // and signing key identifier; verification precedes any payload parsing.
    public VerifiedLicense Verify(ReadOnlySpan<byte> file, string expectedInstallationKeySha256,
        DateTimeOffset now, LicenseCheckpoint? checkpoint = null)
    {
        if (!ValidHash(expectedInstallationKeySha256))
            throw new ArgumentException("Expected installation identity must be a SHA-256 hex digest.");
        if (file.Length is < 1 or > MaxLicenseBytes)
            throw new InvalidDataException("License size outside supported bounds.");
        foreach (var b in file)
            if (b is < 33 or > 126) throw new InvalidDataException("License must be exact printable ASCII.");
        var parts = Encoding.ASCII.GetString(file).Split('.');
        if (parts.Length != 4 || parts[0] != "GCL1" || !ValidId(parts[1]) ||
            !keys.TryGetValue(parts[1], out var spki))
            throw new InvalidDataException("Unknown license format or signing key.");
        var payload = Decode(parts[2], 8192);
        var signature = Decode(parts[3], 64);
        if (signature.Length != 64) throw new InvalidDataException("Invalid signature length.");
        using (var key = ECDsa.Create())
        {
            key.ImportSubjectPublicKeyInfo(spki, out _);
            var signed = Encoding.ASCII.GetBytes(string.Join(".", parts, 0, 3));
            if (!key.VerifyData(signed, signature, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                throw new CryptographicException("License signature verification failed.");
        }

        using var document = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("License payload must be an object.");
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!Fields.Contains(property.Name) || !seen.Add(property.Name))
                throw new InvalidDataException("Unexpected or duplicate license property.");
        if (seen.Count != Fields.Count) throw new InvalidDataException("Missing license property.");
        if (Integer(root, "schemaVersion", 1, 1) != 1 || String(root, "product") != "GatewayCore")
            throw new InvalidDataException("Unsupported product or schema.");

        var licenseId = Id(root, "licenseId");
        var customerId = Id(root, "customerId");
        var deploymentId = Id(root, "deploymentId");
        var allocationId = Id(root, "allocationId");
        var installationHash = String(root, "installationKeySha256");
        if (!ValidHash(installationHash) || !CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(installationHash), Convert.FromHexString(expectedInstallationKeySha256)))
            throw new CryptographicException("License is not allocated to this installation.");
        var edition = String(root, "edition");
        if (edition is not ("evaluation" or "standard" or "professional" or "enterprise" or "custom"))
            throw new InvalidDataException("Unsupported edition.");
        var revision = Integer(root, "revision", 1, long.MaxValue);
        var maxNodes = (int)Integer(root, "maxNodes", 1, 10000);
        var maxSites = (int)Integer(root, "maxSites", 1, 10000);
        if (maxSites > maxNodes) throw new InvalidDataException("Invalid site allocation.");
        var issued = Timestamp(root, "issuedAt");
        var notBefore = Timestamp(root, "notBefore");
        var expires = Timestamp(root, "expiresAt");
        if (issued > notBefore || notBefore >= expires || issued > now.AddMinutes(5))
            throw new InvalidDataException("Invalid license validity period.");
        var featureArray = root.GetProperty("features");
        if (featureArray.ValueKind != JsonValueKind.Array || featureArray.GetArrayLength() > SupportedFeatures.Count)
            throw new InvalidDataException("Invalid feature array.");
        var features = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in featureArray.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.String || item.GetString() is not string feature ||
                !SupportedFeatures.Contains(feature) || !features.Add(feature))
                throw new InvalidDataException("Unknown or duplicate feature.");
        }
        if (features.Count == 0) throw new InvalidDataException("Empty entitlement.");
        var digest = Convert.ToHexString(SHA256.HashData(payload));
        if (checkpoint is not null &&
            (checkpoint.LicenseId != licenseId || checkpoint.AllocationId != allocationId ||
             checkpoint.CustomerId != customerId || checkpoint.DeploymentId != deploymentId ||
             checkpoint.Revision < 1 || !ValidHash(checkpoint.PayloadSha256) ||
             revision < checkpoint.Revision ||
             (revision == checkpoint.Revision && checkpoint.PayloadSha256 != digest)))
            throw new CryptographicException("License rollback, revision equivocation or unauthorized replacement.");
        var validity = now < notBefore ? LicenseValidity.NotYetValid :
            now >= expires ? LicenseValidity.Expired : LicenseValidity.Active;
        return new(licenseId, customerId, deploymentId, allocationId, installationHash,
            edition, revision, maxNodes, maxSites, issued, notBefore, expires,
            features.ToFrozenSet(StringComparer.Ordinal), digest, validity);
    }

    // Irreversible, allocation-specific revocation. A genuine offline node
    // learns about revocation only after importing this signed document.
    public void VerifyRevocation(ReadOnlySpan<byte> file, VerifiedLicense license)
    {
        ArgumentNullException.ThrowIfNull(license);
        var parts = OfflineActivationRequest.Split(file, 8192, 4, "GCV1");
        if (!keys.TryGetValue(parts[1], out var spki))
            throw new CryptographicException("Unknown revocation signing key.");
        using var key = ECDsa.Create();
        key.ImportSubjectPublicKeyInfo(spki, out _);
        OfflineActivationRequest.VerifySignature(parts, key);
        using var document = JsonDocument.Parse(OfflineActivationRequest.Decode(parts[2], 4096),
            new JsonDocumentOptions { MaxDepth = 2 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Invalid revocation payload.");
        var fields = new HashSet<string>(new[] { "schemaVersion", "product", "licenseId", "customerId",
            "deploymentId", "allocationId", "installationKeySha256", "revokedAt" }, StringComparer.Ordinal);
        foreach (var property in root.EnumerateObject())
            if (!fields.Remove(property.Name)) throw new InvalidDataException("Unknown or duplicate revocation property.");
        if (fields.Count != 0 || Integer(root, "schemaVersion", 1, 1) != 1 ||
            String(root, "product") != "GatewayCore" || Id(root, "licenseId") != license.LicenseId ||
            Id(root, "customerId") != license.CustomerId || Id(root, "deploymentId") != license.DeploymentId ||
            Id(root, "allocationId") != license.AllocationId ||
            String(root, "installationKeySha256") != license.InstallationKeySha256)
            throw new CryptographicException("Revocation is not for this allocation.");
        _ = Timestamp(root, "revokedAt");
    }

    private static bool ValidId(string? value) => value is { Length: >= 1 and <= 80 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
    private static bool ValidHash(string? value) => value is { Length: 64 } &&
        value.All(c => c is >= '0' and <= '9' or >= 'A' and <= 'F');

    private static byte[] Decode(string value, int max)
    {
        if (value.Length == 0 || value.Length > ((max + 2) / 3) * 4 ||
            value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw new InvalidDataException("Invalid base64url field.");
        var padded = value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '=');
        var bytes = Convert.FromBase64String(padded);
        if (bytes.Length > max || Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_') != value)
            throw new InvalidDataException("Noncanonical base64url field.");
        return bytes;
    }
    private static string String(JsonElement root, string name) =>
        root.GetProperty(name).ValueKind == JsonValueKind.String
            ? root.GetProperty(name).GetString()! : throw new InvalidDataException("Expected license string.");
    private static string Id(JsonElement root, string name)
    {
        var value = String(root, name);
        return ValidId(value) ? value : throw new InvalidDataException("Invalid license identifier.");
    }
    private static long Integer(JsonElement root, string name, long min, long max)
    {
        var element = root.GetProperty(name);
        if (element.ValueKind != JsonValueKind.Number || !element.TryGetInt64(out var value) ||
            value < min || value > max || element.GetRawText() != value.ToString(CultureInfo.InvariantCulture))
            throw new InvalidDataException("Invalid license integer.");
        return value;
    }
    private static DateTimeOffset Timestamp(JsonElement root, string name) =>
        DateTimeOffset.FromUnixTimeSeconds(Integer(root, name, 0, 4102444800L));
}
