using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using GatewayCore.Gslb.Contracts;

/// <summary>
/// Offline-signed, operator-anchored Linux Data Protection restore checkpoint.
/// A standalone manifest next to a restored key ring is NOT an anti-rollback
/// anchor: the trusted public key and minimum revision must be provisioned
/// independently of the backup being restored.
/// </summary>
public sealed record LinuxDpRecoveryManifest(
    int Version, long Revision, string InventorySha256, string SignatureBase64);

public static class LinuxDpRecoveryEvidence
{
    public const string ManifestEnv = "YARP_LINUX_DP_RECOVERY_MANIFEST_FILE";
    public const string PublicKeyEnv = "YARP_LINUX_DP_RECOVERY_TRUST_PUBLIC_KEY_FILE";
    public const string MinimumRevisionEnv = "YARP_LINUX_DP_RECOVERY_MINIMUM_REVISION";
    // Provision this from the protected service manager, not from a restored
    // backup. Strictly require a signed inventory on a recovery-fenced node.
    public const string RequireEvidenceEnv = "YARP_LINUX_DP_REQUIRE_SIGNED_RECOVERY";
    private const int MaximumXmlFiles = 512;
    private const int MaximumXmlBytes = 1024 * 1024;
    private const string InventoryDomain = "GatewayCore.LinuxDP.Inventory.v1\n";
    private const string SignatureDomain = "GatewayCore.LinuxDP.RecoveryAttestation.v1\n";

    public static void VerifyConfigured(string keyRingDirectory)
    {
        var manifestPath = Environment.GetEnvironmentVariable(ManifestEnv);
        var trustPath = Environment.GetEnvironmentVariable(PublicKeyEnv);
        var revisionText = Environment.GetEnvironmentVariable(MinimumRevisionEnv);
        var requirement = Environment.GetEnvironmentVariable(RequireEvidenceEnv);
        if (requirement is not null && requirement is not ("true" or "false"))
            throw new InvalidOperationException(
                "Linux DP signed-recovery requirement must be exactly true or false");
        if (manifestPath is null && trustPath is null && revisionText is null)
        {
            if (requirement == "true")
                throw new InvalidOperationException(
                    "Mandatory Linux DP recovery attestation missing");
            return; // Standalone non-recovery mode remains backward compatible.
        }

        if (string.IsNullOrWhiteSpace(manifestPath) ||
            string.IsNullOrWhiteSpace(trustPath) ||
            !long.TryParse(revisionText, NumberStyles.None, CultureInfo.InvariantCulture,
                out var trustedMinimumRevision) || trustedMinimumRevision < 1 ||
            !Path.IsPathFullyQualified(manifestPath) ||
            !Path.IsPathFullyQualified(trustPath))
            throw new InvalidOperationException(
                "Signed Linux DP recovery requires an external manifest, trust key and minimum revision");
        Verify(keyRingDirectory, manifestPath, trustPath, trustedMinimumRevision);
    }

    /// <summary>
    /// Fail closed before ASP.NET Data Protection imports any restored key.
    /// This never modifies the key ring or the signed checkpoint.
    /// </summary>
    public static void Verify(string keyRingDirectory, string manifestPath,
        string publicKeyPath, long trustedMinimumRevision)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Signed Linux DP recovery verification is Linux-only");
        if (trustedMinimumRevision < 1 ||
            string.IsNullOrWhiteSpace(keyRingDirectory) ||
            !Path.IsPathFullyQualified(keyRingDirectory) ||
            string.IsNullOrWhiteSpace(manifestPath) ||
            !Path.IsPathFullyQualified(manifestPath) ||
            string.IsNullOrWhiteSpace(publicKeyPath) ||
            !Path.IsPathFullyQualified(publicKeyPath))
            throw new InvalidOperationException("Invalid signed Linux DP recovery paths or minimum revision");

        byte[] manifestBytes;
        byte[] publicKeyBytes;
        try
        {
            manifestBytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                manifestPath, "Signed Linux DP recovery checkpoint", 16_384);
            publicKeyBytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                publicKeyPath, "Trusted Linux DP recovery verification key", 16_384);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            throw new InvalidOperationException("Unsafe Linux DP recovery attestation files", ex);
        }

        try
        {
            LinuxDpRecoveryManifest manifest;
            try
            {
                _ = new UTF8Encoding(false, true).GetCharCount(manifestBytes);
                using var document = JsonDocument.Parse(manifestBytes,
                    new JsonDocumentOptions { MaxDepth = 3 });
                if (document.RootElement.ValueKind != JsonValueKind.Object)
                    throw new InvalidOperationException("Recovery attestation must be one JSON object");
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in document.RootElement.EnumerateObject())
                    if (!names.Add(property.Name))
                        throw new InvalidOperationException("Duplicate or aliased recovery attestation property");
                manifest = JsonSerializer.Deserialize<LinuxDpRecoveryManifest>(manifestBytes,
                    new JsonSerializerOptions
                    {
                        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
                    }) ?? throw new InvalidOperationException("Missing recovery attestation");
            }
            catch (Exception ex) when (ex is JsonException or DecoderFallbackException)
            {
                throw new InvalidOperationException("Malformed Linux DP recovery attestation", ex);
            }

            if (manifest.Version != 1 || manifest.Revision < trustedMinimumRevision ||
                manifest.Revision < 1 ||
                !IsCanonicalHexDigest(manifest.InventorySha256))
                throw new InvalidOperationException(
                    "Recovery attestation version, revision or inventory digest rejected");

            byte[] signature;
            try { signature = Convert.FromBase64String(manifest.SignatureBase64 ?? ""); }
            catch (FormatException ex)
            {
                throw new InvalidOperationException("Invalid recovery signature encoding", ex);
            }
            try
            {
                if (signature.Length != 64)
                    throw new InvalidOperationException("Recovery signature must be P-256 IEEE P1363");
                var pem = new UTF8Encoding(false, true).GetString(publicKeyBytes);
                if (!pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
                    pem.Contains("PRIVATE KEY", StringComparison.Ordinal))
                    throw new InvalidOperationException("Recovery trust key must be SPKI public PEM");
                using var verifier = ECDsa.Create();
                verifier.ImportFromPem(pem);
                if (verifier.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7" ||
                    !verifier.VerifyData(CanonicalPayload(manifest.Revision,
                            manifest.InventorySha256), signature,
                        HashAlgorithmName.SHA256,
                        DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
                    throw new InvalidOperationException("Recovery attestation signature rejected");
            }
            finally { CryptographicOperations.ZeroMemory(signature); }

            var actualDigest = ComputeInventoryDigest(keyRingDirectory);
            if (!CryptographicOperations.FixedTimeEquals(
                    Convert.FromHexString(actualDigest),
                    Convert.FromHexString(manifest.InventorySha256)))
                throw new InvalidOperationException(
                    "Linux DP restored key inventory differs from independently signed checkpoint");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(manifestBytes);
            CryptographicOperations.ZeroMemory(publicKeyBytes);
        }
    }

    /// <summary>
    /// Digest includes EVERY bounded encrypted XML filename and exact file
    /// ciphertext, in deterministic ordinal name order. Never accept a
    /// symlink/unsafe file and never materialize a plaintext master key.
    /// </summary>
    public static string ComputeInventoryDigest(string keyRingDirectory)
    {
        if (!OperatingSystem.IsLinux() ||
            string.IsNullOrWhiteSpace(keyRingDirectory) ||
            !Path.IsPathFullyQualified(keyRingDirectory))
            throw new InvalidOperationException("Linux DP inventory requires an absolute Linux directory");

        // This also validates every directory ancestor and its ownership/mode.
        try
        {
            PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(
                keyRingDirectory, "Linux DP recovery inventory");
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidOperationException("Unsafe Linux DP recovery inventory path", ex);
        }
        var files = Directory.EnumerateFiles(keyRingDirectory, "*.xml")
            .Take(MaximumXmlFiles + 1)
            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
            .ToArray();
        if (files.Length is < 1 or > MaximumXmlFiles)
            throw new InvalidOperationException("Restore requires 1..512 encrypted Linux DP XML entries");

        using var aggregate = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        aggregate.AppendData(Encoding.ASCII.GetBytes(InventoryDomain));
        foreach (var file in files)
        {
            var filename = Path.GetFileName(file);
            if (filename.Length is < 8 or > 128 ||
                filename.Any(ch => !char.IsAsciiLetterOrDigit(ch) &&
                    ch is not ('-' or '_' or '.')))
                throw new InvalidOperationException("Invalid restored DP XML inventory filename");

            byte[] bytes;
            try
            {
                bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                    file, "Linux DP recovery XML ciphertext", MaximumXmlBytes);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                throw new InvalidOperationException("Unsafe restored Linux DP inventory entry", ex);
            }
            try
            {
                var fileDigest = Convert.ToHexString(SHA256.HashData(bytes));
                aggregate.AppendData(Encoding.ASCII.GetBytes(filename + "\n" + fileDigest + "\n"));
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        return Convert.ToHexString(aggregate.GetHashAndReset());
    }

    internal static byte[] CanonicalPayload(long revision, string inventorySha256)
    {
        if (revision < 1 || !IsCanonicalHexDigest(inventorySha256))
            throw new InvalidOperationException("Noncanonical DP recovery signature payload");
        return Encoding.ASCII.GetBytes(SignatureDomain +
            revision.ToString(CultureInfo.InvariantCulture) + "\n" +
            inventorySha256 + "\n");
    }

    private static bool IsCanonicalHexDigest(string? value) =>
        value is { Length: 64 } &&
        value.All(ch => ch is >= '0' and <= '9' or >= 'A' and <= 'F');
}
