using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Xml;
using Microsoft.AspNetCore.DataProtection;

/// <summary>
/// Opt-in portable Windows Data Protection XML wrapping for a single-tenant
/// approved gateway fleet. Default Windows mode remains DPAPI LocalMachine.
/// Keys/cookies are NOT distributed: operators must independently protect,
/// authenticate and stage the same encrypted key ring across fleet nodes.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsFleetKeyProtection
{
    public const string CurrentThumbprintSetting = "YARP_WINDOWS_DP_CERT_THUMBPRINT";
    public const string PreviousThumbprintSetting = "YARP_WINDOWS_DP_OLD_CERT_THUMBPRINT";
    private static readonly Regex ThumbprintPattern = new(
        @"\A[0-9A-Fa-f]{40}\z", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static bool TryConfigure(IDataProtectionBuilder builder, string? encryptedKeyDirectory = null)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("Windows fleet certificate mode requires Windows");
        ArgumentNullException.ThrowIfNull(builder);

        var currentRaw = Environment.GetEnvironmentVariable(CurrentThumbprintSetting);
        var previousRaw = Environment.GetEnvironmentVariable(PreviousThumbprintSetting);
        if (currentRaw is null && previousRaw is null)
            return false; // Preserve shipping DPAPI LocalMachine default verbatim.
        var current = ValidateThumbprint(currentRaw, CurrentThumbprintSetting);
        var previous = previousRaw is null ? null
            : ValidateThumbprint(previousRaw, PreviousThumbprintSetting);
        if (previous is not null &&
            string.Equals(previous, current, StringComparison.Ordinal))
            throw new InvalidOperationException(
                "Windows fleet previous wrapping identity must differ from the current certificate");

        // A local DPAPI-wrapped XML key from a legacy install CANNOT be
        // carried to a different Windows node. Reject a mixed ring before
        // creating an apparently portable fleet provider.
        RejectLegacyOrUnwrappedKeyRing(encryptedKeyDirectory);
        var active = LoadPinnedMachineCertificate(current);
        X509Certificate2? prior = previous is null
            ? null : LoadPinnedMachineCertificate(previous);

        // No fallback to DPAPI or plaintext when an explicitly configured
        // fleet certificate is missing, expired, unusable or untrusted.
        builder.ProtectKeysWithCertificate(active);
        if (prior is not null)
            builder.UnprotectKeysWithAnyCertificate(prior);
        return true;
    }


    private static void RejectLegacyOrUnwrappedKeyRing(string? directory)
    {
        const string protectionNamespace = "http://schemas.asp.net/2015/03/dataProtection";
        const int maximumXmlFiles = 512;
        const int maximumXmlBytes = 131072;
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory) ||
            !Directory.Exists(directory) ||
            (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException(
                "Windows fleet mode requires an existing protected absolute key-ring directory");

        var inventory = Directory.EnumerateFiles(directory, "*.xml", SearchOption.TopDirectoryOnly)
            .Take(maximumXmlFiles + 1).ToArray();
        if (inventory.Length > maximumXmlFiles)
            throw new InvalidOperationException("Windows fleet key-ring XML inventory exceeds 512 entries");
        var seenKeys = new HashSet<Guid>();
        foreach (var keyXml in inventory)
        {
            var info = new FileInfo(keyXml);
            if (info.Length <= 0 || info.Length > maximumXmlBytes ||
                (info.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Windows fleet key XML is linked, empty or oversized");
            byte[] bytes;
            using (var file = File.OpenRead(keyXml))
            {
                if (file.Length <= 0 || file.Length > maximumXmlBytes)
                    throw new InvalidOperationException("Windows fleet key XML changed size");
                bytes = new byte[checked((int)file.Length)];
                file.ReadExactly(bytes);
                if (file.ReadByte() != -1)
                    throw new InvalidOperationException("Windows fleet key XML grew during inspection");
            }
            try
            {
                if ((File.GetAttributes(keyXml) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException("Windows fleet key XML became a link");
                using var stream = new MemoryStream(bytes, writable: false);
                using var reader = XmlReader.Create(stream, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = maximumXmlBytes
                });
                if (reader.MoveToContent() != XmlNodeType.Element)
                    throw new InvalidOperationException("Windows fleet key XML has no root element");
                var isKey = reader.LocalName == "key" && reader.NamespaceURI.Length == 0;
                var isRevocation = reader.LocalName == "revocation" && reader.NamespaceURI.Length == 0;
                if (!isKey && !isRevocation)
                    throw new InvalidOperationException("Windows fleet key XML has an unexpected root");
                if (isKey)
                {
                    var id = reader.GetAttribute("id");
                    if (!Guid.TryParseExact(id, "D", out var keyId) ||
                        !string.Equals(Path.GetFileName(keyXml),
                            "key-" + keyId.ToString("D") + ".xml",
                            StringComparison.OrdinalIgnoreCase) ||
                        !seenKeys.Add(keyId))
                        throw new InvalidOperationException(
                            "Windows fleet key XML identity mismatch or duplicate");
                }
                var wrappedSecrets = 0;
                while (reader.Read())
                {
                    if (reader.NodeType != XmlNodeType.Element) continue;
                    if (reader.LocalName == "masterKey" ||
                        (isRevocation && reader.LocalName == "encryptedSecret"))
                        throw new InvalidOperationException(
                            "Windows fleet key XML contains unexpected key material");
                    if (isKey && reader.LocalName == "encryptedSecret" &&
                        reader.NamespaceURI == protectionNamespace)
                    {
                        var decryptor = reader.GetAttribute("decryptorType");
                        if (decryptor is null ||
                            !decryptor.Contains("EncryptedXmlDecryptor", StringComparison.Ordinal))
                            throw new InvalidOperationException(
                                "Windows fleet key XML is not certificate-wrapped");
                        wrappedSecrets++;
                    }
                }
                if (isKey && wrappedSecrets != 1)
                    throw new InvalidOperationException(
                        "Windows fleet key XML requires exactly one certificate-wrapped secret");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    private static string ValidateThumbprint(string? raw, string name)
    {
        // Thumbprints are certificate lookup locators, not cryptographic
        // signature algorithms or bearer credentials. Require exact 40-hex
        // SHA-1 X509 store thumbprint representation; no aliasing/whitespace.
        if (raw is null || !ThumbprintPattern.IsMatch(raw))
            throw new InvalidOperationException(name +
                " must be exactly one unseparated 40-character hexadecimal certificate thumbprint");
        return raw.ToUpperInvariant();
    }

    private static X509Certificate2 LoadPinnedMachineCertificate(string thumbprint)
    {
        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var matches = store.Certificates.Find(X509FindType.FindByThumbprint,
                                              thumbprint, validOnly: false);
        if (matches.Count != 1)
            throw new InvalidOperationException(
                "Pinned Windows fleet Data Protection certificate is not unique and installed");
        var cert = matches[0];
        if (!string.Equals(cert.Thumbprint, thumbprint,
                           StringComparison.OrdinalIgnoreCase) ||
            !cert.HasPrivateKey)
            throw new InvalidOperationException(
                "Pinned Windows Data Protection certificate has no accessible private key");

        var now = DateTime.UtcNow;
        if (cert.NotBefore.ToUniversalTime() > now ||
            cert.NotAfter.ToUniversalTime() <= now.AddDays(1))
            throw new InvalidOperationException(
                "Windows Data Protection wrapping certificate is inactive or near expiry");

        var constraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
        var usages = cert.Extensions.OfType<X509KeyUsageExtension>().ToArray();
        if (constraints.Length != 1 || constraints[0].CertificateAuthority ||
            usages.Length != 1 ||
            (usages[0].KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0)
            throw new InvalidOperationException(
                "Windows fleet certificate requires a non-CA RSA encryption leaf with keyEncipherment");

        using var rsa = cert.GetRSAPrivateKey();
        if (rsa is null || rsa.KeySize < 3072)
            throw new InvalidOperationException(
                "Windows fleet certificate private key requires accessible RSA 3072+");
        var probe = RandomNumberGenerator.GetBytes(32);
        byte[]? recovered = null;
        try
        {
            var wrapped = rsa.Encrypt(probe, RSAEncryptionPadding.OaepSHA256);
            recovered = rsa.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            if (!CryptographicOperations.FixedTimeEquals(probe, recovered))
                throw new InvalidOperationException(
                    "Windows fleet certificate private key cannot decrypt a probe");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(probe);
            if (recovered is not null) CryptographicOperations.ZeroMemory(recovered);
        }
        return cert;
    }
}
