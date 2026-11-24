using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using Microsoft.AspNetCore.DataProtection;
using GatewayCore.Gslb.Contracts;

/// <summary>
/// Linux/on-premise ASP.NET Data Protection key-ring envelope encryption.
/// No plaintext key-ring fallback outside disposable CI EC2 lab mode.
/// No secrets are accepted as process arguments or embedded in appsettings.
/// </summary>
public static class LinuxKeyProtection
{
    private const UnixFileMode PrivateDirectoryMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode SecretFileMode =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode PublicPermissions =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    public static string InitializeStateDirectory()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Linux key protector is Linux-only");
        var root = Environment.GetEnvironmentVariable("YARP_CONTROL_PLANE_DIR");
        if (string.IsNullOrWhiteSpace(root) || !Path.IsPathFullyQualified(root))
            throw new InvalidOperationException(
                "Set YARP_CONTROL_PLANE_DIR to an absolute private Linux directory");
        root = Path.GetFullPath(root);
        if (root == "/" || root == "/tmp" || root == "/var" || root == "/var/lib")
            throw new InvalidOperationException("Refusing unsafe Linux data-protection state root");
        // Path-based CreateDirectory can traverse a parent symlink before
        // CheckPrivateDirectory ever runs. Create/inspect each component
        // relative to already-opened no-follow Linux directory handles.
        // Reject a linked (including dangling-linked) ancestor *before*
        // creating anything beneath its target.
        var keyDir = Path.Combine(root, "data-protection-keys");
        try
        {
            PrivateKeyFileSecurity.EnsureLinuxPrivateStateDirectory(
                root, "Linux Data Protection state");
            PrivateKeyFileSecurity.EnsureLinuxPrivateStateDirectory(
                keyDir, "Linux Data Protection key ring");
        }
        catch (InvalidDataException ex)
        {
            throw new InvalidOperationException(
                "Unsafe Linux Data Protection directory bootstrap", ex);
        }
        CheckPrivateDirectory(root);
        CheckPrivateDirectory(keyDir);
        return root;
    }

    private static void CheckPrivateDirectory(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Key directory must not be a symlink");
        try { PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(path, "Linux Data Protection state"); }
        catch (InvalidDataException ex) { throw new InvalidOperationException("Unsafe Linux Data Protection directory ancestry", ex); }
        var mode = File.GetUnixFileMode(path);
        if ((mode & PublicPermissions) != 0 || (mode & PrivateDirectoryMode) != PrivateDirectoryMode)
            throw new InvalidOperationException("State/key directory requires owner-only 0700 permissions");
    }

    private static string SecretPath(string environmentName)
    {
        var path = Environment.GetEnvironmentVariable(environmentName);
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidOperationException("Missing absolute secret file path: " + environmentName);
        path = Path.GetFullPath(path);
        if (!File.Exists(path) || (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Missing or symlinked secret: " + environmentName);
        var mode = File.GetUnixFileMode(path);
        if ((mode & PublicPermissions) != 0 || (mode & SecretFileMode) != SecretFileMode)
            throw new InvalidOperationException("Secret requires mode 0600 (no group/other access): " + environmentName);
        return path;
    }

    private static X509Certificate2 LoadRsaProtector(
        string pfxEnv, string passwordFileEnv, bool decryptionOnlyPrevious = false)
    {
        var path = SecretPath(pfxEnv);
        var passwordPath = SecretPath(passwordFileEnv);
        byte[] ReadSecret(string file, string purpose, int limit)
        {
            // Wrapper PFX and its separate password must each be independently
            // provisioned private files. A second hardlink can alias the
            // same secret inode outside the protected provisioning path;
            // validate the opened handle's link count before reading bytes.
            try { return PrivateKeyFileSecurity.ReadPrivateFileBytes(
                file, purpose, limit, requireSingleLink: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { throw new InvalidOperationException("Unsafe or unavailable Linux Data Protection secret", ex); }
        }
        var passwordBytes = ReadSecret(passwordPath, "Linux PFX password", 4096);
        X509Certificate2 cert;
        try
        {
            var password = new System.Text.UTF8Encoding(false, true).GetString(passwordBytes).TrimEnd('\r', '\n');
            if (password.Length == 0 || password.Any(char.IsControl))
                throw new InvalidOperationException("Invalid Linux PFX password");
            var pfx = ReadSecret(path, "Linux wrapping PFX", 1024 * 1024);
            try { cert = X509CertificateLoader.LoadPkcs12(pfx, password, X509KeyStorageFlags.EphemeralKeySet); }
            finally { CryptographicOperations.ZeroMemory(pfx); }
        }
        finally { CryptographicOperations.ZeroMemory(passwordBytes); }
        try
        {
            using var privateKey = cert.GetRSAPrivateKey();
            // Do not use a CA signing key or signing-only TLS identity as
            // an ASP.NET Data Protection XML envelope key. The dedicated
            // RSA leaf must explicitly authorize key encipherment.
            var usage = cert.Extensions.OfType<X509KeyUsageExtension>().ToArray();
            var constraints = cert.Extensions.OfType<X509BasicConstraintsExtension>().ToArray();
            if (privateKey is null || privateKey.KeySize < 2048 ||
                usage.Length != 1 ||
                (usage[0].KeyUsages & X509KeyUsageFlags.KeyEncipherment) == 0 ||
                constraints.Length != 1 || constraints[0].CertificateAuthority ||
                cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
                (!decryptionOnlyPrevious &&
                 cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(1)))
                throw new InvalidOperationException(
                    "Linux Data Protection requires a valid RSA >=2048 leaf wrapping certificate with explicit keyEncipherment usage and a private key");
            return cert;
        }
        catch
        {
            cert.Dispose();
            throw;
        }
    }

    // ProtectKeysWithCertificate only wraps newly persisted keys. It does
    // not reject a legacy plaintext ring imported from an earlier lab.
    // Inspect existing XML without modifying it or deserializing key types.
    private static void ValidateExistingKeyRing(string directory)
    {
        const string protectionNamespace = "http://schemas.asp.net/2015/03/dataProtection";
        // Bound and validate the full restore inventory before framework import.
        const int MaximumKeyRingXmlFiles = 512;
        var inventory = Directory.EnumerateFiles(directory, "*.xml")
            .Take(MaximumKeyRingXmlFiles + 1).ToArray();
        if (inventory.Length > MaximumKeyRingXmlFiles)
            throw new InvalidOperationException(
                "Linux Data Protection key-ring XML inventory exceeds 512 entries");
        var seenKeys = new HashSet<Guid>();
        foreach (var path in inventory)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML must not be a symlink");
            if ((File.GetUnixFileMode(path) & PublicPermissions) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML requires owner-only permissions");
            byte[] bytes;
            try { bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(path, "Linux key-ring XML", 1024 * 1024,
                requireSingleLink: true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            { throw new InvalidOperationException("Unsafe existing Linux key-ring XML", ex); }
            try
            {
                using var stream = new MemoryStream(bytes, writable: false);
                using var reader = XmlReader.Create(stream, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = 1024 * 1024
                });
                if (reader.MoveToContent() != XmlNodeType.Element)
                    throw new InvalidOperationException("Existing Linux key-ring XML has no root element");
                var rootName = reader.LocalName;
                var rootNamespace = reader.NamespaceURI;
                var isRevocation = rootName == "revocation" && rootNamespace.Length == 0;
                var isKey = rootName == "key" && rootNamespace.Length == 0;
                if (!isRevocation && !isKey)
                    throw new InvalidOperationException(
                        "Existing Linux key ring is not certificate-wrapped; isolate and recover an approved protected backup");

                if (isKey)
                {
                    // Data Protection identifies keys by GUID, so the file name
                    // and embedded id must describe the same unique key.
                    var id = reader.GetAttribute("id");
                    if (!Guid.TryParseExact(id, "D", out var keyId) ||
                        !string.Equals(Path.GetFileName(path),
                            "key-" + keyId.ToString("D") + ".xml",
                            StringComparison.OrdinalIgnoreCase) ||
                        !seenKeys.Add(keyId))
                        throw new InvalidOperationException(
                            "Linux Data Protection key-ring XML identity mismatch or duplicate");
                }

                // Walk element names only. Do not materialize the document's
                // text into an XDocument, where a legacy plaintext master key
                // would become a long-lived managed string.
                var encryptedSecretCount = 0;
                while (reader.Read())
                {
                    if (reader.NodeType != XmlNodeType.Element) continue;
                    if (reader.LocalName == "masterKey" ||
                        (isRevocation && reader.LocalName == "encryptedSecret"))
                        throw new InvalidOperationException(
                            "Existing Linux key-ring XML contains unexpected key material");
                    if (isKey && reader.LocalName == "encryptedSecret")
                    {
                        // A foreign namespace may hide extra secret material
                        // alongside the approved certificate-wrapped element.
                        if (reader.NamespaceURI != protectionNamespace)
                            throw new InvalidOperationException(
                                "Linux key-ring XML contains a foreign encryptedSecret element");
                        var decryptor = reader.GetAttribute("decryptorType");
                        var assemblyQualified = decryptor?.Split(
                            ',', StringSplitOptions.TrimEntries);
                        if (assemblyQualified is null || assemblyQualified.Length < 2 ||
                            assemblyQualified[0] !=
                                "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor" ||
                            assemblyQualified[1] != "Microsoft.AspNetCore.DataProtection")
                            throw new InvalidOperationException(
                                "Linux key-ring XML is not from the approved certificate decryptor");
                        encryptedSecretCount++;
                    }
                }
                if (isKey && encryptedSecretCount != 1)
                    throw new InvalidOperationException(
                        "Existing Linux key ring is not certificate-wrapped; isolate and recover an approved protected backup");
            }
            finally
            {
                // Clear the bounded source buffer even if XML parsing or a
                // plaintext-key rejection fails.
                CryptographicOperations.ZeroMemory(bytes);
            }
        }
    }

    // Refuse silent retirement of a historic wrapping identity. ASP.NET Core
    // can otherwise start with a valid new certificate while old persisted
    // keys remain encrypted under a now-missing previous private key; old
    // authentication cookies fail later, after traffic has been admitted.
    // Inspection is read-only and never exports/decrypts a master key.
    private static void RequireHistoricWrappingCertificates(
        string keyDirectory, X509Certificate2 current, X509Certificate2? previous)
    {
        const string protectedNs = "http://schemas.asp.net/2015/03/dataProtection";
        const string xmldsigNs = "http://www.w3.org/2000/09/xmldsig#";
        const int maximumKeyFiles = 512;
        var keys = Directory.EnumerateFiles(keyDirectory, "key-*.xml")
            .Take(maximumKeyFiles + 1).ToArray();
        if (keys.Length > maximumKeyFiles)
            throw new InvalidOperationException("Historic encrypted key-ring inventory is unbounded");
        var activeRecipient = current.RawData;
        var historicRecipient = previous?.RawData;
        try
        {
            foreach (var path in keys)
            {
                var bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                    path, "Historic Data Protection encrypted XML", 1024 * 1024,
                    requireSingleLink: true);
                try
                {
                    using var stream = new MemoryStream(bytes, writable: false);
                    using var reader = XmlReader.Create(stream, new XmlReaderSettings
                    {
                        DtdProcessing = DtdProcessing.Prohibit,
                        XmlResolver = null,
                        MaxCharactersInDocument = 1024 * 1024
                    });
                    var envelopeDepth = -1;
                    var recipientCount = 0;
                    while (reader.Read())
                    {
                        if (reader.NodeType == XmlNodeType.Element &&
                            reader.LocalName == "encryptedSecret" &&
                            reader.NamespaceURI == protectedNs)
                        {
                            if (envelopeDepth != -1)
                                throw new InvalidOperationException(
                                    "Ambiguous Data Protection certificate envelope");
                            envelopeDepth = reader.Depth;
                        }
                        else if (reader.NodeType == XmlNodeType.EndElement &&
                                 reader.LocalName == "encryptedSecret" &&
                                 reader.NamespaceURI == protectedNs &&
                                 reader.Depth == envelopeDepth)
                        {
                            envelopeDepth = -1;
                        }
                        else if (reader.NodeType == XmlNodeType.Element &&
                                 reader.LocalName == "X509Certificate" &&
                                 reader.NamespaceURI == xmldsigNs &&
                                 envelopeDepth >= 0 &&
                                 reader.Depth > envelopeDepth)
                        {
                            // This is the PUBLIC embedded recipient cert, not
                            // the encrypted DP key or private wrapping PFX.
                            var encoded = reader.ReadElementContentAsString();
                            if (encoded.Length is < 1 or > 16384)
                                throw new InvalidOperationException(
                                    "Invalid bounded encrypted-key recipient");
                            byte[] recipient;
                            try { recipient = Convert.FromBase64String(encoded); }
                            catch (FormatException)
                            {
                                throw new InvalidOperationException(
                                    "Malformed encrypted-key recipient certificate");
                            }
                            try
                            {
                                if (!CryptographicOperations.FixedTimeEquals(
                                        recipient, activeRecipient) &&
                                    (historicRecipient is null ||
                                     !CryptographicOperations.FixedTimeEquals(
                                         recipient, historicRecipient)))
                                    throw new InvalidOperationException(
                                        "Historic Data Protection certificate cannot be retired while its keys remain");
                                recipientCount++;
                            }
                            finally { CryptographicOperations.ZeroMemory(recipient); }
                        }
                    }
                    if (recipientCount == 0 || recipientCount > 4)
                        throw new InvalidOperationException(
                            "Encrypted Data Protection key lacks approved public wrapping recipient");
                }
                finally { CryptographicOperations.ZeroMemory(bytes); }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(activeRecipient);
            if (historicRecipient is not null)
                CryptographicOperations.ZeroMemory(historicRecipient);
        }
    }

    public static void Configure(IDataProtectionBuilder dataProtection, string rootDirectory)
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Linux key protector is Linux-only");
        CheckPrivateDirectory(rootDirectory);
        var keyDirectory = Path.Combine(rootDirectory, "data-protection-keys");
        CheckPrivateDirectory(keyDirectory);
        ValidateExistingKeyRing(keyDirectory);
        // During a deliberately staged fleet restore, the independently held
        // signed checkpoint and minimum revision must match before key import.
        LinuxDpRecoveryEvidence.VerifyConfigured(keyDirectory);
        var current = LoadRsaProtector("YARP_LINUX_DP_CERT_PFX_PATH",
            "YARP_LINUX_DP_CERT_PASSWORD_FILE");
        // Optional overlap only during planned protection certificate rotation.
        // Previously persisted XML keys still require the old private key.
        var old = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PFX_PATH");
        var oldPassword = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE");
        if (string.IsNullOrEmpty(old) != string.IsNullOrEmpty(oldPassword))
            throw new InvalidOperationException("Old PFX and its password file must be specified together");
        // Historic wrapping certificates are decrypt-only. Their
        // expiration must prohibit NEW key encryption, but not invalidate
        // already-issued cookies that depend on an encrypted XML key whose
        // original recipient was that certificate. The old key must still
        // be RSA, private, non-CA, keyEncipherment and strictly provisioned.
        X509Certificate2? previous = null;
        if (!string.IsNullOrEmpty(old))
            previous = LoadRsaProtector("YARP_LINUX_DP_OLD_CERT_PFX_PATH",
                "YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",
                decryptionOnlyPrevious: true);

        // Require the configured identities to cover ALL persisted recipient
        // certificates BEFORE admitting any service traffic. A new active
        // identity alone must not silently break previous auth sessions.
        RequireHistoricWrappingCertificates(keyDirectory, current, previous);
        dataProtection.ProtectKeysWithCertificate(current);
        if (previous is not null)
            dataProtection.UnprotectKeysWithAnyCertificate(current, previous);
    }
}
