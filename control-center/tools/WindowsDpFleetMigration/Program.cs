using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;

/// <summary>
/// Explicitly OFFLINE, source-host-only rewrapping of ASP.NET DPAPI key XML
/// into portable X.509 envelope XML without changing key IDs or user cookies.
/// Never rewrites or deletes the original source ring, and never migrates an
/// already serving remote node. Run only with all key writers independently
/// stopped and fenced. No unapproved plaintext, fallback or auto promotion.
/// </summary>
[SupportedOSPlatform("windows")]
public static class WindowsDpOfflineFleetMigration
{
    public static string Stage { get; private set; } = "init";
    private const int MaxFiles = 512;
    private const int MaxXmlBytes = 131072;
    private static readonly XNamespace ProtectionNs =
        "http://schemas.asp.net/2015/03/dataProtection";
    private const string LegacyDecryptor =
        "Microsoft.AspNetCore.DataProtection.XmlEncryption.DpapiXmlDecryptor";
    private const string DpAssembly = "Microsoft.AspNetCore.DataProtection";

    private static byte[] ReadBounded(string path)
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("Linked Windows key XML refused");
        using var file = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.Read, bufferSize: 4096, FileOptions.SequentialScan);
        if (file.Length is <= 0 or > MaxXmlBytes)
            throw new InvalidOperationException("Offline key XML length invalid");
        var bytes = new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if (file.ReadByte() != -1)
            throw new InvalidOperationException("Offline key XML changed during read");
        return bytes;
    }

    private static XDocument Parse(byte[] bytes)
    {
        using var memory = new MemoryStream(bytes, writable: false);
        using var reader = XmlReader.Create(memory, new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaxXmlBytes
        });
        return XDocument.Load(reader, LoadOptions.PreserveWhitespace);
    }

    private static string KeyId(XElement root, string filename)
    {
        if (root.Name != "key" || root.Attribute("version")?.Value != "1" ||
            !Guid.TryParseExact(root.Attribute("id")?.Value, "D", out var id) ||
            !string.Equals(filename, "key-" + id.ToString("D") + ".xml",
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Unexpected legacy key identity");
        return id.ToString("D");
    }

    private static void Rewrap(XDocument document, string filename,
                               CertificateXmlEncryptor encryptor,
                               EncryptedXmlDecryptor decryptor)
    {
        var root = document.Root ??
            throw new InvalidOperationException("Legacy key XML has no root");
        KeyId(root, filename);
        // These checks precede decryption to ensure there is exactly ONE
        // framework-approved DPAPI envelope, not a hidden second secret.
        Stage = "legacy-envelope-validation";
        var secrets = root.Descendants().Where(x =>
            x.Name.LocalName == "encryptedSecret").ToArray();
        if (secrets.Length != 1 || secrets[0].Name != ProtectionNs + "encryptedSecret" ||
            root.Descendants().Any(x => x.Name.LocalName == "masterKey"))
            throw new InvalidOperationException("Legacy key has unknown secret envelope");
        var secret = secrets[0];
        var identity = secret.Attribute("decryptorType")?.Value
            .Split(',', StringSplitOptions.TrimEntries);
        if (identity is null || identity.Length < 2 ||
            identity[0] != LegacyDecryptor || identity[1] != DpAssembly ||
            secret.Elements().Count() != 1)
            throw new InvalidOperationException("Legacy XML is not an approved DPAPI key");
        // Only the original machine/service identity can decrypt this blob.
        // The plaintext XElement exists transiently in the isolated process;
        // no master secret is ever written or printed. The process terminates
        // immediately after migrating its bounded offline inventory.
        Stage = "dpapi-xml-decrypt";
        var plain = new DpapiXmlDecryptor().Decrypt(secret.Elements().Single());
        if (plain.Name.LocalName != "masterKey")
            throw new InvalidOperationException("DPAPI envelope is not a master key");
        Stage = "certificate-xml-encrypt";
        var wrapped = encryptor.Encrypt(plain);
        Stage = "certificate-roundtrip-decrypt";
        var recovered = decryptor.Decrypt(wrapped.EncryptedElement);
        if (!XNode.DeepEquals(plain, recovered))
            throw new InvalidOperationException("Portable X.509 rewrap failed self-check");
        Stage = "certificate-decryptor-type";
        var typeName = wrapped.DecryptorType.AssemblyQualifiedName;
        if (string.IsNullOrWhiteSpace(typeName) ||
            !typeName.StartsWith(
                "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor, " +
                "Microsoft.AspNetCore.DataProtection", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected certificate decryptor identity");
        Stage = "certificate-secret-replacement";
        secret.ReplaceWith(new XElement(ProtectionNs + "encryptedSecret",
            new XAttribute("decryptorType", typeName),
            new XElement(wrapped.EncryptedElement)));
        Stage = "certificate-encrypted-xml-verify";
        if (root.Descendants().Any(x => x.Name.LocalName == "masterKey") ||
            root.Descendants(ProtectionNs + "encryptedSecret").Count() != 1)
            throw new InvalidOperationException("Rewrapped key contains plaintext");
    }

    private static void PrivateWrite(string path, byte[] bytes)
    {
        using var file = new FileStream(path, FileMode.CreateNew,
            FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough);
        file.Write(bytes);
        file.Flush(flushToDisk: true);
    }

    public static int Migrate(string source, string destination,
                              string certificateThumbprint, bool approvedOffline)
    {
        if (!OperatingSystem.IsWindows() || !approvedOffline)
            throw new InvalidOperationException("Explicit offline Windows approval required");
        if (string.IsNullOrWhiteSpace(source) || string.IsNullOrWhiteSpace(destination) ||
            !Path.IsPathFullyQualified(source) || !Path.IsPathFullyQualified(destination))
            throw new InvalidOperationException("Absolute offline source and target required");
        source = Path.GetFullPath(source);
        destination = Path.GetFullPath(destination);
        if (string.Equals(source, destination, StringComparison.OrdinalIgnoreCase) ||
            destination.StartsWith(source + Path.DirectorySeparatorChar,
                                   StringComparison.OrdinalIgnoreCase) ||
            source.StartsWith(destination + Path.DirectorySeparatorChar,
                              StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Offline source and output must be disjoint");

        Stage = "source-acl";
        WindowsStateProtection.ValidateOfflineKeyRingDirectory(source);
        var targetParent = Path.GetDirectoryName(destination) ??
            throw new InvalidOperationException("Private destination parent absent");
        Stage = "target-parent-acl";
        WindowsStateProtection.ValidateOfflineKeyRingDirectory(targetParent);
        if (Directory.Exists(destination) || File.Exists(destination) ||
            new DirectoryInfo(destination).LinkTarget is not null)
            throw new InvalidOperationException("Offline migration must never overwrite");

        Stage = "approved-certificate";
        var thumbprint = WindowsFleetKeyProtection.ValidateThumbprint(
            certificateThumbprint, "approved offline migration certificate");
        using var cert = WindowsFleetKeyProtection.LoadPinnedMachineCertificate(thumbprint);
        var encryptor = new CertificateXmlEncryptor(cert, NullLoggerFactory.Instance);
        // A bare EncryptedXmlDecryptor only searches the implicit user store
        // on some Windows environments. This approved machine-store leaf
        // must be supplied through the SAME ASP.NET Data Protection
        // decryption options used by the actual fleet provider; never
        // weaken the self-check or accept an unavailable private key.
        var services = new ServiceCollection();
        services.AddDataProtection().UnprotectKeysWithAnyCertificate(cert);
        using var cryptoServices = services.BuildServiceProvider();
        var decryptor = new EncryptedXmlDecryptor(cryptoServices);
        Stage = "inventory";
        var files = Directory.EnumerateFiles(source, "*.xml",
            SearchOption.TopDirectoryOnly)
            .OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase).ToArray();
        if (files.Length is < 1 or > MaxFiles ||
            Directory.EnumerateFileSystemEntries(source).Count() != files.Length ||
            files.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                != files.Length)
            throw new InvalidOperationException("Unbounded or unexpected source inventory");

        // No migration manifest includes plaintext; these are exclusively
        // source ciphertext SHA-256 fingerprints for concurrent-write detection.
        var hashes = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        var staging = Path.Combine(targetParent,
            ".dpapi-fleet-stage-" + Guid.NewGuid().ToString("N"));
        var published = false;
        try
        {
            Stage = "create-private-stage";
            WindowsStateProtection.CreateNewOfflinePrivateDirectory(staging);
            foreach (var path in files)
            {
                var name = Path.GetFileName(path);
                Stage = "read-original";
                var raw = ReadBounded(path);
                try
                {
                    hashes.Add(name, SHA256.HashData(raw));
                    Stage = "parse-original";
                    var document = Parse(raw);
                    if (document.Root?.Name == "key")
                    {
                        Stage = "dpapi-to-cert-rewrap";
                        Rewrap(document, name, encryptor, decryptor);
                    }
                    else if (document.Root?.Name != "revocation" ||
                             document.Root.Descendants().Any(x =>
                                 x.Name.LocalName is "masterKey" or "encryptedSecret") ||
                             !name.StartsWith("revocation-", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Unapproved key-ring XML member");

                    // Revocations are passed through exactly; only encrypted
                    // key XML is serialized and it contains no plaintext.
                    var output = document.Root!.Name == "key"
                        ? Encoding.UTF8.GetBytes(document.ToString(
                            SaveOptions.DisableFormatting)) : raw.ToArray();
                    Stage = "write-private-encrypted";
                    try { PrivateWrite(Path.Combine(staging, name), output); }
                    finally { CryptographicOperations.ZeroMemory(output); }
                }
                finally { CryptographicOperations.ZeroMemory(raw); }
            }
            Stage = "validate-staged-acl";
            WindowsStateProtection.ValidateOfflineKeyRingDirectory(staging);
            Stage = "verify-source-inventory";
            var finalNames = Directory.EnumerateFiles(source, "*.xml")
                .Select(Path.GetFileName).OrderBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();
            if (!files.Select(Path.GetFileName).SequenceEqual(finalNames,
                    StringComparer.OrdinalIgnoreCase))
                throw new InvalidOperationException("Source key inventory changed while migrating");
            foreach (var path in files)
            {
                var latest = ReadBounded(path);
                try
                {
                    if (!CryptographicOperations.FixedTimeEquals(
                            hashes[Path.GetFileName(path)], SHA256.HashData(latest)))
                        throw new InvalidOperationException("Source key XML changed during migration");
                }
                finally { CryptographicOperations.ZeroMemory(latest); }
            }
            if (Directory.Exists(destination) || File.Exists(destination))
                throw new InvalidOperationException("Offline destination was claimed concurrently");
            Stage = "atomic-publish";
            Directory.Move(staging, destination);
            published = true;
            Stage = "verify-published-acl";
            WindowsStateProtection.ValidateOfflineKeyRingDirectory(destination);
            Stage = "complete";
            return files.Length;
        }
        finally
        {
            foreach (var hash in hashes.Values)
                CryptographicOperations.ZeroMemory(hash);
            if (!published && Directory.Exists(staging))
                Directory.Delete(staging, recursive: true);
        }
    }
}

public static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            // This tool is explicitly NOT a normal app startup migration.
            // The operator must separately stop/fence every source writer.
            if (args.Length != 5 || args[0] != "migrate" ||
                args[1] != "--approved-offline")
                throw new InvalidOperationException("Invalid offline migration command");
            var count = WindowsDpOfflineFleetMigration.Migrate(
                args[2], args[3], args[4], approvedOffline: true);
            Console.WriteLine("PASS: offline DPAPI keys rewrapped into a new certificate ring; " +
                              "source untouched, live promotion NOT authorized");
            return count > 0 ? 0 : 1;
        }
        catch (Exception)
        {
            // Only fixed source-authored stage names; no exception strings,
            // service SID, certificates, plaintext, file paths or key IDs.
            Console.Error.WriteLine(
                "WIN_DP_MIGRATION_FAILURE_STAGE=" + WindowsDpOfflineFleetMigration.Stage);
            Console.Error.WriteLine(
                "FAIL: offline DPAPI-to-certificate migration rejected; source remains unchanged");
            return 1;
        }
    }
}
