using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using GatewayCore.Gslb.Contracts;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// Offline, owner-only ciphertext backup and signed restore of a Linux
/// ASP.NET Data Protection key ring. Never copies plaintext master keys,
/// wrapping certificates, trust roots or runtime cookies. A separate
/// authorized operator MUST stop/fence writers before using this utility.
/// </summary>
public static class LinuxDpEncryptedSnapshot
{
    private const int MaximumFiles = 512;
    private const int MaximumFileBytes = 1024 * 1024;
    private const int O_RDONLY = 0;
    private const int O_CLOEXEC = 0x80000;
    private const int O_NOFOLLOW = 0x20000;
    private const int O_DIRECTORY = 0x10000;
    private const UnixFileMode PrivateDirectory =
        UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;
    private const UnixFileMode PrivateFile =
        UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private static readonly Regex ArchiveLabel = new(
        @"\A[a-z0-9][a-z0-9._-]{0,47}\z", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenDirectoryUnix(string path, int flags, uint mode);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int FsyncUnix(int descriptor);

    /// <summary>
    /// Take a non-overwriting, durable, same-device atomic snapshot of ONLY
    /// encrypted XML. The result is untrusted until an independent offline
    /// P-256 inventory signature has been generated and checked.
    /// </summary>
    public static string Capture(string ringDirectory, string archiveRoot, string label)
    {
        RequireLinux();
        RequireAbsolute(ringDirectory, "Encrypted key-ring source");
        RequireAbsolute(archiveRoot, "Independent archive root");
        if (!ArchiveLabel.IsMatch(label ?? ""))
            throw new InvalidOperationException("Invalid encrypted snapshot label");
        ValidatePrivate(ringDirectory);
        ValidatePrivate(archiveRoot);
        RequireDisjoint(archiveRoot, Path.GetDirectoryName(Path.GetFullPath(ringDirectory))!);
        var completed = Path.Combine(archiveRoot, label);
        if (File.Exists(completed) || Directory.Exists(completed))
            throw new InvalidOperationException("Encrypted snapshot already exists");
        var sourceDigest = LinuxDpRecoveryEvidence.ComputeInventoryDigest(ringDirectory);
        var staged = Path.Combine(archiveRoot, ".capture-" + Guid.NewGuid().ToString("N"));
        var stage = "stage-init";
        try
        {
            Directory.CreateDirectory(staged, PrivateDirectory);
            stage = "copy-ciphertext";
            CopyCheckedEncryptedXml(ringDirectory, staged);
            stage = "inventory-recheck";
            if (LinuxDpRecoveryEvidence.ComputeInventoryDigest(staged) != sourceDigest ||
                LinuxDpRecoveryEvidence.ComputeInventoryDigest(ringDirectory) != sourceDigest)
                throw new InvalidOperationException("Encrypted key-ring changed during offline snapshot");
            stage = "stage-fsync";
            FlushDirectory(staged);
            stage = "atomic-publish";
            // Rename is atomic in this directory on a single filesystem.
            // Directory.Move never replaces an existing directory.
            Directory.Move(staged, completed);
            stage = "root-fsync";
            FlushDirectory(archiveRoot);
            stage = "published-digest";
            if (LinuxDpRecoveryEvidence.ComputeInventoryDigest(completed) != sourceDigest)
                throw new InvalidOperationException("Committed snapshot digest changed");
            return sourceDigest;
        }
        catch (Exception e) when (e is IOException or InvalidDataException or
            InvalidOperationException or UnauthorizedAccessException or
            System.Xml.XmlException)
        {
            // Fixed stage IDs are safe for public CI; never print source paths,
            // certificate material, XML, cookies or arbitrary exception text.
            var safeStage = stage;
            if (stage == "copy-ciphertext" &&
                e is InvalidOperationException copyError &&
                copyError.Message is "Encrypted snapshot copy read" or
                    "Encrypted snapshot copy validate-xml" or
                    "Encrypted snapshot copy write")
                safeStage = copyError.Message.Replace("Encrypted snapshot copy ", "copy-");
            throw new InvalidOperationException("Encrypted snapshot stage " + safeStage, e);
        }
        finally
        {
            if (Directory.Exists(staged)) Directory.Delete(staged, recursive: true);
        }
    }

    /// <summary>
    /// Restore an independently P-256-signed snapshot into an ABSENT destination
    /// key-ring directory. Never merge into/overwrite live XML or other state.
    /// The existing Data Protection verifier is authoritative for the exact
    /// signed inventory and monotonic external minimum revision.
    /// </summary>
    public static string RestoreOffline(string snapshotDirectory, string destinationStateRoot,
        string manifestPath, string trustedPublicKeyPath, long trustedMinimumRevision)
    {
        RequireLinux();
        RequireAbsolute(snapshotDirectory, "Encrypted snapshot");
        RequireAbsolute(destinationStateRoot, "Destination Control Plane state");
        RequireAbsolute(manifestPath, "Independent P-256 recovery checkpoint");
        RequireAbsolute(trustedPublicKeyPath, "Independent recovery trust key");
        if (trustedMinimumRevision < 1)
            throw new InvalidOperationException("Independent recovery revision floor is required");

        ValidatePrivate(snapshotDirectory);
        ValidatePrivate(destinationStateRoot);
        RequireDisjoint(snapshotDirectory, destinationStateRoot);
        var destination = Path.Combine(destinationStateRoot, "data-protection-keys");
        if (Directory.Exists(destination) || File.Exists(destination) || Path.Exists(destination))
            throw new InvalidOperationException("Restoring over an existing key ring is forbidden");

        // Reject an old/forged manifest and any source drift BEFORE creating
        // a destination. Checkpoint and trust files live outside the restored
        // source tree, not inside an untrusted archive.
        LinuxDpRecoveryEvidence.Verify(snapshotDirectory, manifestPath,
            trustedPublicKeyPath, trustedMinimumRevision);
        var acceptedDigest = LinuxDpRecoveryEvidence.ComputeInventoryDigest(snapshotDirectory);
        var staged = Path.Combine(destinationStateRoot, ".restore-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(staged, PrivateDirectory);
            CopyCheckedEncryptedXml(snapshotDirectory, staged);
            LinuxDpRecoveryEvidence.Verify(staged, manifestPath,
                trustedPublicKeyPath, trustedMinimumRevision);
            if (LinuxDpRecoveryEvidence.ComputeInventoryDigest(staged) != acceptedDigest ||
                LinuxDpRecoveryEvidence.ComputeInventoryDigest(snapshotDirectory) != acceptedDigest)
                throw new InvalidOperationException("Signed snapshot changed during restore");
            FlushDirectory(staged);
            Directory.Move(staged, destination);
            FlushDirectory(destinationStateRoot);
            LinuxDpRecoveryEvidence.Verify(destination, manifestPath,
                trustedPublicKeyPath, trustedMinimumRevision);
            if (LinuxDpRecoveryEvidence.ComputeInventoryDigest(destination) != acceptedDigest)
                throw new InvalidOperationException("Restored encrypted key inventory changed");
            return acceptedDigest;
        }
        finally
        {
            if (Directory.Exists(staged)) Directory.Delete(staged, recursive: true);
        }
    }

    private static void CopyCheckedEncryptedXml(string source, string destination)
    {
        var entries = Directory.EnumerateFileSystemEntries(source).ToArray();
        if (entries.Length is < 1 or > MaximumFiles)
            throw new InvalidOperationException("Encrypted snapshot requires 1..512 XML entries");
        foreach (var path in entries.OrderBy(Path.GetFileName, StringComparer.Ordinal))
        {
            var name = Path.GetFileName(path);
            if (name.Length is < 8 or > 128 ||
                !name.EndsWith(".xml", StringComparison.Ordinal) ||
                name.Any(ch => !char.IsAsciiLetterOrDigit(ch) &&
                    ch is not ('-' or '_' or '.')))
                throw new InvalidOperationException("Unexpected file in encrypted key-ring snapshot");

            byte[]? raw = null;
            var copyStage = "read";
            try
            {
                raw = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                    path, "Encrypted DP XML snapshot entry", MaximumFileBytes,
                    requireSingleLink: true);
                copyStage = "validate-xml";
                CheckCiphertextOnly(name, raw);
                copyStage = "write";
                var output = Path.Combine(destination, name);
                using var stream = new FileStream(output, new FileStreamOptions {
                    Mode = FileMode.CreateNew,
                    Access = FileAccess.Write,
                    Share = FileShare.None,
                    Options = FileOptions.WriteThrough,
                    UnixCreateMode = PrivateFile
                });
                stream.Write(raw);
                stream.Flush(flushToDisk: true);
            }
            catch (Exception ex) when (ex is InvalidDataException or
                InvalidOperationException or IOException or UnauthorizedAccessException or
                System.Xml.XmlException)
            {
                // Only fixed source-code stage names, no filenames, XML or
                // exception text may reach public CI.
                throw new InvalidOperationException("Encrypted snapshot copy " + copyStage, ex);
            }
            finally
            {
                if (raw is not null) CryptographicOperations.ZeroMemory(raw);
            }
        }
    }

    private static void CheckCiphertextOnly(string filename, byte[] bytes)
    {
        // Use the same bounded forward-only XML constraints as the
        // production LinuxKeyProtection key-ring reader. The previously
        // used XDocument materialized decrypted-looking XML text into
        // managed strings; it also rejected legitimate wrapped metadata.
        // No master key, request body or certificate secret is materialized.
        const string protectionNamespace =
            "http://schemas.asp.net/2015/03/dataProtection";
        using var data = new MemoryStream(bytes, writable: false);
        using var reader = XmlReader.Create(data, new XmlReaderSettings {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            MaxCharactersInDocument = MaximumFileBytes
        });
        if (reader.MoveToContent() != XmlNodeType.Element ||
            reader.NamespaceURI.Length != 0)
            throw new InvalidOperationException("Encrypted XML root invalid");
        var isKey = reader.LocalName == "key";
        var isRevocation = reader.LocalName == "revocation";
        if (!isKey && !isRevocation)
            throw new InvalidOperationException("Unexpected Data Protection XML type");
        if (isKey)
        {
            if (!Guid.TryParseExact(reader.GetAttribute("id"), "D", out var id) ||
                !string.Equals(filename, "key-" + id.ToString("D") + ".xml",
                    StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Encrypted key filename/GUID mismatch");
        }
        else if (!filename.StartsWith("revocation-", StringComparison.Ordinal))
            throw new InvalidOperationException("Unexpected revocation XML filename");

        var wrappedCount = 0;
        while (reader.Read())
        {
            if (reader.NodeType != XmlNodeType.Element) continue;
            if (reader.LocalName == "masterKey" ||
                (isRevocation && reader.LocalName == "encryptedSecret"))
                throw new InvalidOperationException("Plaintext/unexpected DP key XML rejected");
            if (isKey && reader.LocalName == "encryptedSecret")
            {
                if (reader.NamespaceURI != protectionNamespace)
                    throw new InvalidOperationException("Foreign wrapped-secret namespace rejected");
                var decryptor = reader.GetAttribute("decryptorType")?
                    .Split(',', StringSplitOptions.TrimEntries);
                if (decryptor is null || decryptor.Length < 2 ||
                    decryptor[0] !=
                        "Microsoft.AspNetCore.DataProtection.XmlEncryption.EncryptedXmlDecryptor" ||
                    decryptor[1] != "Microsoft.AspNetCore.DataProtection")
                    throw new InvalidOperationException("Unknown wrapped key decryptor rejected");
                wrappedCount++;
            }
        }
        if (isKey && wrappedCount != 1)
            throw new InvalidOperationException("Exactly one approved encryptedSecret required");
    }

    private static void ValidatePrivate(string directory)
    {
        if (Path.GetFullPath(directory).TrimEnd('/') == "/")
            throw new InvalidOperationException("Filesystem root cannot be a DP snapshot directory");
        PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(
            directory, "Encrypted Data Protection snapshot");
    }

    private static void RequireLinux()
    {
        if (!OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Encrypted DP snapshot is Linux-only");
    }

    private static void RequireAbsolute(string? path, string purpose)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) ||
            Path.GetFullPath(path) != path)
            throw new InvalidOperationException(purpose + " requires a canonical absolute path");
    }

    private static void RequireDisjoint(string first, string second)
    {
        var a = Path.GetFullPath(first);
        var b = Path.GetFullPath(second);
        static bool Within(string candidate, string root)
        {
            var relative = Path.GetRelativePath(root, candidate);
            return relative == "." ||
                (!Path.IsPathRooted(relative) && relative != ".." &&
                !relative.StartsWith("../", StringComparison.Ordinal));
        }
        if (Within(a, b) || Within(b, a))
            throw new InvalidOperationException("Encrypted snapshot cannot overlap live/restored state");
    }

    private static void FlushDirectory(string path)
    {
        var fd = OpenDirectoryUnix(path, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW, 0);
        if (fd < 0)
            throw new InvalidOperationException("Cannot durably sync encrypted DP snapshot directory");
        using var handle = new SafeFileHandle((IntPtr)fd, ownsHandle: true);
        if (FsyncUnix(fd) != 0)
            throw new InvalidOperationException("Encrypted DP snapshot directory fsync failed");
    }
}
