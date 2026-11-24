using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;
using Microsoft.Win32.SafeHandles;

/// <summary>
/// External Linux Data Protection recovery revision high-water.
/// The file is outside the restored Control Plane snapshot. A verified offline
/// restore can commit a newer signed revision, never roll back an older one.
/// This is an OFFLINE coordinator primitive; it does not replace fleet quorum,
/// distributed fencing or an authorized service-stop/DR procedure.
/// </summary>
public static class LinuxDpRecoveryFloor
{
    private const int O_RDONLY = 0;
    private const int O_RDWR = 2;
    private const int O_CREAT = 0x40;
    private const int O_DIRECTORY = 0x10000;
    private const int O_NOFOLLOW = 0x20000;
    private const int O_CLOEXEC = 0x80000;
    private const int LOCK_EX_NB = 2 | 4;
    private const UnixFileMode PrivateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
    private const UnixFileMode UntrustedMode =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    [DllImport("libc", EntryPoint = "open", SetLastError = true)]
    private static extern int OpenUnix(string path, int flags, uint mode);

    [DllImport("libc", EntryPoint = "flock", SetLastError = true)]
    private static extern int FlockUnix(int descriptor, int operation);

    [DllImport("libc", EntryPoint = "fsync", SetLastError = true)]
    private static extern int FsyncUnix(int descriptor);

    public static long ReadExternalFloor(string ringDirectory, string floorPath)
    {
        ValidateFloorPath(ringDirectory, floorPath);
        byte[] contents = PrivateKeyFileSecurity.ReadPrivateFileBytes(
            floorPath, "Independent Data Protection revision floor", 24, requireSingleLink: true);
        try
        {
            // Canonical ASCII, one optional terminal LF, no BOM/CR/sign/leading zero.
            var text = Encoding.ASCII.GetString(contents);
            if (text.EndsWith('\n')) text = text[..^1];
            if (text.Length is < 1 or > 19 || text[0] is < '1' or > '9' ||
                text.Any(ch => ch is < '0' or > '9') ||
                !long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture,
                    out var revision) || revision < 1)
                throw new InvalidOperationException("Invalid independent recovery revision floor");
            return revision;
        }
        finally { CryptographicOperations.ZeroMemory(contents); }
    }

    /// <summary>
    /// Commit a higher verified checkpoint to a separately custodied local floor.
    /// The restored ring must be quiesced by the authorized offline coordinator.
    /// This method never writes a key, manifest, trust key or plaintext token.
    /// </summary>
    public static long CommitVerifiedOfflineRecovery(string ringDirectory,
        string manifestPath, string trustedPublicKeyPath, string floorPath)
    {
        ValidateFloorPath(ringDirectory, floorPath);
        var parent = Path.GetDirectoryName(floorPath)!;
        var lockPath = Path.Combine(parent, "." + Path.GetFileName(floorPath) + ".lock");
        // O_NOFOLLOW blocks leaf aliases, and the parent is a no-follow,
        // validated owner-only directory. The lock is intentionally retained
        // across runs, so a second coordinator cannot bypass a held inode.
        var descriptor = OpenUnix(lockPath, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 384);
        if (descriptor < 0)
            throw new InvalidOperationException("Cannot open independent revision-floor lock");
        using var lockHandle = new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
        if ((File.GetAttributes(lockHandle) & (FileAttributes.Directory |
                FileAttributes.ReparsePoint | FileAttributes.Device)) != 0 ||
            (File.GetUnixFileMode(lockPath) & UntrustedMode) != 0 ||
            FlockUnix(descriptor, LOCK_EX_NB) != 0)
            throw new InvalidOperationException("Unsafe or busy independent revision-floor lock");

        var current = ReadExternalFloor(ringDirectory, floorPath);
        if (current == long.MaxValue)
            throw new InvalidOperationException("Independent recovery revision exhausted");
        var before = PrivateKeyFileSecurity.ReadPrivateFileBytes(
            manifestPath, "Recovery checkpoint before commit", 16_384, requireSingleLink: true);
        try
        {
            using var doc = JsonDocument.Parse(before, new JsonDocumentOptions { MaxDepth = 3 });
            var proposed = doc.RootElement.GetProperty("Revision").GetInt64();
            if (proposed <= current)
                throw new InvalidOperationException("Recovery checkpoint does not advance the trusted floor");

            // Existing verification performs strict JSON identity, P-256 signature,
            // outside-state trust placement and exact encrypted ring inventory checks.
            LinuxDpRecoveryEvidence.Verify(ringDirectory, manifestPath,
                trustedPublicKeyPath, current + 1);
            var inventoryBefore = LinuxDpRecoveryEvidence.ComputeInventoryDigest(ringDirectory);
            var after = PrivateKeyFileSecurity.ReadPrivateFileBytes(
                manifestPath, "Recovery checkpoint after verification", 16_384,
                requireSingleLink: true);
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(before, after) ||
                    !CryptographicOperations.FixedTimeEquals(
                        Encoding.ASCII.GetBytes(inventoryBefore),
                        Encoding.ASCII.GetBytes(
                            LinuxDpRecoveryEvidence.ComputeInventoryDigest(ringDirectory))) ||
                    ReadExternalFloor(ringDirectory, floorPath) != current)
                    throw new InvalidOperationException("Recovery inputs changed during revision commit");
            }
            finally { CryptographicOperations.ZeroMemory(after); }

            var temp = Path.Combine(parent, "." + Path.GetFileName(floorPath) +
                "." + Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temp, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew, Access = FileAccess.Write,
                    Share = FileShare.None, Options = FileOptions.WriteThrough,
                    UnixCreateMode = PrivateMode
                }))
                {
                    var line = Encoding.ASCII.GetBytes(
                        proposed.ToString(CultureInfo.InvariantCulture) + "\n");
                    stream.Write(line);
                    stream.Flush(flushToDisk: true);
                }
                // Atomic same-directory replacement; the previous floor is
                // unchanged on pre-rename failure, never silently decremented.
                File.Move(temp, floorPath, overwrite: true);
                var directoryDescriptor = OpenUnix(parent,
                    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0);
                if (directoryDescriptor < 0)
                    throw new InvalidOperationException("Cannot durably commit recovery floor");
                using var directoryHandle = new SafeFileHandle(
                    (IntPtr)directoryDescriptor, ownsHandle: true);
                if (FsyncUnix(directoryDescriptor) != 0)
                    throw new InvalidOperationException("Recovery-floor directory sync failed");
            }
            finally
            {
                if (File.Exists(temp)) File.Delete(temp);
            }
            if (ReadExternalFloor(ringDirectory, floorPath) != proposed)
                throw new InvalidOperationException("Recovery floor failed durable readback");
            return proposed;
        }
        finally { CryptographicOperations.ZeroMemory(before); }
    }

    private static void ValidateFloorPath(string ringDirectory, string floorPath)
    {
        if (!OperatingSystem.IsLinux() || string.IsNullOrWhiteSpace(ringDirectory) ||
            string.IsNullOrWhiteSpace(floorPath) ||
            !Path.IsPathFullyQualified(ringDirectory) ||
            !Path.IsPathFullyQualified(floorPath) ||
            Path.GetFileName(ringDirectory.TrimEnd('/')) != "data-protection-keys" ||
            Path.GetFileName(floorPath) is "" or "." or "..")
            throw new InvalidOperationException("Linux external recovery floor requires absolute independent paths");
        var stateRoot = Path.GetDirectoryName(Path.GetFullPath(ringDirectory))!;
        var relative = Path.GetRelativePath(stateRoot, Path.GetFullPath(floorPath));
        if (relative == "." || (!Path.IsPathRooted(relative) &&
            relative != ".." && !relative.StartsWith("../", StringComparison.Ordinal)))
            throw new InvalidOperationException("Restored state cannot supply its own revision floor");

        // This descriptor-relative check refuses symlink ancestors and
        // group/other-accessible final trust directory on Linux.
        PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(
            Path.GetDirectoryName(floorPath), "Independent recovery floor parent");
    }
}
