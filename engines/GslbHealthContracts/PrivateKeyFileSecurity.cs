using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace GatewayCore.Gslb.Contracts;

/// <summary>
/// Opens private-key files without following links, checks the opened object,
/// and returns only the bytes read from that same handle.
/// </summary>
public static class PrivateKeyFileSecurity
{
    private const int LinuxReadOnly = 0;
    private const int LinuxNonBlock = 0x800;
    private const int LinuxCloseOnExec = 0x80000;
    private const int LinuxNoFollow = 0x20000;
    private const int LinuxDirectory = 0x10000;
    private const int LinuxAtEmptyPath = 0x1000;
    private const int LinuxFileExists = 17;
    private const uint LinuxDirectoryPrivateMode = 0x1C0; // 0700
    private const uint LinuxStatxMode = 0x0002;
    private const uint LinuxStatxUid = 0x0008;
    private const uint GenericRead = 0x80000000;
    private const uint ShareRead = 0x00000001;
    private const uint OpenExisting = 3;
    private const uint OpenReparsePoint = 0x00200000;
    private const uint SequentialScan = 0x08000000;
    private const int MaximumPemBytes = 1024 * 1024;

    private const UnixFileMode ForbiddenUnixPermissions =
        UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute |
        UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;

    /// <summary>
    /// Reads a PEM key from the same no-follow handle whose file type and Unix
    /// permissions are validated. Windows ACL authorization remains deployment-managed.
    /// </summary>
    public static string ReadPrivateKeyPem(string? path, string purpose)
    {
        var bytes = ReadPrivateFileBytes(path, purpose, MaximumPemBytes);
        try { return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>
    /// A signing public key is a trusted policy input even though it is not secret.
    /// Use a bounded, no-follow opened handle and private state permissions.
    /// </summary>
    public static string ReadTrustedPublicKeyPem(string? path, string purpose)
    {
        const int MaximumTrustAnchorBytes = 16 * 1024;
        var bytes = ReadPrivateFileBytes(path, purpose, MaximumTrustAnchorBytes);
        try
        {
            var pem = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false,
                throwOnInvalidBytes: true).GetString(bytes);
            if (!pem.Contains("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal) ||
                !pem.Contains("-----END PUBLIC KEY-----", StringComparison.Ordinal))
                throw new InvalidDataException("Trusted signing key must be a SubjectPublicKeyInfo PEM");
            return pem;
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    /// <summary>
    /// Read using the same inspected, non-symlinked opened handle.
    /// On Linux validate each parent directory and the final regular file;
    /// Windows callers must separately enforce their required ACL policy.
    /// </summary>
    public static FileStream OpenPrivateFileRead(string? path, string purpose)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException($"{purpose} path must be absolute");
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Private-file loading supports Windows and Linux only");

        SafeFileHandle? handle = null;
        try
        {
            handle = OperatingSystem.IsLinux()
                ? OpenLinuxNoFollow(path, purpose)
                : OpenWindowsNoFollow(path, purpose);
            var attributes = File.GetAttributes(handle);
            if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
                throw new InvalidDataException($"{purpose} must be a regular file, not a directory, device, or link");
            if (OperatingSystem.IsLinux())
                ValidateLinuxOpenedObject(handle, purpose, isDirectory: false);
            var stream = new FileStream(handle, FileAccess.Read);
            handle = null;
            return stream;
        }
        finally { handle?.Dispose(); }
    }

    /// <summary>Read bounded bytes from one validated, no-follow handle.</summary>
    public static byte[] ReadPrivateFileBytes(string? path, string purpose, int maximumBytes)
    {
        if (maximumBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        using var stream = OpenPrivateFileRead(path, purpose);
        var length = stream.Length;
        if (!stream.CanSeek || length <= 0 || length > maximumBytes)
            throw new InvalidDataException($"{purpose} must be a regular file no larger than {maximumBytes} bytes");
        var bytes = new byte[checked((int)length)];
        try
        {
            stream.ReadExactly(bytes);
            if (stream.ReadByte() != -1)
                throw new InvalidDataException($"{purpose} changed while reading");
            return bytes;
        }
        catch
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes);
            throw;
        }
    }

    /// <summary>Bounded streaming SHA-256 over the inspected handle, without a heap-sized replay buffer.</summary>
    public static byte[] HashPrivateFileSha256(string? path, string purpose, int maximumBytes)
    {
        if (maximumBytes is < 1 or > 16 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        using var stream = OpenPrivateFileRead(path, purpose);
        var length = stream.Length;
        if (!stream.CanSeek || length <= 0 || length > maximumBytes)
            throw new InvalidDataException($"{purpose} has an invalid bounded length");
        using var hasher = System.Security.Cryptography.IncrementalHash.CreateHash(
            System.Security.Cryptography.HashAlgorithmName.SHA256);
        Span<byte> scratch = stackalloc byte[4096];
        try
        {
            long remaining = length;
            while (remaining > 0)
            {
                var read = stream.Read(scratch[..(int)Math.Min(remaining, scratch.Length)]);
                if (read <= 0) throw new EndOfStreamException($"{purpose} shortened while hashing");
                hasher.AppendData(scratch[..read]);
                remaining -= read;
            }
            if (stream.ReadByte() != -1)
                throw new InvalidDataException($"{purpose} grew while hashing");
            return hasher.GetHashAndReset();
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(scratch); }
    }

    /// <summary>
    /// Validates the full Linux parent chain for durable private state. The
    /// final directory must remain service-private; trusted sticky ancestors
    /// such as root-owned /tmp are permitted.
    /// </summary>
    public static void ValidateLinuxPrivateStateDirectory(string? path, string purpose)
    {
        if (!OperatingSystem.IsLinux()) return;
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException($"{purpose} directory path must be absolute");

        var components = Path.GetFullPath(path).Split(Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
            throw new InvalidDataException($"{purpose} directory must not be the filesystem root");

        SafeFileHandle? directory = OpenLinux("/", LinuxReadOnly | LinuxDirectory | LinuxCloseOnExec,
            purpose, "parent directory");
        try
        {
            ValidateLinuxOpenedObject(directory, purpose, isDirectory: true);
            for (var i = 0; i < components.Length; i++)
            {
                var next = OpenLinuxAt(directory, components[i],
                    LinuxReadOnly | LinuxDirectory | LinuxNoFollow | LinuxCloseOnExec,
                    purpose, "parent directory");
                LinuxStatx metadata;
                try { metadata = ValidateLinuxOpenedObject(next, purpose, isDirectory: true); }
                catch { next.Dispose(); throw; }

                if (i == components.Length - 1 &&
                    (((UnixFileMode)metadata.Mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                      UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                      UnixFileMode.OtherExecute)) != 0))
                {
                    next.Dispose();
                    throw new InvalidDataException($"{purpose} directory must be private to the service identity");
                }

                directory.Dispose();
                directory = next;
            }
        }
        finally { directory?.Dispose(); }
    }

    /// <summary>
    /// Creates a private Linux state directory by walking each path component
    /// relative to an already validated directory handle. Existing symlinks
    /// are rejected before any child directory can be created through them.
    /// </summary>
    public static void EnsureLinuxPrivateStateDirectory(string? path, string purpose)
    {
        if (!OperatingSystem.IsLinux()) return;
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException($"{purpose} directory path must be absolute");

        var components = Path.GetFullPath(path).Split(Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
            throw new InvalidDataException($"{purpose} directory must not be the filesystem root");

        SafeFileHandle? directory = OpenLinux("/", LinuxReadOnly | LinuxDirectory | LinuxCloseOnExec,
            purpose, "parent directory");
        try
        {
            ValidateLinuxOpenedObject(directory, purpose, isDirectory: true);
            for (var i = 0; i < components.Length; i++)
            {
                var created = false;
                if (MkdirAtUnix(directory.DangerousGetHandle().ToInt32(), components[i],
                        LinuxDirectoryPrivateMode) == 0)
                {
                    created = true;
                }
                else if (Marshal.GetLastPInvokeError() != LinuxFileExists)
                {
                    throw new InvalidDataException($"Unable to create {purpose} directory without following links",
                        new Win32Exception(Marshal.GetLastPInvokeError()));
                }

                var next = OpenLinuxAt(directory, components[i],
                    LinuxReadOnly | LinuxDirectory | LinuxNoFollow | LinuxCloseOnExec,
                    purpose, "parent directory");
                try
                {
                    var metadata = ValidateLinuxOpenedObject(next, purpose, isDirectory: true);
                    if (created)
                    {
                        if (FchmodUnix(next.DangerousGetHandle().ToInt32(), LinuxDirectoryPrivateMode) != 0)
                            throw new InvalidDataException($"Unable to set private permissions on {purpose} directory",
                                new Win32Exception(Marshal.GetLastPInvokeError()));
                        metadata = ValidateLinuxOpenedObject(next, purpose, isDirectory: true);
                    }

                    if (i == components.Length - 1 &&
                        (((UnixFileMode)metadata.Mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
                          UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
                          UnixFileMode.OtherExecute)) != 0))
                        throw new InvalidDataException($"{purpose} directory must be private to the service identity");
                }
                catch { next.Dispose(); throw; }

                directory.Dispose();
                directory = next;
            }
        }
        finally { directory?.Dispose(); }
    }

    /// <summary>Validates an existing Linux state file using the opened object, without following links.</summary>
    public static void ValidateLinuxPrivateStateFile(string? path, string purpose)
    {
        if (!OperatingSystem.IsLinux() || !File.Exists(path)) return;
        using var handle = OpenLinuxNoFollow(path!, purpose);
        var attributes = File.GetAttributes(handle);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            throw new InvalidDataException($"{purpose} must be a regular file, not a directory, device, or link");
        ValidateLinuxOpenedObject(handle, purpose, isDirectory: false);
    }

    private static SafeFileHandle OpenLinuxNoFollow(string path, string purpose)
    {
        var absolute = Path.GetFullPath(path);
        var components = absolute.Split(Path.DirectorySeparatorChar,
            StringSplitOptions.RemoveEmptyEntries);
        if (components.Length == 0)
            throw new InvalidDataException($"{purpose} must name a file");

        SafeFileHandle? directory = OpenLinux("/", LinuxReadOnly | LinuxDirectory | LinuxCloseOnExec,
            purpose, "parent directory");
        try
        {
            ValidateLinuxOpenedObject(directory, purpose, isDirectory: true);
            for (var i = 0; i < components.Length - 1; i++)
            {
                var next = OpenLinuxAt(directory, components[i],
                    LinuxReadOnly | LinuxDirectory | LinuxNoFollow | LinuxCloseOnExec,
                    purpose, "parent directory");
                try { ValidateLinuxOpenedObject(next, purpose, isDirectory: true); }
                catch { next.Dispose(); throw; }
                directory.Dispose();
                directory = next;
            }

            return OpenLinuxAt(directory, components[^1],
                LinuxReadOnly | LinuxNonBlock | LinuxNoFollow | LinuxCloseOnExec,
                purpose, "private key");
        }
        finally
        {
            directory?.Dispose();
        }
    }

    private static LinuxStatx ValidateLinuxOpenedObject(SafeFileHandle handle, string purpose, bool isDirectory)
    {
        var requiredMask = LinuxStatxMode | LinuxStatxUid;
        if (StatxUnix(handle.DangerousGetHandle().ToInt32(), "", LinuxAtEmptyPath,
                requiredMask, out var metadata) != 0 || (metadata.Mask & requiredMask) != requiredMask)
            throw new InvalidDataException($"Unable to verify {purpose} ownership and permissions",
                new Win32Exception(Marshal.GetLastPInvokeError()));

        // statx describes the actual opened object; reject FIFOs/sockets
        // before constructing a stream (O_NONBLOCK avoids FIFO open hangs).
        if ((metadata.Mode & 0xF000) != (isDirectory ? 0x4000 : 0x8000))
            throw new InvalidDataException($"{purpose} must be a regular file or expected directory");
        ValidateLinuxPathObject(metadata.OwnerUid, metadata.Mode, GetEffectiveUid(), isDirectory, purpose);
        return metadata;
    }

    internal static void ValidateLinuxPathObject(uint ownerUid, uint mode, uint effectiveUid,
        bool isDirectory, string purpose)
    {
        if (ownerUid != 0 && ownerUid != effectiveUid)
            throw new InvalidDataException($"{purpose} owner must be root or the service identity");

        var unixMode = (UnixFileMode)mode;
        if (!isDirectory)
        {
            if ((unixMode & UnixFileMode.UserRead) == 0 ||
                (unixMode & ForbiddenUnixPermissions) != 0)
                throw new InvalidDataException($"{purpose} permissions must grant owner read and no group/other access (chmod 600 recommended)");
            return;
        }

        var groupOrOtherWrite = UnixFileMode.GroupWrite | UnixFileMode.OtherWrite;
        var sticky = (unixMode & UnixFileMode.StickyBit) != 0;
        if ((unixMode & groupOrOtherWrite) != 0 && !sticky)
            throw new InvalidDataException($"{purpose} permissions must not allow group/other writes");
    }

    private static SafeFileHandle OpenLinux(string path, int flags, string purpose, string objectName)
    {
        var descriptor = OpenUnix(path, flags);
        return WrapUnixDescriptor(descriptor, purpose, objectName);
    }

    private static SafeFileHandle OpenLinuxAt(SafeFileHandle directory, string path, int flags,
        string purpose, string objectName)
    {
        var descriptor = OpenAtUnix(directory.DangerousGetHandle().ToInt32(), path, flags);
        return WrapUnixDescriptor(descriptor, purpose, objectName);
    }

    private static SafeFileHandle WrapUnixDescriptor(int descriptor, string purpose, string objectName)
    {
        if (descriptor < 0)
            throw new InvalidDataException($"Unable to open {purpose} {objectName} without following links",
                new Win32Exception(Marshal.GetLastPInvokeError()));
        return new SafeFileHandle((IntPtr)descriptor, ownsHandle: true);
    }

    private static SafeFileHandle OpenWindowsNoFollow(string path, string purpose)
    {
        var handle = CreateFileW(path, GenericRead, ShareRead, IntPtr.Zero, OpenExisting,
            OpenReparsePoint | SequentialScan, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new InvalidDataException($"Unable to open {purpose} without following links",
                new Win32Exception(error));
        }
        return handle;
    }

    [DllImport("libc", EntryPoint = "open", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int OpenUnix(string path, int flags);

    [DllImport("libc", EntryPoint = "openat", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int OpenAtUnix(int directoryDescriptor, string path, int flags);

    [DllImport("libc", EntryPoint = "mkdirat", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int MkdirAtUnix(int directoryDescriptor, string path, uint mode);

    [DllImport("libc", EntryPoint = "fchmod", SetLastError = true)]
    private static extern int FchmodUnix(int descriptor, uint mode);

    [DllImport("libc", EntryPoint = "statx", SetLastError = true, CharSet = CharSet.Ansi)]
    private static extern int StatxUnix(int directoryDescriptor, string path, int flags,
        uint mask, out LinuxStatx metadata);

    [DllImport("libc", EntryPoint = "geteuid", SetLastError = true)]
    private static extern uint GetEffectiveUid();

    [StructLayout(LayoutKind.Explicit, Size = 256)]
    private struct LinuxStatx
    {
        [FieldOffset(0)] public uint Mask;
        [FieldOffset(20)] public uint OwnerUid;
        [FieldOffset(28)] public ushort Mode;
    }

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
}
