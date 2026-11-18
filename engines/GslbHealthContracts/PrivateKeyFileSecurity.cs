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
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException($"{purpose} path must be absolute");
        if (!OperatingSystem.IsWindows() && !OperatingSystem.IsLinux())
            throw new PlatformNotSupportedException("Private-key loading is supported only on Windows and Linux");

        using var handle = OperatingSystem.IsLinux()
            ? OpenLinuxNoFollow(path, purpose)
            : OpenWindowsNoFollow(path, purpose);

        var attributes = File.GetAttributes(handle);
        if ((attributes & (FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) != 0)
            throw new InvalidDataException($"{purpose} must be a regular file, not a directory, device, or link");

        if (OperatingSystem.IsLinux())
        {
            var mode = File.GetUnixFileMode(handle);
            if ((mode & UnixFileMode.UserRead) == 0 || (mode & ForbiddenUnixPermissions) != 0)
                throw new InvalidDataException($"{purpose} permissions must grant owner read and no group/other access (chmod 600 recommended)");
        }

        using var stream = new FileStream(handle, FileAccess.Read);
        if (!stream.CanSeek || stream.Length is <= 0 or > MaximumPemBytes)
            throw new InvalidDataException($"{purpose} must be a regular PEM file no larger than {MaximumPemBytes} bytes");

        var bytes = new byte[checked((int)stream.Length)];
        stream.ReadExactly(bytes);
        return new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(bytes);
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
            for (var i = 0; i < components.Length - 1; i++)
            {
                var next = OpenLinuxAt(directory, components[i],
                    LinuxReadOnly | LinuxDirectory | LinuxNoFollow | LinuxCloseOnExec,
                    purpose, "parent directory");
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

    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string fileName, uint desiredAccess, uint shareMode,
        IntPtr securityAttributes, uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);
}
