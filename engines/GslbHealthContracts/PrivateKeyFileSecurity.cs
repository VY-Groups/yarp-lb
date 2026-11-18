namespace GatewayCore.Gslb.Contracts;

/// <summary>Reject private-key files that are missing, linked, or broadly readable on Unix.</summary>
public static class PrivateKeyFileSecurity
{
    public static void Validate(string? path, string purpose)
    {
        if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path))
            throw new InvalidDataException($"{purpose} path must be absolute");

        var file = new FileInfo(path);
        if (!file.Exists || (file.Attributes & FileAttributes.ReparsePoint) != 0)
            throw new InvalidDataException($"{purpose} must be an existing regular file, not a link");

        if (OperatingSystem.IsWindows())
        {
            // Windows ACL evaluation is deployment-specific; callers still reject reparse points.
            // A future Windows ACL policy must validate the service SID before reading key bytes.
            return;
        }

        var mode = File.GetUnixFileMode(path);
        var allowed = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        if ((mode & UnixFileMode.UserRead) == 0 || (mode & ~allowed) != 0)
            throw new InvalidDataException($"{purpose} permissions must be owner-only (chmod 600)");
    }
}
