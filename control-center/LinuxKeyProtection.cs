using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;
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
        if (!Directory.Exists(root))
            Directory.CreateDirectory(root, PrivateDirectoryMode);
        CheckPrivateDirectory(root);
        var keyDir = Path.Combine(root, "data-protection-keys");
        if (!Directory.Exists(keyDir))
            Directory.CreateDirectory(keyDir, PrivateDirectoryMode);
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

    private static X509Certificate2 LoadRsaProtector(string pfxEnv, string passwordFileEnv)
    {
        var path = SecretPath(pfxEnv);
        var passwordPath = SecretPath(passwordFileEnv);
        byte[] ReadSecret(string file, string purpose, int limit)
        {
            try { return PrivateKeyFileSecurity.ReadPrivateFileBytes(file, purpose, limit); }
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
            if (privateKey is null || privateKey.KeySize < 2048 ||
                cert.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
                cert.NotAfter.ToUniversalTime() <= DateTime.UtcNow.AddDays(1))
                throw new InvalidOperationException(
                    "Linux Data Protection requires a currently valid RSA >=2048 certificate with a private key");
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
        XNamespace protection = "http://schemas.asp.net/2015/03/dataProtection";
        foreach (var path in Directory.EnumerateFiles(directory, "*.xml"))
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML must not be a symlink");
            if ((File.GetUnixFileMode(path) & PublicPermissions) != 0)
                throw new InvalidOperationException("Existing Linux key-ring XML requires owner-only permissions");
            byte[] bytes;
            try { bytes = PrivateKeyFileSecurity.ReadPrivateFileBytes(path, "Linux key-ring XML", 1024 * 1024); }
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
                var root = XDocument.Load(reader).Root;
                // Revocation files never contain master key material. A forged
                // revocation wrapper must not bypass our plaintext-ring guard.
                if (root?.Name == "revocation")
                {
                    if (root.Descendants().Any(element =>
                        element.Name.LocalName is "masterKey" or "encryptedSecret"))
                        throw new InvalidOperationException(
                            "Linux key-ring revocation XML contains unexpected key material");
                    continue;
                }
                if (root?.Name != "key" ||
                    root.Descendants().Any(element => element.Name.LocalName == "masterKey") ||
                    root.Descendants(protection + "encryptedSecret").Count() != 1)
                    throw new InvalidOperationException(
                        "Existing Linux key ring is not certificate-wrapped; isolate and recover an approved protected backup");
            }
            finally
            {
                // Legacy plaintext key XML is deliberately read for rejection;
                // do not leave those secret bytes in a managed heap after failure.
                CryptographicOperations.ZeroMemory(bytes);
            }
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
        var current = LoadRsaProtector("YARP_LINUX_DP_CERT_PFX_PATH",
            "YARP_LINUX_DP_CERT_PASSWORD_FILE");
        dataProtection.ProtectKeysWithCertificate(current);
        // Optional overlap only during planned protection certificate rotation.
        // Previously persisted XML keys still require the old private key.
        var old = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PFX_PATH");
        var oldPassword = Environment.GetEnvironmentVariable("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE");
        if (string.IsNullOrEmpty(old) != string.IsNullOrEmpty(oldPassword))
            throw new InvalidOperationException("Old PFX and its password file must be specified together");
        if (!string.IsNullOrEmpty(old))
        {
            var previous = LoadRsaProtector("YARP_LINUX_DP_OLD_CERT_PFX_PATH",
                "YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE");
            dataProtection.UnprotectKeysWithAnyCertificate(current, previous);
        }
    }
}
