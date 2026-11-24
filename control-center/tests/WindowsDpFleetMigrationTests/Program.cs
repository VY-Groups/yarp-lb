using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

if (!OperatingSystem.IsWindows() ||
    Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
    Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
    throw new InvalidOperationException("REFUSED: offline DPAPI migration acceptance requires a disposable Windows runner");

void Check(bool okay, string name)
{
    if (!okay) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
}

var root = Path.Combine(Path.GetTempPath(),
    "gatewaycore-dpapi-migration-" + Guid.NewGuid().ToString("N"));
var state = Path.Combine(root, "ControlPlane");
var source = Path.Combine(state, "data-protection-keys");
var destination = Path.Combine(state, "portable-fleet-ring");
var tool = Environment.GetEnvironmentVariable("DP_MIGRATION_ASSEMBLY");
Check(!string.IsNullOrWhiteSpace(tool) && File.Exists(tool),
    "offline .NET 10 migration tool was independently built and published");

WindowsStateProtection.InitializeStateDirectory(root, state);
var previousThumbprint = Environment.GetEnvironmentVariable(
    WindowsFleetKeyProtection.CurrentThumbprintSetting);
var previousOld = Environment.GetEnvironmentVariable(
    WindowsFleetKeyProtection.PreviousThumbprintSetting);
X509Certificate2? installed = null;

int Invoke(string[] arguments)
{
    var options = new ProcessStartInfo("dotnet") {
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };
    options.ArgumentList.Add(tool!);
    foreach (var value in arguments) options.ArgumentList.Add(value);
    using var process = Process.Start(options)
        ?? throw new InvalidOperationException("Cannot start published migration tool");
    if (!process.WaitForExit(90_000))
    {
        process.Kill(entireProcessTree: true);
        throw new InvalidOperationException("Migration process timed out");
    }
    // Test contract: never echo child logs, cookies, key files, private keys
    // or live state. A failing code must be reproducible without source dump.
    return process.ExitCode;
}

try
{
    using var rsa = RSA.Create(3072);
    var request = new CertificateRequest(
        "CN=GatewayCore Disposable DPAPI Fleet Migration",
        rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(
        new X509BasicConstraintsExtension(false, false, 0, true));
    request.CertificateExtensions.Add(
        new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
    using var generated = request.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    var pfx = generated.Export(X509ContentType.Pkcs12, "ci-only-migration");
    try
    {
        installed = X509CertificateLoader.LoadPkcs12(pfx,
            "ci-only-migration",
            X509KeyStorageFlags.MachineKeySet |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.Exportable);
    }
    finally { CryptographicOperations.ZeroMemory(pfx); }
    using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
    {
        store.Open(OpenFlags.ReadWrite);
        store.Add(installed);
    }
    var thumbprint = installed.Thumbprint ??
        throw new InvalidOperationException("Fixture certificate lacks thumbprint");

    Environment.SetEnvironmentVariable(
        WindowsFleetKeyProtection.CurrentThumbprintSetting, null);
    Environment.SetEnvironmentVariable(
        WindowsFleetKeyProtection.PreviousThumbprintSetting, null);

    var services = new ServiceCollection();
    services.AddDataProtection()
        .SetApplicationName("GatewayCoreYarpControlCenter")
        .PersistKeysToFileSystem(new DirectoryInfo(source))
        .ProtectKeysWithDpapi(protectToLocalMachine: true);
    using var legacy = services.BuildServiceProvider();
    var purpose = "gatewaycore-windows-fleet-cookie-v1";
    var token = legacy.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector(purpose).Protect("portable-cookie");
    var xmls = Directory.GetFiles(source, "key-*.xml");
    Check(xmls.Length > 0 && File.ReadAllText(xmls[0]).Contains(
        "DpapiXmlDecryptor", StringComparison.Ordinal),
        "real Windows DPAPI LocalMachine key XML generated");

    var originalFiles = Directory.GetFiles(source, "*.xml")
        .ToDictionary(Path.GetFileName, File.ReadAllBytes);
    Check(Invoke(new[] {"migrate", "--approved-offline", source,
                        destination, thumbprint}) == 0,
        "real separate OS process rewrapped DPAPI XML to certificate");

    WindowsStateProtection.ValidateOfflineKeyRingDirectory(destination);
    var migrated = Directory.GetFiles(destination, "key-*.xml");
    Check(migrated.Length == xmls.Length &&
          migrated.All(file => File.ReadAllText(file).Contains(
              "EncryptedXmlDecryptor", StringComparison.Ordinal) &&
          !File.ReadAllText(file).Contains("DpapiXmlDecryptor",
                                          StringComparison.Ordinal) &&
          !File.ReadAllText(file).Contains("<masterKey",
                                          StringComparison.Ordinal)),
        "same key IDs now encrypted by portable X.509; no plaintext or DPAPI");
    Check(originalFiles.All(item => CryptographicOperations.FixedTimeEquals(
            item.Value, File.ReadAllBytes(Path.Combine(source, item.Key)))),
        "all original DPAPI source XML remains byte-identical");

    Environment.SetEnvironmentVariable(
        WindowsFleetKeyProtection.CurrentThumbprintSetting, thumbprint);
    var portable = new ServiceCollection();
    var builder = portable.AddDataProtection()
        .SetApplicationName("GatewayCoreYarpControlCenter")
        .PersistKeysToFileSystem(new DirectoryInfo(destination));
    Check(WindowsFleetKeyProtection.TryConfigure(builder, destination),
        "production opt-in fleet provider accepts migrated certificate XML");
    using (var live = portable.BuildServiceProvider())
    {
        var plain = live.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(purpose).Unprotect(token);
        Check(plain == "portable-cookie",
            "actual pre-migration Windows cookie decrypts after certificate migration");
    }

    Check(Invoke(new[] {"migrate", "--approved-offline", source,
                        destination, thumbprint}) != 0,
        "replay into existing fleet ring refused without overwrite");
    Check(originalFiles.All(item => CryptographicOperations.FixedTimeEquals(
            item.Value, File.ReadAllBytes(Path.Combine(source, item.Key)))),
        "failed replay cannot rewrite original DPAPI source");

    var unapproved = Path.Combine(state, "unapproved-target");
    Check(Invoke(new[] {"migrate", source, unapproved, thumbprint}) != 0 &&
          !Directory.Exists(unapproved),
        "missing explicit offline authorization creates no destination");

    var malformed = Path.Combine(state, "malformed-source");
    WindowsStateProtection.CreateNewOfflinePrivateDirectory(malformed);
    foreach (var file in xmls)
        File.WriteAllText(Path.Combine(malformed, Path.GetFileName(file)),
            File.ReadAllText(file).Replace("DpapiXmlDecryptor",
                "UnknownXmlDecryptor", StringComparison.Ordinal));
    var rejected = Path.Combine(state, "rejected-target");
    Check(Invoke(new[] {"migrate", "--approved-offline", malformed,
                        rejected, thumbprint}) != 0 &&
          !Directory.Exists(rejected),
        "unapproved DPAPI decryptor class refuses migration atomically");

    var invalidThumbprint = "F" + thumbprint[1..];
    if (invalidThumbprint == thumbprint)
        invalidThumbprint = "E" + thumbprint[1..];
    var missingCertTarget = Path.Combine(state, "missing-cert-target");
    Check(Invoke(new[] {"migrate", "--approved-offline", source,
                        missingCertTarget, invalidThumbprint}) != 0 &&
          !Directory.Exists(missingCertTarget),
        "missing approved X.509 certificate fails before destination creation");
}
finally
{
    Environment.SetEnvironmentVariable(
        WindowsFleetKeyProtection.CurrentThumbprintSetting, previousThumbprint);
    Environment.SetEnvironmentVariable(
        WindowsFleetKeyProtection.PreviousThumbprintSetting, previousOld);
    if (installed is not null)
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Remove(installed);
        }
        finally { installed.Dispose(); }
    }
    if (Directory.Exists(root)) Directory.Delete(root, recursive: true);
}
