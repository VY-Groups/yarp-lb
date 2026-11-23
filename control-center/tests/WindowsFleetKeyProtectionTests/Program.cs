using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

if (!OperatingSystem.IsWindows() ||
    Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
    Environment.GetEnvironmentVariable("RUNNER_OS") != "Windows")
    throw new InvalidOperationException("REFUSED: certificate fleet test requires disposable Windows GitHub runner");

const string Current = WindowsFleetKeyProtection.CurrentThumbprintSetting;
const string Previous = WindowsFleetKeyProtection.PreviousThumbprintSetting;
var prevCurrent = Environment.GetEnvironmentVariable(Current);
var prevOld = Environment.GetEnvironmentVariable(Previous);
var root = Path.Combine(Path.GetTempPath(), "gatewaycore-windows-fleet-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root);
var certs = new List<X509Certificate2>();

void Check(bool ok, string label)
{
    if (!ok) throw new InvalidOperationException("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
}

X509Certificate2 Install(bool encryptionLeaf)
{
    using var key = RSA.Create(3072);
    var req = new CertificateRequest(
        new X500DistinguishedName("CN=GatewayCore disposable DP fleet fixture"),
        key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    req.CertificateExtensions.Add(new X509KeyUsageExtension(
        encryptionLeaf ? X509KeyUsageFlags.KeyEncipherment
                       : X509KeyUsageFlags.DigitalSignature, critical: true));
    using var generated = req.CreateSelfSigned(
        DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(31));
    var raw = generated.Export(X509ContentType.Pkcs12, "ci-test-only-windows-wrap");
    X509Certificate2 cert;
    try
    {
        cert = X509CertificateLoader.LoadPkcs12(raw,
            "ci-test-only-windows-wrap",
            X509KeyStorageFlags.MachineKeySet |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.Exportable);
    }
    finally { CryptographicOperations.ZeroMemory(raw); }
    using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
    store.Open(OpenFlags.ReadWrite);
    store.Add(cert);
    certs.Add(cert);
    return cert;
}

ServiceProvider Build(string name)
{
    var dir = Path.Combine(root, name);
    Directory.CreateDirectory(dir);
    var services = new ServiceCollection();
    var builder = services.AddDataProtection()
        .SetApplicationName("GatewayCoreYarpControlCenter")
        .PersistKeysToFileSystem(new DirectoryInfo(dir));
    Check(WindowsFleetKeyProtection.TryConfigure(builder),
        "opt-in fleet mode selected without DPAPI fallback");
    return services.BuildServiceProvider();
}

void CopyKeys(string from, string to)
{
    var origin = Path.Combine(root, from);
    var destination = Path.Combine(root, to);
    Directory.CreateDirectory(destination);
    foreach (var key in Directory.GetFiles(origin, "*.xml"))
        File.Copy(key, Path.Combine(destination, Path.GetFileName(key)), overwrite: false);
    Check(Directory.GetFiles(destination, "*.xml").Length != 0,
        "only encrypted key XML is transferred between disposable independent roots");
}

bool CanRead(ServiceProvider provider, string token)
{
    try
    {
        var result = provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("gatewaycore-windows-fleet-cookie-v1").Unprotect(token);
        return result == "portable-cookie";
    }
    catch (Exception ex) when (ex is CryptographicException or InvalidOperationException
                                 or System.Xml.XmlException)
    {
        return false;
    }
}

try
{
    Environment.SetEnvironmentVariable(Current, null);
    Environment.SetEnvironmentVariable(Previous, null);
    using (var unused = new ServiceCollection().AddDataProtection())
    {
        // This fixture is intentionally not used to activate a real DPAPI
        // provider: the existing Windows SCM CI separately tests that path.
    }
}
finally
{
    Environment.SetEnvironmentVariable(Current, null);
    Environment.SetEnvironmentVariable(Previous, null);
}

try
{
    var active = Install(true);
    var rotated = Install(true);
    var wrong = Install(true);
    var signOnly = Install(false);
    var t1 = active.Thumbprint ?? throw new InvalidOperationException("missing test cert thumbprint");
    var t2 = rotated.Thumbprint ?? throw new InvalidOperationException("missing rotated thumbprint");
    var t3 = wrong.Thumbprint ?? throw new InvalidOperationException("missing bad thumbprint");
    Environment.SetEnvironmentVariable(Current, null);
    Environment.SetEnvironmentVariable(Previous, null);
    var baselineServices = new ServiceCollection();
    var baseline = baselineServices.AddDataProtection();
    Check(!WindowsFleetKeyProtection.TryConfigure(baseline),
        "unconfigured Windows fleet option preserves DPAPI default");
    Environment.SetEnvironmentVariable(Previous, t1);
    bool missingCurrentRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline); }
    catch (InvalidOperationException) { missingCurrentRejected = true; }
    Check(missingCurrentRejected, "previous-only certificate setting fails closed");
    Environment.SetEnvironmentVariable(Current, "NOT_A_THUMBPRINT");
    Environment.SetEnvironmentVariable(Previous, null);
    bool malformedRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline); }
    catch (InvalidOperationException) { malformedRejected = true; }
    Check(malformedRejected, "malformed thumbprint fails without fallback");
    Environment.SetEnvironmentVariable(Current, t1);
    Environment.SetEnvironmentVariable(Previous, t1);
    bool aliasRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline); }
    catch (InvalidOperationException) { aliasRejected = true; }
    Check(aliasRejected, "same-current/previous wrapping identity rejected");
    Environment.SetEnvironmentVariable(Previous, null);
    Environment.SetEnvironmentVariable(Current, signOnly.Thumbprint);
    bool signingOnlyRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline); }
    catch (InvalidOperationException) { signingOnlyRejected = true; }
    Check(signingOnlyRejected, "signing-only private key cannot wrap fleet DP data");

    Environment.SetEnvironmentVariable(Current, t1);
    using var first = Build("gateway-one");
    var protect = first.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("gatewaycore-windows-fleet-cookie-v1");
    var token = protect.Protect("portable-cookie");
    var xml = Directory.GetFiles(Path.Combine(root, "gateway-one"), "*.xml");
    Check(xml.Length > 0 && xml.All(path =>
        File.ReadAllText(path).Contains("<encryptedSecret", StringComparison.Ordinal) &&
        !File.ReadAllText(path).Contains("<masterKey", StringComparison.Ordinal)),
        "Windows fleet persisted Data Protection keys are certificate-wrapped at rest");
    CopyKeys("gateway-one", "gateway-two");
    using var second = Build("gateway-two");
    Check(CanRead(second, token), "second isolated Windows gateway reads approved portable cookie");

    Environment.SetEnvironmentVariable(Current, t3);
    using var untrusted = Build("gateway-untrusted");
    CopyKeys("gateway-one", "gateway-untrusted");
    Check(!CanRead(untrusted, token), "wrong certificate cannot decrypt copied fleet key ring");

    Environment.SetEnvironmentVariable(Current, t2);
    Environment.SetEnvironmentVariable(Previous, t1);
    using var overlapping = Build("gateway-two");
    Check(CanRead(overlapping, token),
        "rotated certificate retains original cookie using explicitly pinned previous identity");
    var manager = overlapping.GetRequiredService<IKeyManager>();
    manager.CreateNewKey(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(30));
    var latest = overlapping.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("gatewaycore-windows-fleet-cookie-v1")
        .Protect("portable-cookie");
    Check(CanRead(overlapping, latest),
        "new certificate can protect and recover a session after forced key rotation");
    Check(Directory.GetFiles(Path.Combine(root, "gateway-two"), "*.xml").Length > 1,
        "rotation persisted multiple encrypted key XML revisions");
    Console.WriteLine("WINDOWS FLEET CERTIFICATE DATA PROTECTION SOFTWARE ACCEPTANCE PASSED");
}
finally
{
    Environment.SetEnvironmentVariable(Current, prevCurrent);
    Environment.SetEnvironmentVariable(Previous, prevOld);
    foreach (var cert in certs)
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Remove(cert);
        }
        catch { /* disposable GitHub runner destroys certificate store */ }
        cert.Dispose();
    }
    if (Directory.Exists(root)) Directory.Delete(root, true);
}
