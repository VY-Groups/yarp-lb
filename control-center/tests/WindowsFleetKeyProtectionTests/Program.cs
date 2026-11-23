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
    Check(WindowsFleetKeyProtection.TryConfigure(builder, dir),
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

Environment.SetEnvironmentVariable(Current, null);
Environment.SetEnvironmentVariable(Previous, null);

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
    try
    {
        var empty = Path.Combine(root, "validated-empty");
        Directory.CreateDirectory(empty);
        WindowsFleetKeyProtection.TryConfigure(baseline, empty);
    }
    catch (InvalidOperationException ex)
    {
        signingOnlyRejected = ex.Message.Contains("keyEncipherment", StringComparison.Ordinal);
    }
    Check(signingOnlyRejected, "signing-only private key cannot wrap fleet DP data");

    Environment.SetEnvironmentVariable(Current, t1);
    var legacy = Path.Combine(root, "legacy-machine-bound");
    Directory.CreateDirectory(legacy);
    File.WriteAllText(Path.Combine(legacy, "key-legacy.xml"),
        "<key><encryptedSecret decryptorType=\"Microsoft.AspNetCore.DataProtection.XmlEncryption.DpapiXmlDecryptor\" /></key>");
    bool legacyRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline, legacy); }
    catch (InvalidOperationException) { legacyRejected = true; }
    Check(legacyRejected, "Windows fleet refuses silent import of host-bound legacy DPAPI key XML");
    File.WriteAllText(Path.Combine(legacy, "key-legacy.xml"),
        "<key><masterKey>test-only-no-real-secret</masterKey></key>");
    bool plaintextRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline, legacy); }
    catch (InvalidOperationException) { plaintextRejected = true; }
    Check(plaintextRejected, "Windows fleet refuses unwrapped existing key material");

    // String searches used to accept a comment containing "encryptedSecret"
    // and missed a namespace-qualified plaintext masterKey. Inspect XML nodes.
    var disguised = Path.Combine(root, "disguised-existing-ring");
    Directory.CreateDirectory(disguised);
    var disguisedId = Guid.NewGuid().ToString("D");
    var disguisedFile = Path.Combine(disguised, "key-" + disguisedId + ".xml");
    foreach (var (xmlText, label) in new (string Xml, string Label)[]
    {
        ("<key id=\"" + disguisedId + "\"><!-- encryptedSecret --><descriptor/></key>",
         "comment cannot impersonate a wrapped key"),
        ("<key id=\"" + disguisedId + "\"><x:masterKey xmlns:x=\"urn:untrusted\">plaintext-test-only</x:masterKey>" +
         "<encryptedSecret xmlns=\"http://schemas.asp.net/2015/03/dataProtection\"" +
         " decryptorType=\"EncryptedXmlDecryptor\"/></key>",
         "namespace-qualified plaintext master key is refused")
    })
    {
        File.WriteAllText(disguisedFile, xmlText);
        var rejected = false;
        try { WindowsFleetKeyProtection.TryConfigure(baseline, disguised); }
        catch (InvalidOperationException) { rejected = true; }
        Check(rejected, label);
    }

    using var first = Build("gateway-one");
    var protect = first.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("gatewaycore-windows-fleet-cookie-v1");
    var token = protect.Protect("portable-cookie");
    var xml = Directory.GetFiles(Path.Combine(root, "gateway-one"), "*.xml");
    Check(xml.Length > 0 && xml.All(path =>
        File.ReadAllText(path).Contains("<encryptedSecret", StringComparison.Ordinal) &&
        !File.ReadAllText(path).Contains("<masterKey", StringComparison.Ordinal)),
        "Windows fleet persisted Data Protection keys are certificate-wrapped at rest");
    // A copied XML file with a second filename cannot impersonate another key.
    var duplicateAlias = Path.Combine(root, "gateway-one",
        "key-" + Guid.NewGuid().ToString("D") + ".xml");
    File.Copy(xml[0], duplicateAlias);
    var aliasIdentityRejected = false;
    try { WindowsFleetKeyProtection.TryConfigure(baseline, Path.Combine(root, "gateway-one")); }
    catch (InvalidOperationException) { aliasIdentityRejected = true; }
    Check(aliasIdentityRejected, "duplicated key XML under another GUID filename is refused");
    File.Delete(duplicateAlias);
    CopyKeys("gateway-one", "gateway-two");
    using var second = Build("gateway-two");
    Check(CanRead(second, token), "second isolated Windows gateway reads approved portable cookie");

    // A one-host test with BOTH private certificates in LocalMachine\My is
    // not a cross-host negative: ASP.NET can resolve the XML-encrypted key's
    // embedded recipient thumbprint against that shared machine store.
    // Remove the approved leaf from the recipient's available store before
    // probing the wrong-only identity, then restore it for rotation tests.
    using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
    {
        machineStore.Open(OpenFlags.ReadWrite);
        machineStore.Remove(active);
        try
        {
            Environment.SetEnvironmentVariable(Current, t3);
            using var untrusted = Build("gateway-untrusted");
            CopyKeys("gateway-one", "gateway-untrusted");
            Check(!CanRead(untrusted, token),
                "isolated recipient without approved wrapping certificate cannot decrypt ring");
        }
        finally
        {
            machineStore.Add(active);
        }
    }

    Environment.SetEnvironmentVariable(Current, t2);
    Environment.SetEnvironmentVariable(Previous, t1);
    using var overlapping = Build("gateway-two");
    Check(CanRead(overlapping, token),
        "rotated certificate retains original cookie using explicitly pinned previous identity");
    var ring = Path.Combine(root, "gateway-two");
    var beforeRotationFiles = Directory.GetFiles(ring, "*.xml")
        .Select(Path.GetFileName).ToHashSet(StringComparer.Ordinal);
    var manager = overlapping.GetRequiredService<IKeyManager>();
    // Use a strictly newer activation than the existing active default.
    // Backdating by a minute lets Data Protection prefer the older key;
    // merely creating encrypted XML does not prove the new key serves data.
    var activation = DateTimeOffset.UtcNow.AddSeconds(2);
    manager.CreateNewKey(activation, DateTimeOffset.UtcNow.AddDays(30));
    var untilActivation = activation - DateTimeOffset.UtcNow;
    if (untilActivation > TimeSpan.Zero)
        Thread.Sleep(untilActivation + TimeSpan.FromMilliseconds(350));
    var newestFiles = Directory.GetFiles(ring, "*.xml")
        .Where(path => !beforeRotationFiles.Contains(Path.GetFileName(path))).ToArray();
    Check(newestFiles.Length == 1,
        "explicit rotation writes exactly one new encrypted Data Protection XML key");
    var newestXml = File.ReadAllText(newestFiles[0]);
    Check(newestXml.Contains("<encryptedSecret", StringComparison.Ordinal) &&
          !newestXml.Contains("<masterKey", StringComparison.Ordinal),
        "rotated Windows fleet key remains encrypted at rest");
    // ASP.NET Core emits the recipient X.509 certificate in encryptedKey
    // XML. Require the NEW certificate (t2), never the retired t1.
    var newRecipientBytes = Convert.ToBase64String(rotated.RawData);
    var oldRecipientBytes = Convert.ToBase64String(active.RawData);
    Check(newestXml.Contains(newRecipientBytes, StringComparison.Ordinal) &&
          !newestXml.Contains(oldRecipientBytes, StringComparison.Ordinal),
        "new rotated XML is bound to the current RSA recipient t2 rather than t1");

    // A FRESH provider is needed: the original provider may cache an
    // active key chosen before CreateNewKey was called.
    using var freshWriter = Build("gateway-two");
    var latest = freshWriter.GetRequiredService<IDataProtectionProvider>()
        .CreateProtector("gatewaycore-windows-fleet-cookie-v1")
        .Protect("portable-cookie");
    Check(CanRead(freshWriter, latest),
        "fresh writer protects with a new key after explicit rotation");
    // Verify the ACTUAL key GUID encoded into the cookie, not merely that
    // a newly generated XML key exists. This catches provider-cache reuse.
    var payload = Microsoft.AspNetCore.WebUtilities.WebEncoders.Base64UrlDecode(latest);
    Check(payload.Length > 20 && payload.AsSpan(0, 4).SequenceEqual(
              new byte[] { 0x09, 0xF0, 0xC9, 0xF0 }),
        "new portable cookie has the expected ASP.NET DP key envelope");
    var cookieKeyId = new Guid(payload.AsSpan(4, 16));
    var newXmlKeyId = System.Xml.Linq.XDocument.Load(newestFiles[0])
        .Root?.Attribute("id")?.Value;
    Check(Guid.TryParse(newXmlKeyId, out var expectedKeyId) &&
          cookieKeyId == expectedKeyId,
        "new cookie is protected with the newly rotated t2-wrapped key ID");


    var recipientDir = Path.Combine(root, "gateway-three");
    Directory.CreateDirectory(recipientDir);
    File.Copy(newestFiles[0], Path.Combine(recipientDir, Path.GetFileName(newestFiles[0])));
    // Remove old RSA identity from the machine store to approximate an
    // isolated recipient that ONLY possesses the current t2 key. Existing
    // providers remain disposable; this does not qualify real hosts.
    using (var machineStore = new X509Store(StoreName.My, StoreLocation.LocalMachine))
    {
        machineStore.Open(OpenFlags.ReadWrite);
        machineStore.Remove(active);
        try
        {
            Environment.SetEnvironmentVariable(Current, t2);
            Environment.SetEnvironmentVariable(Previous, null);
            using var freshRecipient = Build("gateway-three");
            Check(CanRead(freshRecipient, latest),
                "new cookie works on a fresh recipient with only current t2 certificate");
            Check(!CanRead(freshRecipient, token),
                "old cookie cannot be used by t2-only recipient without old key XML");
        }
        finally
        {
            machineStore.Add(active);
        }
    }
    Environment.SetEnvironmentVariable(Current, t2);
    Environment.SetEnvironmentVariable(Previous, t1);
    using var overlapReader = Build("gateway-two");
    Check(CanRead(overlapReader, token) && CanRead(overlapReader, latest),
        "staged rotation overlap accepts both old and new cookies");
    Check(Directory.GetFiles(ring, "*.xml").Length > 1,
        "rotation persisted old and new encrypted key XML revisions");
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
