using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;

static void Assert(bool condition, string message)
{
    if (!condition) throw new Exception("FAIL: " + message);
    Console.WriteLine("PASS: " + message);
}
if (!OperatingSystem.IsLinux())
{
    Console.WriteLine("SKIP: Linux-specific filesystem/DAPI tests on non-Linux host");
    return;
}
const UnixFileMode PrivateDir=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
const UnixFileMode PrivateFile=UnixFileMode.UserRead|UnixFileMode.UserWrite;
var root = Path.Combine(Path.GetTempPath(),"yarp-linux-dp-test-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(root,PrivateDir);
var state=Path.Combine(root,"state");
var secrets=Path.Combine(root,"secrets");
Directory.CreateDirectory(secrets,PrivateDir);
var previousEnv=new[] {
    "YARP_CONTROL_PLANE_DIR","YARP_LINUX_DP_CERT_PFX_PATH",
    "YARP_LINUX_DP_CERT_PASSWORD_FILE",
    "YARP_LINUX_DP_OLD_CERT_PFX_PATH","YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE"
}.ToDictionary(k=>k,k=>Environment.GetEnvironmentVariable(k));
void Set(string key,string? value) => Environment.SetEnvironmentVariable(key,value);
(string Pfx,string PasswordFile) CreateCertificate(string prefix,
    X509KeyUsageFlags? keyUsage=X509KeyUsageFlags.KeyEncipherment|X509KeyUsageFlags.DataEncipherment,
    bool isCa=false, bool includeBasicConstraints=true)
{
    using var rsa=RSA.Create(3072);
    var request=new CertificateRequest("CN=DP "+prefix,rsa,
        HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    if(includeBasicConstraints)
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(isCa,false,0,true));
    if(keyUsage is { } flags)
        request.CertificateExtensions.Add(new X509KeyUsageExtension(flags,true));
    using var cert=request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
        DateTimeOffset.UtcNow.AddDays(30));
    var pass=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    var pfx=Path.Combine(secrets,prefix+".pfx");
    var secret=Path.Combine(secrets,prefix+".password");
    File.WriteAllBytes(pfx,cert.Export(X509ContentType.Pfx,pass));
    File.WriteAllText(secret,pass+"\n");
    File.SetUnixFileMode(pfx,PrivateFile);
    File.SetUnixFileMode(secret,PrivateFile);
    return(pfx,secret);
}
ServiceProvider Provider(string statePath)
{
    var services=new ServiceCollection();
    var keys=Path.Combine(statePath,"data-protection-keys");
    var builder=services.AddDataProtection()
        .SetApplicationName("OnPremLinuxDpIntegration.v1")
        .PersistKeysToFileSystem(new DirectoryInfo(keys));
    LinuxKeyProtection.Configure(builder,statePath);
    return services.BuildServiceProvider();
}
static bool Throws(Action action)
{
    try {action();return false;}
    catch (Exception ex) when (ex is InvalidOperationException or
        CryptographicException or UnauthorizedAccessException) {return true;}
}
try
{
    var first=CreateCertificate("first");
    var second=CreateCertificate("second");
    Set("YARP_CONTROL_PLANE_DIR",state);
    Set("YARP_LINUX_DP_CERT_PFX_PATH",first.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",first.PasswordFile);
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",null);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",null);
    Assert(LinuxKeyProtection.InitializeStateDirectory()==state,
        "private Linux state initialized from explicit absolute path");
    Assert(File.GetUnixFileMode(state)==PrivateDir &&
        File.GetUnixFileMode(Path.Combine(state,"data-protection-keys"))==PrivateDir,
        "persisted key directories are owner-only 0700");
    string encrypted;
    using(var service=Provider(state))
    {
        var dp=service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe");
        encrypted=dp.Protect("sensitive-session-value-123");
        Assert(encrypted!="sensitive-session-value-123","protector encrypts contents");
    }
    var keyFiles=Directory.GetFiles(Path.Combine(state,"data-protection-keys"),"key-*.xml");
    Assert(keyFiles.Length>0,"persisted DP key XML exists");
    var xml=File.ReadAllText(keyFiles[0]);
    Assert(xml.Contains("<encryptedSecret") && !xml.Contains("<masterKey"),
        "persisted master key XML is certificate-wrapped, not plaintext");
    using(var service=Provider(state))
    {
        var dp=service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe");
        Assert(dp.Unprotect(encrypted)=="sensitive-session-value-123",
            "session value decrypts across a new service provider using persisted key ring");
    }
    // Build a real legacy plaintext ring with ASP.NET's unwrapped file
    // repository, then ensure protected mode refuses it without mutation.
    var legacyState=Path.Combine(root,"legacy-plaintext-state");
    Set("YARP_CONTROL_PLANE_DIR",legacyState);
    LinuxKeyProtection.InitializeStateDirectory();
    var legacyDirectory=Path.Combine(legacyState,"data-protection-keys");
    var legacyServices=new ServiceCollection();
    legacyServices.AddDataProtection().SetApplicationName("OnPremLinuxDpIntegration.v1")
        .PersistKeysToFileSystem(new DirectoryInfo(legacyDirectory));
    using(var legacyProvider=legacyServices.BuildServiceProvider())
        _=legacyProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Protect("legacy-lab-only-session");
    var legacyFile=Directory.GetFiles(legacyDirectory,"key-*.xml").Single();
    File.SetUnixFileMode(legacyFile,PrivateFile);
    var legacyBytes=File.ReadAllBytes(legacyFile);
    Assert(System.Text.Encoding.UTF8.GetString(legacyBytes).Contains("<masterKey"),
        "legacy fixture contains a real unwrapped master key");
    Assert(Throws(()=>{using var _=Provider(legacyState);}) &&
           File.ReadAllBytes(legacyFile).SequenceEqual(legacyBytes),
        "protected startup refuses legacy plaintext key ring without overwriting it");
    var protectedFile=keyFiles[0];
    var originalMode=File.GetUnixFileMode(protectedFile);
    File.SetUnixFileMode(protectedFile,originalMode|UnixFileMode.OtherRead);
    Assert(Throws(()=>{using var _=Provider(state);}), "public-readable persisted key XML is refused");
    File.SetUnixFileMode(protectedFile,originalMode);
    var symlink=Path.Combine(Path.GetDirectoryName(protectedFile)!,"key-test-link.xml");
    File.CreateSymbolicLink(symlink,protectedFile);
    Assert(Throws(()=>{using var _=Provider(state);}), "symlinked persisted key XML is refused");
    File.Delete(symlink);
    var protectedKeyBytesBefore=File.ReadAllBytes(protectedFile);
    var forgedRevocation=Path.Combine(Path.GetDirectoryName(protectedFile)!,"revocation-hostile.xml");
    const string forbiddenMasterKey="DISPOSABLE_TEST_PLAINTEXT_KEY_MATERIAL";
    var forgedRevocationBytes=System.Text.Encoding.UTF8.GetBytes(
        "<revocation version=\"1\"><masterKey>"+forbiddenMasterKey+"</masterKey></revocation>");
    File.WriteAllBytes(forgedRevocation,forgedRevocationBytes);
    File.SetUnixFileMode(forgedRevocation,PrivateFile);
    Assert(Throws(()=>{using var _=Provider(state);}) &&
           File.ReadAllBytes(forgedRevocation).SequenceEqual(forgedRevocationBytes),
        "revocation XML cannot conceal plaintext master key material and is not mutated");
    File.Delete(forgedRevocation);
    Assert(File.ReadAllBytes(protectedFile).SequenceEqual(protectedKeyBytesBefore),
        "rejected rogue revocation does not alter the original wrapped key ring");
    var tamperState=Path.Combine(root,"tamper-state");
    Set("YARP_CONTROL_PLANE_DIR",tamperState);
    LinuxKeyProtection.InitializeStateDirectory();
    string tamperedSession;
    using(var service=Provider(tamperState))
        tamperedSession=service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Protect("session-before-disk-tamper");
    var tamperedKeyFile=Directory.GetFiles(Path.Combine(tamperState,"data-protection-keys"),"key-*.xml").Single();
    var tamperedDocument=XDocument.Load(tamperedKeyFile);
    var encryptedSecretElement=tamperedDocument.Descendants()
        .Single(element=>element.Name.LocalName=="encryptedSecret");
    var encryptedDataElement=encryptedSecretElement.Elements()
        .Single(element=>element.Name.LocalName=="EncryptedData");
    var cipherDataElement=encryptedDataElement.Elements()
        .Single(element=>element.Name.LocalName=="CipherData");
    var cipherValueElement=cipherDataElement.Elements()
        .Single(element=>element.Name.LocalName=="CipherValue");
    var encryptedSecretBytes=Convert.FromBase64String(cipherValueElement.Value);
    Assert(encryptedSecretBytes.Length>0,"persisted encrypted secret contains a valid ciphertext payload");
    // Corrupt the first encrypted byte so the wrapped key cannot be recovered.
    encryptedSecretBytes[0]^=0x01;
    cipherValueElement.Value=Convert.ToBase64String(encryptedSecretBytes);
    File.WriteAllText(tamperedKeyFile,tamperedDocument.ToString(SaveOptions.DisableFormatting));
    Set("YARP_CONTROL_PLANE_DIR",tamperState);
    Assert(Throws(()=>
    {
        using var service=Provider(tamperState);
        service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(tamperedSession);
    }),"tampering with persisted encrypted key material never authenticates an existing session");
    Set("YARP_CONTROL_PLANE_DIR",state);
    File.SetUnixFileMode(first.PasswordFile,
        PrivateFile|UnixFileMode.OtherRead);
    Assert(Throws(()=>{using var _=Provider(state);}),
        "0644 secret password file is refused");
    File.SetUnixFileMode(first.PasswordFile,PrivateFile);
    var linkedSecrets=Path.Combine(root,"linked-secrets");
    Directory.CreateSymbolicLink(linkedSecrets,secrets);
    Set("YARP_LINUX_DP_CERT_PFX_PATH",Path.Combine(linkedSecrets,Path.GetFileName(first.Pfx)));
    Assert(Throws(()=>{using var _=Provider(state);}), "symlinked PFX ancestor refused");
    Set("YARP_LINUX_DP_CERT_PFX_PATH",first.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",Path.Combine(linkedSecrets,Path.GetFileName(first.PasswordFile)));
    Assert(Throws(()=>{using var _=Provider(state);}), "symlinked password ancestor refused");
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",first.PasswordFile);
    File.SetUnixFileMode(secrets,PrivateDir|UnixFileMode.OtherWrite);
    Assert(Throws(()=>{using var _=Provider(state);}), "world-writable secret ancestor refused");
    File.SetUnixFileMode(secrets,PrivateDir);
    // Wrapping certificates are dedicated RSA encryption *leaf* identities.
    // Bad certificates must fail at configuration time, not at the first
    // user sign-in or when a new Data Protection key is generated.
    var signingOnly=CreateCertificate("sign-only", X509KeyUsageFlags.DigitalSignature);
    var issuer=CreateCertificate("issuer-only", X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.KeyEncipherment, isCa:true);
    var missingUsage=CreateCertificate("without-usage", keyUsage:null);
    var missingConstraints=CreateCertificate("without-basic-constraints", includeBasicConstraints:false);
    foreach(var invalid in new[] {
        (Identity:signingOnly,Label:"signing-only RSA identity"),
        (Identity:issuer,Label:"CA signing identity"),
        (Identity:missingUsage,Label:"certificate without key usage"),
        (Identity:missingConstraints,Label:"certificate without leaf basic constraints")
    })
    {
        Set("YARP_LINUX_DP_CERT_PFX_PATH",invalid.Identity.Pfx);
        Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",invalid.Identity.PasswordFile);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "Linux DP refuses " + invalid.Label);
    }
    Set("YARP_LINUX_DP_CERT_PFX_PATH",first.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",first.PasswordFile);
    var originalPassword=File.ReadAllBytes(first.PasswordFile);
    File.WriteAllText(first.PasswordFile,new string('x',4097));
    Assert(Throws(()=>{using var _=Provider(state);}), "oversized wrapping password refused");
    File.WriteAllBytes(first.PasswordFile,originalPassword);
    File.SetUnixFileMode(state,PrivateDir|UnixFileMode.GroupRead);
    Assert(Throws(()=>LinuxKeyProtection.InitializeStateDirectory()),
        "0750 state directory is refused");
    File.SetUnixFileMode(state,PrivateDir);
    Set("YARP_LINUX_DP_CERT_PFX_PATH",null);
    Assert(Throws(()=>{using var _=Provider(state);}),
        "missing Linux protection certificate fails closed");
    Set("YARP_LINUX_DP_CERT_PFX_PATH",first.Pfx);
    File.WriteAllText(first.PasswordFile,"incorrect-password");
    Assert(Throws(()=>{using var _=Provider(state);}),
        "incorrect certificate password fails closed");
    var correct=File.ReadAllText(second.PasswordFile);
    // Restore original first secret by regenerating its original password
    // from the prior encrypted PFX is intentionally impossible; create a
    // third fresh identity for the rotation acceptance below.
    var replacement=CreateCertificate("replacement");
    Set("YARP_LINUX_DP_CERT_PFX_PATH",replacement.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",replacement.PasswordFile);
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",second.Pfx);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",null);
    Assert(Throws(()=>{using var _=Provider(state);}),
        "incomplete previous certificate rotation config is refused");
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",second.PasswordFile);
    using(var service=Provider(state))
    {
        var dp=service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe");
        var ciphertext=dp.Protect("new-protected-message");
        Assert(dp.Unprotect(ciphertext)=="new-protected-message",
            "new current RSA identity remains usable during overlap");
    }
    // Actual old->new key rotation with persistent old session:
    // use second identity for NEW key ring and then select replacement
    // current while keeping second as a decryption certificate.
    var rotationState=Path.Combine(root,"rotation-state");
    Set("YARP_CONTROL_PLANE_DIR",rotationState);
    LinuxKeyProtection.InitializeStateDirectory();
    Set("YARP_LINUX_DP_CERT_PFX_PATH",second.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",second.PasswordFile);
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",null);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",null);
    string beforeRotation;
    using(var provider=Provider(rotationState))
        beforeRotation=provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Protect("before-rotation");
    Set("YARP_LINUX_DP_CERT_PFX_PATH",replacement.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE",replacement.PasswordFile);
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",second.Pfx);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",second.PasswordFile);
    using(var provider=Provider(rotationState))
        Assert(provider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(beforeRotation)=="before-rotation",
            "old session decrypts with previous certificate during rotation overlap");
    await ProductLinuxStartupSmoke.RunAsync();
    await SystemdServiceAcceptance.RunTerminationCleanupContractAsync();
    await SystemdServiceAcceptance.RunFromGitHubLinuxAsync();
    Console.WriteLine("LINUX DATA PROTECTION ACCEPTANCE PASSED");
}
finally
{
    foreach(var (key,value) in previousEnv) Set(key,value);
    Directory.Delete(root,true);
}
