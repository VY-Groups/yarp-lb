using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
(string Pfx,string PasswordFile) CreateCertificate(string prefix)
{
    using var rsa=RSA.Create(3072);
    var request=new CertificateRequest("CN=DP "+prefix,rsa,
        HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
    request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
    request.CertificateExtensions.Add(new X509KeyUsageExtension(
        X509KeyUsageFlags.KeyEncipherment|X509KeyUsageFlags.DataEncipherment,true));
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
    File.SetUnixFileMode(first.PasswordFile,
        PrivateFile|UnixFileMode.OtherRead);
    Assert(Throws(()=>{using var _=Provider(state);}),
        "0644 secret password file is refused");
    File.SetUnixFileMode(first.PasswordFile,PrivateFile);
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
    Console.WriteLine("LINUX DATA PROTECTION ACCEPTANCE PASSED");
}
finally
{
    foreach(var (key,value) in previousEnv) Set(key,value);
    Directory.Delete(root,true);
}
