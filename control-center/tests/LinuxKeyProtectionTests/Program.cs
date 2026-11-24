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
// DP-09/DP-13: execute the real key-ring loader in a separate OS process.
// The disposable protected cookie and expected plaintext travel over stdin, never argv or logs.
if (args.Length > 0 && args[0] == "--verify-cookie")
{
    if (args.Length != 4) Environment.Exit(2);
    try
    {
        Environment.SetEnvironmentVariable("YARP_CONTROL_PLANE_DIR", args[1]);
        var childServices = new ServiceCollection();
        var childBuilder = childServices.AddDataProtection()
            .SetApplicationName(args[2])
            .PersistKeysToFileSystem(new DirectoryInfo(
                Path.Combine(args[1], "data-protection-keys")));
        LinuxKeyProtection.Configure(childBuilder, args[1]);
        using var childProvider = childServices.BuildServiceProvider();
        var protectedCookie = Console.In.ReadLine()
            ?? throw new InvalidOperationException("Missing disposable cookie");
        var expectedPlaintext = Console.In.ReadLine()
            ?? throw new InvalidOperationException("Missing expected plaintext");
        var clear = childProvider.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector(args[3]).Unprotect(protectedCookie);
        Environment.Exit(clear == expectedPlaintext ? 0 : 3);
    }
    catch (Exception)
    {
        // Do not print the cookie, decrypted value or sensitive paths.
        Environment.Exit(3);
    }
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
    "YARP_LINUX_DP_OLD_CERT_PFX_PATH","YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",
    LinuxDpRecoveryEvidence.ManifestEnv, LinuxDpRecoveryEvidence.PublicKeyEnv,
    LinuxDpRecoveryEvidence.MinimumRevisionEnv,
    LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,
    LinuxDpRecoveryEvidence.RequireEvidenceEnv
}.ToDictionary(k=>k,k=>Environment.GetEnvironmentVariable(k));
void Set(string key,string? value) => Environment.SetEnvironmentVariable(key,value);
// A hard link has a different pathname but the same backing inode; neither
// GetFullPath nor realpath detects it. Use the standard Linux utility in the
// disposable Ubuntu runner to construct this restore-trust bypass fixture.
void MakeHardLink(string existingFile, string additionalPath)
{
    var start = new System.Diagnostics.ProcessStartInfo("ln")
    {
        UseShellExecute = false,
        RedirectStandardError = true
    };
    start.ArgumentList.Add("--");
    start.ArgumentList.Add(existingFile);
    start.ArgumentList.Add(additionalPath);
    using var process = System.Diagnostics.Process.Start(start)
        ?? throw new Exception("FAIL: Linux hardlink regression fixture could not launch ln");
    if (!process.WaitForExit(5000) || process.ExitCode != 0)
        throw new Exception("FAIL: Linux hardlink regression fixture could not create an inode alias");
}
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
ServiceProvider Provider(string statePath, string applicationName = "OnPremLinuxDpIntegration.v1")
{
    var services=new ServiceCollection();
    var keys=Path.Combine(statePath,"data-protection-keys");
    var builder=services.AddDataProtection()
        .SetApplicationName(applicationName)
        .PersistKeysToFileSystem(new DirectoryInfo(keys));
    LinuxKeyProtection.Configure(builder,statePath);
    return services.BuildServiceProvider();
}
// Return only the exit status. Disposable authentication material is sent via
// stdin and is never placed in command-line arguments or diagnostic output.
int VerifyInFreshProcess(string statePath, string applicationName,
    string purpose, string protectedCookie, string expected)
{
    var assemblyPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
    var start = new System.Diagnostics.ProcessStartInfo("dotnet")
    {
        UseShellExecute = false,
        RedirectStandardInput = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    foreach (var arg in new[] { assemblyPath, "--verify-cookie", statePath,
        applicationName, purpose })
        start.ArgumentList.Add(arg);
    using var child = System.Diagnostics.Process.Start(start)
        ?? throw new Exception("FAIL: disposable child process could not start");
    child.StandardInput.WriteLine(protectedCookie);
    child.StandardInput.WriteLine(expected);
    child.StandardInput.Close();
    if (!child.WaitForExit(60000))
    {
        child.Kill(entireProcessTree: true);
        throw new Exception("FAIL: disposable child process timed out");
    }
    return child.ExitCode;
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

    // Validate bootstrap safety, not just a later secret-file read. A plain
    // Directory.CreateDirectory() through a parent symlink would create a
    // new directory outside the intended state tree *before* rejecting it.
    var missingSymlinkTarget=Path.Combine(root,"must-not-be-created");
    var linkedAncestor=Path.Combine(root,"linked-uncreated-state");
    Directory.CreateSymbolicLink(linkedAncestor,missingSymlinkTarget);
    Set("YARP_CONTROL_PLANE_DIR",Path.Combine(linkedAncestor,"state"));
    Assert(Throws(()=>LinuxKeyProtection.InitializeStateDirectory()) &&
           !Directory.Exists(missingSymlinkTarget),
        "startup rejects dangling parent link without creating its missing target");
    File.Delete(linkedAncestor);

    var existingLinkedTarget=Path.Combine(root,"existing-link-target");
    Directory.CreateDirectory(existingLinkedTarget,PrivateDir);
    var existingAncestor=Path.Combine(root,"linked-existing-state");
    Directory.CreateSymbolicLink(existingAncestor,existingLinkedTarget);
    Set("YARP_CONTROL_PLANE_DIR",Path.Combine(existingAncestor,"new-subtree"));
    Assert(Throws(()=>LinuxKeyProtection.InitializeStateDirectory()) &&
           !Directory.Exists(Path.Combine(existingLinkedTarget,"new-subtree")),
        "startup refuses existing symlinked ancestor before creating a state subtree");
    File.Delete(existingAncestor);

    var alternateState=Path.Combine(root,"linked-keyring-parent");
    Directory.CreateDirectory(alternateState,PrivateDir);
    var redirectedKeys=Path.Combine(root,"never-create-external-keyring");
    var linkedKeyDir=Path.Combine(alternateState,"data-protection-keys");
    Directory.CreateSymbolicLink(linkedKeyDir,redirectedKeys);
    Set("YARP_CONTROL_PLANE_DIR",alternateState);
    Assert(Throws(()=>LinuxKeyProtection.InitializeStateDirectory()) &&
           !Directory.Exists(redirectedKeys),
        "startup refuses dangling key-ring link before creating any external key directory");
    File.Delete(linkedKeyDir);
    Set("YARP_CONTROL_PLANE_DIR",state);

    // A hardlinked secret can leave the protected provisioning directory
    // without any symlink or realpath difference. Reject both RSA PFX and
    // password aliases based on the already-open file's inode link count.
    foreach (var (sourceSecret, aliasName) in new[]
    {
        (first.Pfx, "rsa-pfx-hardlink-alias"),
        (first.PasswordFile, "rsa-password-hardlink-alias")
    })
    {
        var extraLink=Path.Combine(root,aliasName);
        MakeHardLink(sourceSecret,extraLink);
        try
        {
            Assert(Throws(()=>{ using var _=Provider(state); }),
                "Linux wrapping secret hardlink alias is rejected: "+aliasName);
        }
        finally { File.Delete(extraLink); }
        Assert(File.ReadAllBytes(sourceSecret).Length>0,
            "rejecting a secret alias does not mutate the protected secret");
    }
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
    // Two distinct private state roots simulate separate on-prem Linux
    // instances. Provision only the same operator-approved wrapping identity
    // and a byte-for-byte copy of encrypted XML; never create plaintext keys
    // or claim these directories are separate physical machines.
    var fleetReplicaState = Path.Combine(root, "fleet-replica-state");
    Set("YARP_CONTROL_PLANE_DIR", fleetReplicaState);
    Assert(LinuxKeyProtection.InitializeStateDirectory() == fleetReplicaState,
        "independent fleet replica initializes a separate private key-ring root");
    Set("YARP_CONTROL_PLANE_DIR", state);
    var fleetReplicaKeys = Path.Combine(fleetReplicaState, "data-protection-keys");
    foreach (var protectedKey in keyFiles)
    {
        var replicaKeyPath = Path.Combine(fleetReplicaKeys, Path.GetFileName(protectedKey));
        File.Copy(protectedKey, replicaKeyPath, overwrite: false);
        File.SetUnixFileMode(replicaKeyPath, PrivateFile);
    }
    Assert(Directory.GetFiles(fleetReplicaKeys, "key-*.xml").Length == keyFiles.Length &&
        Directory.GetFiles(fleetReplicaKeys, "key-*.xml").All(path =>
            File.ReadAllText(path).Contains("<encryptedSecret", StringComparison.Ordinal) &&
            !File.ReadAllText(path).Contains("<masterKey", StringComparison.Ordinal)),
        "replicated key-ring preserves only certificate-wrapped XML");
    string replicaProtectedCookie;
    using (var replica = Provider(fleetReplicaState))
    {
        var dp = replica.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe");
        Assert(dp.Unprotect(encrypted) == "sensitive-session-value-123",
            "replica decrypts original session using approved shared wrapping identity");
        replicaProtectedCookie = dp.Protect("replica-auth-session");
    }
    using (var origin = Provider(state))
        Assert(origin.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(replicaProtectedCookie) ==
            "replica-auth-session",
            "original node decrypts replica session with unchanged app/purpose identity");

    // Separate .NET processes must independently load the encrypted ring.
    // A same-process DI-container check alone cannot prove restart/fleet
    // continuity. This is a disposable multi-process software test, not a
    // physical two-host acceptance.
    Assert(VerifyInFreshProcess(fleetReplicaState,
        "OnPremLinuxDpIntegration.v1", "session-probe", encrypted,
        "sensitive-session-value-123") == 0,
        "DP-09 replica process decrypts origin cookie using shared wrapped ring");
    Assert(VerifyInFreshProcess(state,
        "OnPremLinuxDpIntegration.v1", "session-probe", replicaProtectedCookie,
        "replica-auth-session") == 0,
        "DP-09 origin process decrypts replica cookie after independent restart");
    Assert(VerifyInFreshProcess(fleetReplicaState,
        "OnPremLinuxDpIntegration.other-fleet", "session-probe", encrypted,
        "sensitive-session-value-123") != 0,
        "DP-13 separate process rejects cookie with foreign fleet discriminator");
    Assert(VerifyInFreshProcess(fleetReplicaState,
        "OnPremLinuxDpIntegration.v1", "unrelated-authentication-purpose",
        encrypted, "sensitive-session-value-123") != 0,
        "DP-13 separate process rejects cookie with unrelated purpose");

    // DP-13: even when two fleets mistakenly share the same encrypted key XML
    // and wrapping certificate, the Data Protection application discriminator
    // must prevent accepting another fleet's session. The purpose chain must
    // independently reject a token from an unrelated authentication protocol.
    using (var otherFleet = Provider(fleetReplicaState, "OnPremLinuxDpIntegration.other-fleet"))
    {
        var foreignProtector = otherFleet.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe");
        Assert(Throws(() => foreignProtector.Unprotect(encrypted)),
            "DP-13 rejects cross-fleet session despite identical encrypted ring and RSA key");
        var foreignCookie = foreignProtector.Protect("other-fleet-session");
        using var originalFleet = Provider(state);
        Assert(Throws(() => originalFleet.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(foreignCookie)),
            "DP-13 rejects foreign-fleet session in both directions");
    }
    using (var sameFleet = Provider(fleetReplicaState))
    {
        Assert(Throws(() => sameFleet.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("unrelated-authentication-purpose").Unprotect(encrypted)),
            "DP-13 rejects unrelated authentication purpose with shared fleet key");
        Assert(sameFleet.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted) ==
                "sensitive-session-value-123",
            "DP-13 rejection leaves authorized fleet session decryptable");
    }

    // A different authorized RSA key is NOT automatically a decryption key
    // for a recovered ring. Do not silently generate replacement sessions or
    // treat successful startup as successful restoration.
    Set("YARP_LINUX_DP_CERT_PFX_PATH", second.Pfx);
    Set("YARP_LINUX_DP_CERT_PASSWORD_FILE", second.PasswordFile);
    try
    {
        Assert(Throws(() =>
        {
            using var replica = Provider(fleetReplicaState);
            _ = replica.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted);
        }), "replica rejects restored cookie without its original wrapping private key");
    }
    finally
    {
        Set("YARP_LINUX_DP_CERT_PFX_PATH", first.Pfx);
        Set("YARP_LINUX_DP_CERT_PASSWORD_FILE", first.PasswordFile);
    }
    using (var replica = Provider(fleetReplicaState))
        Assert(replica.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(encrypted) ==
            "sensitive-session-value-123",
            "restored wrapping identity recovers the original replica session");

    // Restored encrypted keys must retain their filename/GUID identity.
    // A second case-variant filename exercises the duplicate guard on Linux,
    // where both paths can coexist while passing the case-insensitive GUID check.
    var initialKeyPath = keyFiles[0];
    var originalProtectedBytes = File.ReadAllBytes(initialKeyPath);
    var tamperedIdentity = XDocument.Load(initialKeyPath);
    var originalIdText = (string?)tamperedIdentity.Root?.Attribute("id")
        ?? throw new Exception("FAIL: valid Data Protection key did not contain a GUID");
    var originalGuid = Guid.Parse(originalIdText);
    var otherGuid = originalGuid == Guid.Empty ? Guid.Parse("00000000-0000-0000-0000-000000000001") : Guid.Empty;
    tamperedIdentity.Root!.SetAttributeValue("id", otherGuid.ToString("D"));
    try
    {
        File.WriteAllText(initialKeyPath, tamperedIdentity.ToString(SaveOptions.DisableFormatting));
        Assert(Throws(()=>{using var _=Provider(state);}),
            "restored wrapped key XML with mismatched filename/embedded GUID is refused");
    }
    finally { File.WriteAllBytes(initialKeyPath, originalProtectedBytes); }

    var canonicalKeyName = originalGuid.ToString("D");
    var caseVariantKeyName = canonicalKeyName.ToUpperInvariant();
    if (caseVariantKeyName == canonicalKeyName)
    {
        var index = canonicalKeyName.IndexOfAny("abcdef".ToCharArray());
        if (index >= 0)
        {
            var chars = canonicalKeyName.ToCharArray();
            chars[index] = char.ToUpperInvariant(chars[index]);
            caseVariantKeyName = new string(chars);
        }
    }
    if (caseVariantKeyName != canonicalKeyName)
    {
        var copiedKey = Path.Combine(Path.GetDirectoryName(initialKeyPath)!,
            "key-" + caseVariantKeyName + ".xml");
        File.WriteAllBytes(copiedKey, originalProtectedBytes);
        File.SetUnixFileMode(copiedKey, PrivateFile);
        try
        {
            Assert(Throws(()=>{using var _=Provider(state);}),
                "duplicate master-key GUID under a case-variant filename is refused");
        }
        finally { File.Delete(copiedKey); }
    }

    // A restored ring may carry an approved wrapped element and a second
    // foreign-namespace lookalike. Reject the whole document before import.
    var foreignSecretDocument = XDocument.Load(initialKeyPath);
    foreignSecretDocument.Root!.Add(new XElement(
        XName.Get("encryptedSecret", "urn:gatewaycore:test:foreign"), "disposable-fixture"));
    try
    {
        File.WriteAllText(initialKeyPath,
            foreignSecretDocument.ToString(SaveOptions.DisableFormatting));
        Assert(Throws(()=>{using var _=Provider(state);}),
            "foreign-namespace encryptedSecret beside valid wrapper is refused");
    }
    finally { File.WriteAllBytes(initialKeyPath, originalProtectedBytes); }

    var foreignDecryptorDocument = XDocument.Load(initialKeyPath);
    var wrappedElement = foreignDecryptorDocument.Descendants()
        .Single(element => element.Name.LocalName == "encryptedSecret");
    wrappedElement.SetAttributeValue("decryptorType",
        "Other.Namespace.EncryptedXmlDecryptor, Microsoft.AspNetCore.DataProtection");
    try
    {
        File.WriteAllText(initialKeyPath,
            foreignDecryptorDocument.ToString(SaveOptions.DisableFormatting));
        Assert(Throws(()=>{using var _=Provider(state);}),
            "unapproved certificate decryptor type is refused");
    }
    finally { File.WriteAllBytes(initialKeyPath, originalProtectedBytes); }

    var excessiveFiles = new List<string>();
    try
    {
        for (var n = 0; n < 512; n++)
        {
            var rogue = Path.Combine(Path.GetDirectoryName(initialKeyPath)!,
                "rogue-" + n.ToString("D4") + ".xml");
            File.WriteAllText(rogue, string.Empty);
            File.SetUnixFileMode(rogue, PrivateFile);
            excessiveFiles.Add(rogue);
        }
        Assert(Throws(()=>{using var _=Provider(state);}),
            "key-ring startup refuses an XML inventory exceeding 512 entries");
    }
    finally
    {
        foreach (var rogue in excessiveFiles) File.Delete(rogue);
    }
    using (var service = Provider(state))
        Assert(service.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(encrypted) ==
            "sensitive-session-value-123",
            "original encrypted session remains decryptable after rejected restore tampering");

    // A trust key held outside the restored ring signs an exact bounded
    // inventory. The independent minimum revision prevents accepting an
    // otherwise valid older signed snapshot during a staged recovery.
    using(var attestationSigner=ECDsa.Create(ECCurve.NamedCurves.nistP256))
    {
        var trustedPublicPath=Path.Combine(secrets,"recovery-verifier.pem");
        var attestationPath=Path.Combine(secrets,"recovery-attestation.json");
        File.WriteAllText(trustedPublicPath,attestationSigner.ExportSubjectPublicKeyInfoPem());
        File.SetUnixFileMode(trustedPublicPath,PrivateFile);
        var keyDirectory=Path.Combine(state,"data-protection-keys");
        var inventoryHash=LinuxDpRecoveryEvidence.ComputeInventoryDigest(keyDirectory);
        // The standalone issuer must produce a byte-for-byte compatible
        // checkpoint using an independently custodied P-256 signer. Run the
        // real tool on this disposable encrypted key ring, not a JSON mock.
        var signerPrivatePath=Path.Combine(secrets,"offline-issuer-private.pem");
        var revisionFloorPath=Path.Combine(secrets,"offline-revision-floor.txt");
        var generatedManifest=Path.Combine(secrets,"issued-offline-recovery.json");
        File.WriteAllText(signerPrivatePath,attestationSigner.ExportECPrivateKeyPem());
        File.SetUnixFileMode(signerPrivatePath,PrivateFile);
        File.WriteAllText(revisionFloorPath,"42" + Environment.NewLine);
        File.SetUnixFileMode(revisionFloorPath,PrivateFile);
        var issuerProject=Path.GetFullPath(Path.Combine("tools","LinuxDpRecoverySigner",
            "LinuxDpRecoverySigner.csproj"));
        Assert(File.Exists(issuerProject),"offline recovery issuer project exists");
        int RunIssuer(string signedRevision,string target,string verificationKey)
        {
            var start=new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                UseShellExecute=false,
                RedirectStandardError=true,
                RedirectStandardOutput=true
            };
            foreach (var arg in new[] {
                "run","--project",issuerProject,"--configuration","Release","--",
                "--ring",keyDirectory,"--revision",signedRevision,
                "--signing-key",signerPrivatePath,"--trust-public-key",verificationKey,
                "--minimum-revision-file",revisionFloorPath,
                "--manifest",target })
                start.ArgumentList.Add(arg);
            using var process=System.Diagnostics.Process.Start(start)
                ?? throw new Exception("FAIL: Cannot start offline checkpoint issuer");
            if (!process.WaitForExit(120000))
            {
                process.Kill(entireProcessTree:true);
                throw new Exception("FAIL: offline checkpoint issuer timeout");
            }
            return process.ExitCode;
        }
        Assert(RunIssuer("43",generatedManifest,trustedPublicPath)==0,
            "real offline P-256 issuer creates signed revision 43");
        Assert((File.GetUnixFileMode(generatedManifest)&(UnixFileMode.GroupRead|
            UnixFileMode.GroupWrite|UnixFileMode.OtherRead|UnixFileMode.OtherWrite))==0,
            "offline checkpoint remains owner-only on disk");
        LinuxDpRecoveryEvidence.Verify(keyDirectory,generatedManifest,trustedPublicPath,43);
        Assert(true,"real restore verifier accepts offline-issued inventory");
        var generatedOriginal=File.ReadAllBytes(generatedManifest);
        Assert(RunIssuer("43",generatedManifest,trustedPublicPath)!=0 &&
            File.ReadAllBytes(generatedManifest).SequenceEqual(generatedOriginal),
            "offline issuer cannot overwrite pre-existing signed checkpoint");
        var rejectedManifest=Path.Combine(secrets,"rejected-stale-recovery.json");
        Assert(RunIssuer("42",rejectedManifest,trustedPublicPath)!=0 &&
            !File.Exists(rejectedManifest),
            "offline issuer rejects non-increasing independent revision");
        var revision=42L;
        LinuxDpRecoveryManifest MakeAttestation(long signedRevision,string digest)
        {
            var payload=LinuxDpRecoveryEvidence.CanonicalPayload(signedRevision,digest);
            var signature=attestationSigner.SignData(payload,HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return new LinuxDpRecoveryManifest(1,signedRevision,digest,Convert.ToBase64String(signature));
        }
        var attestation=MakeAttestation(revision,inventoryHash);
        void WriteAttestation(LinuxDpRecoveryManifest value)
        {
            File.WriteAllText(attestationPath,System.Text.Json.JsonSerializer.Serialize(value));
            File.SetUnixFileMode(attestationPath,PrivateFile);
        }
        WriteAttestation(attestation);

        // Real separate CLI process: read the external trusted floor, reject
        // invalid signed evidence, atomically advance 42->43, and prove
        // replay/old signed snapshots cannot turn into successful recovery.
        var floorProject=Path.GetFullPath(Path.Combine("tools","LinuxDpRecoveryFloor",
            "LinuxDpRecoveryFloor.csproj"));
        Assert(File.Exists(floorProject),"offline revision-floor coordinator project exists");
        int RunFloorCommit(string proposedManifest,string floorFile)
        {
            var start=new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                UseShellExecute=false,RedirectStandardError=true,RedirectStandardOutput=true
            };
            foreach(var arg in new[] {
                "run","--project",floorProject,"--configuration","Release","--",
                "--ring",keyDirectory,"--checkpoint",proposedManifest,
                "--trusted-public-key",trustedPublicPath,"--revision-floor-file",floorFile })
                start.ArgumentList.Add(arg);
            using var proc=System.Diagnostics.Process.Start(start)
                ?? throw new Exception("FAIL: Cannot start Linux DP floor coordinator");
            if(!proc.WaitForExit(120000))
            {
                proc.Kill(entireProcessTree:true);
                throw new Exception("FAIL: offline revision commit timed out");
            }
            return proc.ExitCode;
        }
        Assert(LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==42,
            "externally stored Linux recovery floor starts at independently provisioned 42");
        var inventoryBeforeCommit=LinuxDpRecoveryEvidence.ComputeInventoryDigest(keyDirectory);
        var unsignedFloorCandidate=Path.Combine(secrets,"unsigned-floor-candidate.json");
        File.WriteAllText(unsignedFloorCandidate,
            System.Text.Json.JsonSerializer.Serialize(
                new LinuxDpRecoveryManifest(1,43,inventoryBeforeCommit,Convert.ToBase64String(new byte[64]))));
        File.SetUnixFileMode(unsignedFloorCandidate,PrivateFile);
        Assert(RunFloorCommit(unsignedFloorCandidate,revisionFloorPath)!=0 &&
            LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==42,
            "unsigned recovery cannot advance independent floor");
        var restoredSelfFloor=Path.Combine(state,"untrusted-recovery-floor.txt");
        File.WriteAllText(restoredSelfFloor,"42\n");
        File.SetUnixFileMode(restoredSelfFloor,PrivateFile);
        Assert(RunFloorCommit(generatedManifest,restoredSelfFloor)!=0 &&
            File.ReadAllText(restoredSelfFloor)=="42\n",
            "backup-contained floor cannot authorize its own recovery high-water");
        var linkedFloor=Path.Combine(secrets,"linked-floor.txt");
        File.CreateSymbolicLink(linkedFloor,revisionFloorPath);
        try
        {
            Assert(RunFloorCommit(generatedManifest,linkedFloor)!=0 &&
                LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==42,
                "symbolic alias cannot advance trusted revision floor");
        }
        finally { File.Delete(linkedFloor); }
        var protectedXml=keyFiles[0];
        var originalXml=File.ReadAllBytes(protectedXml);
        try
        {
            File.AppendAllText(protectedXml,"<!-- synthetic ring drift -->");
            File.SetUnixFileMode(protectedXml,PrivateFile);
            Assert(RunFloorCommit(generatedManifest,revisionFloorPath)!=0 &&
                LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==42,
                "changed encrypted inventory cannot advance signed floor");
        }
        finally
        {
            File.WriteAllBytes(protectedXml,originalXml);
            File.SetUnixFileMode(protectedXml,PrivateFile);
        }
        Assert(RunFloorCommit(generatedManifest,revisionFloorPath)==0 &&
            LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==43,
            "real verified offline coordinator durably commits signed 43 high-water");
        Assert(RunFloorCommit(generatedManifest,revisionFloorPath)!=0 &&
            LinuxDpRecoveryFloor.ReadExternalFloor(keyDirectory,revisionFloorPath)==43,
            "replayed signed revision cannot advance or overwrite the external floor");
        Assert(inventoryBeforeCommit==
            LinuxDpRecoveryEvidence.ComputeInventoryDigest(keyDirectory),
            "offline revision commitment never modifies the encrypted key ring");
        Assert((File.GetUnixFileMode(revisionFloorPath)&(UnixFileMode.GroupRead|
            UnixFileMode.GroupWrite|UnixFileMode.OtherRead|UnixFileMode.OtherWrite))==0,
            "committed independent floor persists privately");
        // Test RESTORATION into a fresh isolated key-ring root, not the
        // earlier live fleet replica. That replica may legitimately have
        // generated its own newer encrypted key and is not a byte-identical
        // backup snapshot. A recovery MUST preserve the signed exact XML
        // inventory before allowing the new service to use old sessions.
        var signedRestoreState=Path.Combine(root,"signed-recovery-replica-state");
        Set("YARP_CONTROL_PLANE_DIR",signedRestoreState);
        Assert(LinuxKeyProtection.InitializeStateDirectory()==signedRestoreState,
            "recovery creates a separate owner-only destination state");
        Set("YARP_CONTROL_PLANE_DIR",state);
        var signedRestoreKeys=Path.Combine(signedRestoreState,"data-protection-keys");
        foreach(var sourceKey in Directory.GetFiles(keyDirectory,"*.xml"))
        {
            var restoredFile=Path.Combine(signedRestoreKeys,Path.GetFileName(sourceKey));
            File.Copy(sourceKey,restoredFile,overwrite:false);
            File.SetUnixFileMode(restoredFile,PrivateFile);
        }
        Assert(LinuxDpRecoveryEvidence.ComputeInventoryDigest(signedRestoreKeys) ==
            inventoryBeforeCommit,
            "fresh isolated restore retains exact signed encrypted inventory");
        LinuxDpRecoveryEvidence.Verify(signedRestoreKeys,generatedManifest,
            trustedPublicPath,LinuxDpRecoveryFloor.ReadExternalFloor(
                signedRestoreKeys,revisionFloorPath));
        Assert(true,"fresh isolated replica accepts independently signed restore");
        Assert(Throws(()=>LinuxDpRecoveryEvidence.Verify(signedRestoreKeys,
                attestationPath,trustedPublicPath,43)),
            "fresh isolated replica rejects older signed restore after floor commit");

        // A separate offline executable now captures only wrapped XML into
        // a new-only atomic archive directory and restores it only after the
        // same independently signed P-256 inventory / external floor check.
        var snapshotCli=Path.GetFullPath(Path.Combine(
            "tools","LinuxDpEncryptedSnapshot","LinuxDpEncryptedSnapshot.csproj"));
        Assert(File.Exists(snapshotCli),"offline encrypted snapshot CLI project exists");
        int RunSnapshot(params string[] options)
        {
            var start=new System.Diagnostics.ProcessStartInfo("dotnet")
            {
                UseShellExecute=false,
                RedirectStandardError=true,
                RedirectStandardOutput=true
            };
            foreach(var arg in new[] {
                "run","--project",snapshotCli,"--configuration","Release","--" })
                start.ArgumentList.Add(arg);
            foreach(var arg in options) start.ArgumentList.Add(arg);
            using var process=System.Diagnostics.Process.Start(start)
                ?? throw new Exception("FAIL: encrypted snapshot CLI failed to start");
            if(!process.WaitForExit(120000))
            {
                process.Kill(entireProcessTree:true);
                throw new Exception("FAIL: encrypted snapshot CLI exceeded timeout");
            }
            var childError=process.StandardError.ReadToEnd();
            if(process.ExitCode!=0)
            {
                // The child's fixed, sanitized stage is the only data
                // permitted into public CI. Never echo raw stderr/paths/XML.
                var stageMatch=System.Text.RegularExpressions.Regex.Match(childError,
                    @"FAIL: offline encrypted DP snapshot/restore refused at (?:Encrypted snapshot stage )?(stage-init|copy-ciphertext|copy-read|copy-validate-xml|copy-write|inventory-recheck|stage-fsync|atomic-publish|root-fsync|published-digest|preflight-or-restore)");
                Console.WriteLine("SNAPSHOT_CLI_FAILURE_STAGE="+
                    (stageMatch.Success?stageMatch.Groups[1].Value:"unclassified"));
            }
            return process.ExitCode;
        }
        var snapshotVault=Path.Combine(root,"encrypted-snapshot-vault");
        Directory.CreateDirectory(snapshotVault,PrivateDir);
        Assert(RunSnapshot("capture","--ring",keyDirectory,
                "--archive-root",snapshotVault,"--label","rev43") == 0 &&
            LinuxDpRecoveryEvidence.ComputeInventoryDigest(
                Path.Combine(snapshotVault,"rev43"))==inventoryBeforeCommit,
            "real CLI creates immutable-by-name encrypted DP snapshot with exact inventory");
        Assert(RunSnapshot("capture","--ring",keyDirectory,
                "--archive-root",snapshotVault,"--label","rev43")!=0,
            "encrypted DP snapshot cannot overwrite an earlier backup");
        var backupRoot=Path.Combine(root,"encrypted-snapshot-restored-state");
        Directory.CreateDirectory(backupRoot,PrivateDir);
        var archivePath=Path.Combine(snapshotVault,"rev43");
        Assert(RunSnapshot("restore","--archive",archivePath,
                "--state-root",backupRoot,
                "--checkpoint",generatedManifest,
                "--trusted-public-key",trustedPublicPath,
                "--minimum-revision-file",revisionFloorPath)==0 &&
            LinuxDpRecoveryEvidence.ComputeInventoryDigest(
                Path.Combine(backupRoot,"data-protection-keys"))==inventoryBeforeCommit,
            "real CLI restores P-256-signed ciphertext into only an absent isolated key ring");

        // End-to-end software acceptance must execute the ACTUAL published
        // signed .NET restore after an actual OpenSSL mutual-TLS transfer,
        // not only separate transport/restore tests or a mock Python process.
        var deliveredState = Path.Combine(root, "pinned-mtls-restored-state");
        var deliveredInbox = Path.Combine(root, "pinned-mtls-receiver-inbox");
        Directory.CreateDirectory(deliveredState, PrivateDir);
        Directory.CreateDirectory(deliveredInbox, PrivateDir);
        var deliveredApphostRoot = Path.GetFullPath(Path.Combine(
            "tools", "LinuxDpEncryptedSnapshot", "bin", "Release", "net10.0"));
        var deliveredApphost = Path.Combine(deliveredApphostRoot, "LinuxDpEncryptedSnapshot");
        Assert(File.Exists(deliveredApphost), "real signed restore apphost exists after CLI build");
        var deliveredHarness = Path.GetFullPath(Path.Combine(
            "..", "ops", "fleet", "linux_dp_real_restore_e2e.py"));
        Assert(File.Exists(deliveredHarness), "real pinned mTLS to .NET restore harness exists");
        // Hosted SDK caches may be group-/other-writable for CI installation.
        // NEVER relax the receiver's production filesystem requirements to
        // accommodate that shared cache. Instead stage only this disposable
        // runner's running .NET host, hostfxr and Microsoft.NETCore.App into
        // a fresh, private 0700 tree, preserving executable bits for native
        // files and forbidding a symlinked destination.
        var executingRuntimeDirectory =
            System.Runtime.InteropServices.RuntimeEnvironment.GetRuntimeDirectory();
        var installedDotnetRoot = Path.GetFullPath(Path.Combine(
            executingRuntimeDirectory, "..", "..", ".."));
        var approvedDotnetRoot = Path.Combine(root, "owner-private-net10-host");
        Directory.CreateDirectory(approvedDotnetRoot, PrivateDir);
        void PrivateRuntimeCopy(string input, string output)
        {
            Directory.CreateDirectory(output, PrivateDir);
            foreach (var sourceFile in Directory.EnumerateFiles(input))
            {
                var destination = Path.Combine(output, Path.GetFileName(sourceFile));
                File.Copy(sourceFile, destination, overwrite: false);
                var mode = File.GetUnixFileMode(sourceFile);
                var executable = (mode & (UnixFileMode.UserExecute |
                    UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) != 0;
                File.SetUnixFileMode(destination, PrivateFile |
                    (executable ? UnixFileMode.UserExecute : 0));
            }
            foreach (var sourceDir in Directory.EnumerateDirectories(input))
                PrivateRuntimeCopy(sourceDir, Path.Combine(
                    output, Path.GetFileName(sourceDir)));
        }
        var sourceHost = Path.Combine(installedDotnetRoot, "dotnet");
        Assert(File.Exists(sourceHost), "current .NET 10 runtime host exists");
        var destinationHost = Path.Combine(approvedDotnetRoot, "dotnet");
        File.Copy(sourceHost, destinationHost);
        File.SetUnixFileMode(destinationHost,
            PrivateFile | UnixFileMode.UserExecute);
        var runtimeVersion = Path.GetFileName(Path.TrimEndingDirectorySeparator(
            executingRuntimeDirectory));
        var privateShared = Path.Combine(approvedDotnetRoot, "shared",
            "Microsoft.NETCore.App", runtimeVersion);
        PrivateRuntimeCopy(executingRuntimeDirectory, privateShared);
        var sourceFxrRoot = Path.Combine(installedDotnetRoot, "host", "fxr");
        var fxrVersions = Directory.GetDirectories(sourceFxrRoot)
            .Where(name => Version.TryParse(Path.GetFileName(name), out var v)
                && v.Major == Environment.Version.Major)
            .OrderByDescending(name => Version.Parse(Path.GetFileName(name)))
            .ToArray();
        Assert(fxrVersions.Length > 0,
            "installed .NET 10 hostfxr is available for private recovery fixture");
        PrivateRuntimeCopy(fxrVersions[0], Path.Combine(approvedDotnetRoot,
            "host", "fxr", Path.GetFileName(fxrVersions[0])));
        Assert(File.Exists(destinationHost) &&
            File.GetUnixFileMode(approvedDotnetRoot) == PrivateDir,
            "disposable recovery runtime staged under private owner-only root");
        var transfer = new System.Diagnostics.ProcessStartInfo("python3")
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        foreach (var (flag, value) in new[] {
            ("--source-root", snapshotVault),
            ("--label", "rev43"),
            ("--checkpoint", generatedManifest),
            ("--trusted-public-key", trustedPublicPath),
            ("--minimum-revision-file", revisionFloorPath),
            ("--state-root", deliveredState),
            ("--inbox", deliveredInbox),
            ("--restore-bundle", deliveredApphostRoot),
            ("--dotnet-runtime-root", approvedDotnetRoot)
        })
        {
            transfer.ArgumentList.Add(flag);
            transfer.ArgumentList.Add(value);
        }
        transfer.ArgumentList.Insert(0, deliveredHarness);
        using (var realTransfer = System.Diagnostics.Process.Start(transfer)
            ?? throw new Exception("FAIL: actual pinned mutual-TLS receiver did not start"))
        {
            if (!realTransfer.WaitForExit(180000))
            {
                realTransfer.Kill(entireProcessTree: true);
                throw new Exception("FAIL: real encrypted DP network-to-restore test timeout");
            }
            // Only print an allowlisted, source-owned diagnostic stage, never
            // exception messages, trust paths, TLS keys, XML, cookies or
            // unbounded subprocess stderr/stdout from the recovery harness.
            var privateDiagnostic = realTransfer.StandardError.ReadToEnd();
            if (realTransfer.ExitCode != 0)
            {
                var stage = System.Text.RegularExpressions.Regex.Match(
                    privateDiagnostic,
                    @"FAIL: real pinned mTLS to \.NET signed DP restore at (startup|linux-check|private-xml-archive|disposable-openssl-identities|independent-p256-node-cryptographic-fixtures|pinned-mtls-server-start|trusted-dotnet-bundle-inspection|mutual-tls-receive-and-signed-dotnet-restore|restored-archive-identity|reject-duplicate|receiver-(?:platform-and-operator-approval|private-recovery-directories|independent-trust-custody|independent-two-node-writer-quiescence|pinned-complete-dotnet-bundle|pinned-mtls-fetch|atomic-received-archive|independent-checkpoint-staging|approved-dotnet-runtime|signed-dotnet-restore-subprocess|post-execution-bundle-integrity|restored-private-ring-integrity|post-restore-quorum|signed-dotnet-exit-(?:1|131|134|150|other)))");
                Console.WriteLine("PINNED_DP_TRANSFER_FAILURE_STAGE=" +
                    (stage.Success ? stage.Groups[1].Value : "unclassified"));
            }
            Assert(realTransfer.ExitCode == 0,
                "real pinned TLS transfer plus signed .NET 10 offline restore accepted");
        }
        Assert(LinuxDpRecoveryEvidence.ComputeInventoryDigest(
            Path.Combine(deliveredState,"data-protection-keys")) == inventoryBeforeCommit,
            "pinned mTLS receiver preserved actual P-256-verified ciphertext inventory");
        // Temporarily bind the fresh receiver process to the actual signed
        // manifest and committed floor. Restore exact previous environment
        // values before the existing negative/failure tests resume.
        var previousRecoveryValues = new[] {
            LinuxDpRecoveryEvidence.ManifestEnv, LinuxDpRecoveryEvidence.PublicKeyEnv,
            LinuxDpRecoveryEvidence.MinimumRevisionEnv,
            LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,
            LinuxDpRecoveryEvidence.RequireEvidenceEnv
        }.ToDictionary(key => key, key => Environment.GetEnvironmentVariable(key));
        try
        {
            Set(LinuxDpRecoveryEvidence.ManifestEnv, generatedManifest);
            Set(LinuxDpRecoveryEvidence.PublicKeyEnv, trustedPublicPath);
            Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv, null);
            Set(LinuxDpRecoveryEvidence.MinimumRevisionFileEnv, revisionFloorPath);
            Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv, "true");
            Assert(VerifyInFreshProcess(deliveredState, "OnPremLinuxDpIntegration.v1",
                    "session-probe", encrypted, "sensitive-session-value-123") == 0,
                "real pinned mTLS recovery preserves original authenticated cookie in fresh OS process");
        }
        finally
        {
            foreach (var item in previousRecoveryValues)
                Set(item.Key, item.Value);
        }
        Assert(!File.Exists(Path.Combine(deliveredInbox, "rev43", "ring", "private.key")),
            "network DP snapshot contains no private wrapping-key file");

        Assert(RunSnapshot("restore","--archive",archivePath,
                "--state-root",backupRoot,
                "--checkpoint",generatedManifest,
                "--trusted-public-key",trustedPublicPath,
                "--minimum-revision-file",revisionFloorPath)!=0 &&
            LinuxDpRecoveryEvidence.ComputeInventoryDigest(
                Path.Combine(backupRoot,"data-protection-keys"))==inventoryBeforeCommit,
            "restoring over existing encrypted key ring is denied without mutation");
        var tamperedArchiveXml=Directory.GetFiles(archivePath,"key-*.xml").Single();
        var originalArchivedXml=File.ReadAllBytes(tamperedArchiveXml);
        var alteredTargetRoot=Path.Combine(root,"tampered-backup-target");
        Directory.CreateDirectory(alteredTargetRoot,PrivateDir);
        try
        {
            File.AppendAllText(tamperedArchiveXml,"<!-- altered archive -->");
            File.SetUnixFileMode(tamperedArchiveXml,PrivateFile);
            Assert(RunSnapshot("restore","--archive",archivePath,
                    "--state-root",alteredTargetRoot,
                    "--checkpoint",generatedManifest,
                    "--trusted-public-key",trustedPublicPath,
                    "--minimum-revision-file",revisionFloorPath)!=0 &&
                !Path.Exists(Path.Combine(alteredTargetRoot,"data-protection-keys")),
                "tampered signed ciphertext archive fails before destination is installed");
        }
        finally
        {
            File.WriteAllBytes(tamperedArchiveXml,originalArchivedXml);
            File.SetUnixFileMode(tamperedArchiveXml,PrivateFile);
        }
        var plaintextStateRoot=Path.Combine(root,"disposable-plaintext-state");
        var plaintextRing=Path.Combine(plaintextStateRoot,"data-protection-keys");
        Directory.CreateDirectory(plaintextRing,PrivateDir);
        var plaintextFile=Path.Combine(plaintextRing,"key-unwrapped.xml");
        File.WriteAllText(plaintextFile,
            "<key><masterKey>DISPOSABLE-PLAINTEXT-FIXTURE-ONLY</masterKey></key>");
        File.SetUnixFileMode(plaintextFile,PrivateFile);
        Assert(RunSnapshot("capture","--ring",plaintextRing,
                "--archive-root",snapshotVault,"--label","plaintext")!=0 &&
            !Directory.Exists(Path.Combine(snapshotVault,"plaintext")),
            "backup utility rejects and does not archive plaintext key XML");
        Assert(LinuxDpRecoveryEvidence.ComputeInventoryDigest(keyDirectory)==inventoryBeforeCommit,
            "offline backup/restore never mutates the original wrapped key ring");

        // Fleet nodes opt into the independent revision FLOOR FILE at startup,
        // instead of copying a stale environment integer from a restored
        // backup. The legacy integer contract must still work by default.
        Set(LinuxDpRecoveryEvidence.ManifestEnv,generatedManifest);
        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,trustedPublicPath);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv,null);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,revisionFloorPath);
        Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv,"true");
        using(var restored=Provider(state))
            Assert(restored.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted)=="sensitive-session-value-123",
                "service restart honors externally committed floor and old encrypted cookie");
        Set("YARP_CONTROL_PLANE_DIR",signedRestoreState);
        using(var replicaRestored=Provider(signedRestoreState))
            Assert(replicaRestored.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted)=="sensitive-session-value-123",
                "independent replica restart preserves original session after signed restore");
        Set("YARP_CONTROL_PLANE_DIR",backupRoot);
        using(var snapshotRestored=Provider(backupRoot))
            Assert(snapshotRestored.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted)=="sensitive-session-value-123",
                "offline signed archive restore preserves original cookie across isolated service restart");
        Set("YARP_CONTROL_PLANE_DIR",state);
        Set(LinuxDpRecoveryEvidence.ManifestEnv,attestationPath);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "older correctly signed restored snapshot fails against durable external floor");
        Set(LinuxDpRecoveryEvidence.ManifestEnv,generatedManifest);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv,"42");
        Assert(Throws(()=>{using var _=Provider(state);}),
            "mixing stale environment minimum with independent file is rejected");
        Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv,null);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionFileEnv,null);
        Set(LinuxDpRecoveryEvidence.ManifestEnv,attestationPath);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv,"42");
        Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv,"true");

        // A restored backup must never be trusted to supply its own signing
        // identity or checkpoint, even if the signature itself is valid.
        // These files have safe 0600 modes but are inside restored state.
        var untrustedManifest=Path.Combine(state,"recovery-attestation.json");
        File.Copy(attestationPath,untrustedManifest);
        File.SetUnixFileMode(untrustedManifest,PrivateFile);
        Set(LinuxDpRecoveryEvidence.ManifestEnv,untrustedManifest);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "signed recovery checkpoint inside restored state fails closed");
        Set(LinuxDpRecoveryEvidence.ManifestEnv,attestationPath);

        // A syntactically external path may point back into the restored
        // snapshot through an intermediate Linux directory symlink. Verify
        // that the physical containment check catches this path *before*
        // any trusted input is read.
        var linkedStateParent=Path.Combine(secrets,"aliased-restored-state");
        Directory.CreateSymbolicLink(linkedStateParent,state);
        Set(LinuxDpRecoveryEvidence.ManifestEnv,
            Path.Combine(linkedStateParent,"recovery-attestation.json"));
        Assert(Throws(()=>LinuxDpRecoveryEvidence.Verify(
                   Path.Combine(state,"data-protection-keys"),
                   Path.Combine(linkedStateParent,"recovery-attestation.json"),
                   trustedPublicPath,42)),
            "linked parent outside state cannot supply the recovered manifest");
        Set(LinuxDpRecoveryEvidence.ManifestEnv,attestationPath);
        Directory.Delete(linkedStateParent);
        File.Delete(untrustedManifest);

        var untrustedVerifier=Path.Combine(state,"recovery-verifier.pem");
        File.Copy(trustedPublicPath,untrustedVerifier);
        File.SetUnixFileMode(untrustedVerifier,PrivateFile);
        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,untrustedVerifier);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "recovery trust anchor inside restored state fails closed");
        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,trustedPublicPath);
        var linkedVerifier=Path.Combine(secrets,"linked-recovery-verifier.pem");
        File.CreateSymbolicLink(linkedVerifier,untrustedVerifier);
        Assert(Throws(()=>LinuxDpRecoveryEvidence.Verify(
                   Path.Combine(state,"data-protection-keys"),
                   attestationPath,linkedVerifier,42)),
            "external verifier symlink into restored state is rejected");
        File.Delete(linkedVerifier);
        File.Delete(untrustedVerifier);

        // Even if the key directory is presented under a symlinked state
        // alias, the physical state root must be recognized as restored data.
        var linkedStateRoot=Path.Combine(secrets,"alternate-state-root");
        Directory.CreateSymbolicLink(linkedStateRoot,state);
        var aliasManifest=Path.Combine(state,"alias-manifest.json");
        File.Copy(attestationPath,aliasManifest);
        File.SetUnixFileMode(aliasManifest,PrivateFile);
        Assert(Throws(()=>LinuxDpRecoveryEvidence.Verify(
                   Path.Combine(linkedStateRoot,"data-protection-keys"),
                   aliasManifest,trustedPublicPath,42)),
            "linked state-root alias cannot bypass restored authority boundary");
        File.Delete(aliasManifest);
        Directory.Delete(linkedStateRoot);

        // The independent trust anchor cannot be the *same inode* as a
        // file inside a restored snapshot. Hard links evade realpath and
        // parent-directory symlink checks: reject both possible aliases.
        var hardlinkedManifest=Path.Combine(state,"checkpoint-hardlink.json");
        MakeHardLink(attestationPath,hardlinkedManifest);
        try
        {
            Assert(Throws(()=>{using var _=Provider(state);}),
                "external recovery checkpoint hardlinked into restored state fails closed");
        }
        finally { File.Delete(hardlinkedManifest); }

        var hardlinkedVerifier=Path.Combine(state,"verifier-hardlink.pem");
        MakeHardLink(trustedPublicPath,hardlinkedVerifier);
        try
        {
            Assert(Throws(()=>{using var _=Provider(state);}),
                "external recovery trust key hardlinked into restored state fails closed");
        }
        finally { File.Delete(hardlinkedVerifier); }

        using(var service=Provider(state))
            Assert(service.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted)=="sensitive-session-value-123",
                "externally signed exact inventory accepts original encrypted session after restore");

        WriteAttestation(attestation with { InventorySha256 = new string('A',64) });
        Assert(Throws(()=>{using var _=Provider(state);}),
            "signed inventory digest substitution rejected");
        WriteAttestation(MakeAttestation(41,inventoryHash));
        Assert(Throws(()=>{using var _=Provider(state);}),
            "correctly signed older checkpoint rejected against external revision floor");
        WriteAttestation(attestation);
        File.WriteAllText(attestationPath,
            System.Text.Json.JsonSerializer.Serialize(attestation)
                .Replace("\"Revision\":42,", "\"Revision\":42,\"revision\":49,"));
        File.SetUnixFileMode(attestationPath,PrivateFile);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "duplicated and case-aliased recovery manifest fields rejected");
        WriteAttestation(attestation);

        var wrappedKeyFile=keyFiles[0];
        var originalWrappedBytes=File.ReadAllBytes(wrappedKeyFile);
        try
        {
            File.AppendAllText(wrappedKeyFile,"<!-- valid XML comment invalidates exact signed snapshot -->");
            File.SetUnixFileMode(wrappedKeyFile,PrivateFile);
            Assert(Throws(()=>{using var _=Provider(state);}),
                "stale signed inventory refused even if restored XML remains valid and wrapped");
        }
        finally
        {
            File.WriteAllBytes(wrappedKeyFile,originalWrappedBytes);
            File.SetUnixFileMode(wrappedKeyFile,PrivateFile);
        }
        using(var service=Provider(state))
            Assert(service.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted)=="sensitive-session-value-123",
                "exact original signed ring remains recoverable after rejected tamper");

        using(var wrongSigner=ECDsa.Create(ECCurve.NamedCurves.nistP256))
        {
            File.WriteAllText(trustedPublicPath,wrongSigner.ExportSubjectPublicKeyInfoPem());
            Assert(Throws(()=>{using var _=Provider(state);}),
                "untrusted recovery verification signing identity rejected");
        }
        File.WriteAllText(trustedPublicPath,attestationSigner.ExportSubjectPublicKeyInfoPem());
        File.SetUnixFileMode(trustedPublicPath,PrivateFile);

        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,null);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "incomplete recovery attestation configuration fails closed");
        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,trustedPublicPath);
        Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv,"TRUE");
        Assert(Throws(()=>{using var _=Provider(state);}),
            "unrecognized recovery requirement spelling fails closed");
        Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv,"true");
        Set(LinuxDpRecoveryEvidence.ManifestEnv,null);
        Set(LinuxDpRecoveryEvidence.PublicKeyEnv,null);
        Set(LinuxDpRecoveryEvidence.MinimumRevisionEnv,null);
        Assert(Throws(()=>{using var _=Provider(state);}),
            "mandatory signed Linux recovery cannot silently start without external attestation");
        // Backward-compatible standalone mode remains optional, without
        // turning a required signed-fleet restore into an accepted fallback.
        Set(LinuxDpRecoveryEvidence.RequireEvidenceEnv,null);
        using(var service=Provider(state))
            Assert(service.GetRequiredService<IDataProtectionProvider>()
                .CreateProtector("session-probe").Unprotect(encrypted) ==
                "sensitive-session-value-123",
                "standalone Linux DP mode still reads its approved encrypted ring");
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
    // A separately named hard link can alias the exact same encrypted key
    // inode outside the private ring. Refuse both normal DP startup and
    // signed recovery inventory hashing while the alias exists, even though
    // the XML bytes remain encrypted and file modes are still owner-only.
    var externalKeyAlias=Path.Combine(secrets,"outside-keyring-alias.xml");
    MakeHardLink(protectedFile,externalKeyAlias);
    try
    {
        Assert(Throws(()=>{using var _=Provider(state);}),
            "hardlinked persisted DP key XML fails closed before framework import");
        Assert(Throws(()=>LinuxDpRecoveryEvidence.ComputeInventoryDigest(
            Path.Combine(state,"data-protection-keys"))),
            "signed recovery digest refuses multiply-linked encrypted key XML");
    }
    finally { File.Delete(externalKeyAlias); }
    using(var recovered=Provider(state))
        Assert(recovered.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("session-probe").Unprotect(encrypted) ==
            "sensitive-session-value-123",
            "removing external key-ring hardlink restores original cookie continuity");
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
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",null);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",null);
    var previousRing = Directory.GetFiles(
        Path.Combine(rotationState, "data-protection-keys"), "key-*.xml");
    var beforeDenied = previousRing.ToDictionary(p=>p,p=>SHA256.HashData(File.ReadAllBytes(p)));
    Assert(Throws(()=>{using var _=Provider(rotationState);}),
        "new certificate alone must not start while historic XML still needs old private key");
    Assert(previousRing.All(p=>SHA256.HashData(File.ReadAllBytes(p))
            .SequenceEqual(beforeDenied[p])),
        "blocked unsafe cert retirement never changes the encrypted key ring");
    Set("YARP_LINUX_DP_OLD_CERT_PFX_PATH",first.Pfx);
    Set("YARP_LINUX_DP_OLD_CERT_PASSWORD_FILE",first.PasswordFile);
    Assert(Throws(()=>{using var _=Provider(rotationState);}),
        "different but accessible previous wrapping certificate cannot masquerade as old recipient");
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
