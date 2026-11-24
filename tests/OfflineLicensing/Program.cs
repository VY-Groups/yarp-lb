using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using GatewayCore.Licensing;

// Test-only ephemeral signing keys; no issuer or reusable private key ships.
using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var installation = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var binding = Convert.ToHexString(SHA256.HashData(installation.ExportSubjectPublicKeyInfo()));
var now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
var keys = new Dictionary<string, byte[]> { ["test-1"] = signer.ExportSubjectPublicKeyInfo() };
var verifier = new OfflineLicenseVerifier(keys);
if(args.Length==5 && args[0]=="--ci-verify-fleet-proofs")
{
    if(Environment.GetEnvironmentVariable("CI")!="true" || Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")
        throw new InvalidOperationException("Disposable fleet test only.");
    var fleetTrust=JsonSerializer.Deserialize<Dictionary<string,byte[]>>(File.ReadAllBytes(args[1]))!;
    var proofVerifier=new OfflineLicenseVerifier(fleetTrust);
    var fleetUtc=DateTimeOffset.UtcNow;
    var localProof=proofVerifier.VerifyInstallationProof(File.ReadAllBytes(args[3]),args[2],fleetUtc);
    var remoteProof=proofVerifier.VerifyInstallationProof(File.ReadAllBytes(args[4]),args[2],fleetUtc);
    FleetLicensePolicy.Validate(localProof,new[]{localProof,remoteProof},fleetUtc);
    Console.WriteLine("REAL_MTLS_FLEET_PROOFS_VERIFIED");
    return;
}
if (args.Length >= 2 && args[0] is "--ci-engine-key" or "--ci-engine-license" or "--ci-engine-revoke" or "--ci-fleet-license")
{
    if(Environment.GetEnvironmentVariable("CI")!="true" || Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true")
        throw new InvalidOperationException("Disposable engine test only.");
    var rootPath=Path.GetFullPath(args[1]);
    var privatePath=Path.Combine(rootPath,"fixture-engine.pk8");
    if(args is ["--ci-engine-key",_])
    {
        Directory.CreateDirectory(rootPath);
        var rawKey=signer.ExportPkcs8PrivateKey();
        try
        {
            var opts=new FileStreamOptions{Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None};
            if(OperatingSystem.IsLinux())opts.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
            using var outputKey=new FileStream(privatePath,opts);
            outputKey.Write(rawKey);
        }
        finally{CryptographicOperations.ZeroMemory(rawKey);}
        File.WriteAllBytes(Path.Combine(rootPath,"trust.json"),JsonSerializer.SerializeToUtf8Bytes(keys));
        return;
    }
    if(args.Length!=5)throw new ArgumentException("Engine fixture arguments.");
    var rawFixtureKey=File.ReadAllBytes(privatePath);
    try{signer.ImportPkcs8PrivateKey(rawFixtureKey,out _);}
    finally{CryptographicOperations.ZeroMemory(rawFixtureKey);}
    var engineBinding=OfflineActivationRequest.Verify(File.ReadAllBytes(args[2])).InstallationKeySha256;
    var engineNow=DateTimeOffset.UtcNow;
    var engineBytes=args[0]=="--ci-fleet-license"?FixtureSign("GCL1",new{
        schemaVersion=2,product="GatewayCore",licenseId="engine-ci",customerId="ci",deploymentId="ci",
        allocationId="node-"+engineBinding[..32],installationKeySha256=engineBinding,edition="enterprise",revision=1,
        siteId=args[4],maxNodes=2,maxSites=2,issuedAt=engineNow.ToUnixTimeSeconds(),notBefore=engineNow.ToUnixTimeSeconds(),
        expiresAt=new DateTimeOffset(engineNow.UtcDateTime.Date.AddDays(2),TimeSpan.Zero).ToUnixTimeSeconds(),
        features=new[]{"l7","ha","fleet","dc-dr"}},signer):
        args[0]=="--ci-engine-license"?FixtureSign("GCL1",new{
        schemaVersion=1,product="GatewayCore",licenseId="engine-ci",customerId="ci",deploymentId="ci",
        allocationId="engine-node",installationKeySha256=engineBinding,edition="standard",revision=1,
        maxNodes=1,maxSites=1,issuedAt=engineNow.ToUnixTimeSeconds(),notBefore=engineNow.ToUnixTimeSeconds(),
        expiresAt=engineNow.AddDays(1).ToUnixTimeSeconds(),features=new[]{args[4]}},signer):
        FixtureSign("GCV1",new{schemaVersion=1,product="GatewayCore",licenseId="engine-ci",customerId="ci",
        deploymentId="ci",allocationId=args[4]=="fleet"?"node-"+engineBinding[..32]:"engine-node",installationKeySha256=engineBinding,
        revokedAt=engineNow.ToUnixTimeSeconds()},signer);
    using var engineOutput=new FileStream(args[3],FileMode.CreateNew);
    engineOutput.Write(engineBytes);
    return;
}
if (args.Length >= 2 && args[0] is "--ci-release-key" or "--ci-release-manifest")
{
    if (Environment.GetEnvironmentVariable("CI") != "true" ||
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true")
        throw new InvalidOperationException("Disposable release fixture only.");
    var releaseRoot = Path.GetFullPath(args[1]);
    var fixtureKeyPath = Path.Combine(releaseRoot, "release-fixture.pk8");
    if (args[0] == "--ci-release-key" && args.Length == 2)
    {
        Directory.CreateDirectory(releaseRoot);
        var fixtureKeyBytes = signer.ExportPkcs8PrivateKey();
        try
        {
            var fixtureOptions = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
            if (OperatingSystem.IsLinux()) fixtureOptions.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
            using var fixtureKeyFile = new FileStream(fixtureKeyPath, fixtureOptions);
            fixtureKeyFile.Write(fixtureKeyBytes);
        }
        finally { CryptographicOperations.ZeroMemory(fixtureKeyBytes); }
        File.WriteAllBytes(Path.Combine(releaseRoot, "release-trust.json"), JsonSerializer.SerializeToUtf8Bytes(
            new Dictionary<string,byte[]> { ["release-ci"] = signer.ExportSubjectPublicKeyInfo() }));
        return;
    }
    if (args[0] != "--ci-release-manifest" || args.Length != 4) throw new ArgumentException("Invalid release fixture arguments.");
    var fixturePackage = Path.GetFullPath(args[2]);
    var fixturePrivateKey = File.ReadAllBytes(fixtureKeyPath);
    try { signer.ImportPkcs8PrivateKey(fixturePrivateKey, out _); }
    finally { CryptographicOperations.ZeroMemory(fixturePrivateKey); }
    var fixtureFiles = Directory.EnumerateFiles(fixturePackage, "*", SearchOption.AllDirectories)
        .Order(StringComparer.Ordinal).Select(path =>
        {
            using var input = File.OpenRead(path);
            return new { path = Path.GetRelativePath(fixturePackage,path).Replace(Path.DirectorySeparatorChar,'/'),
                size = input.Length, sha256 = Convert.ToHexString(SHA256.HashData(input)) };
        }).ToArray();
    var fixturePayload = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, product = "GatewayCore",
        sourceCommit = args[3], files = fixtureFiles });
    var fixturePrefix = "GCM1.release-ci." + B64(fixturePayload);
    var fixtureManifest = fixturePrefix + "." + B64(signer.SignData(Encoding.ASCII.GetBytes(fixturePrefix),
        HashAlgorithmName.SHA256,DSASignatureFormat.IeeeP1363FixedFieldConcatenation));
    using var manifestFile = new FileStream(Path.Combine(fixturePackage,ReleaseIntegrityVerifier.ManifestName),FileMode.CreateNew);
    manifestFile.Write(Encoding.ASCII.GetBytes(fixtureManifest));
    return;
}
if (args.Length == 2 && args[0] == "--ci-trust")
{
    // Disposable public-only trust resource for commercial compile CI.
    File.WriteAllBytes(args[1], JsonSerializer.SerializeToUtf8Bytes(keys));
    return;
}
if (args.Length >= 2 && args[0] is "--ci-authority" or "--ci-issue" or "--ci-revoke" or "--ci-downgrade" or "--ci-upgrade" or "--ci-short-renew" or "--ci-resume")
{
    if (Environment.GetEnvironmentVariable("CI") != "true" ||
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" || !OperatingSystem.IsLinux())
        throw new InvalidOperationException("Disposable Linux CI fixture only.");
    var root = Path.GetFullPath(args[1]);
    var keyPath = Path.Combine(root, "disposable-ci-issuer.pk8");
    // Fixed synthetic one-node scenario. Not a production issuer, no customer
    // terms, allocations, approvals, durable issuance ledger or real keys.
    var bindingPath = Path.Combine(root, "fixture-binding.txt");
    var stepPath = Path.Combine(root, "fixture-step.txt");
    if (args[0] == "--ci-authority" && args.Length == 2)
    {
        Directory.CreateDirectory(root, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        var raw = signer.ExportPkcs8PrivateKey();
        try
        {
            using var keyFile = new FileStream(keyPath, new FileStreamOptions
            {
                Mode = FileMode.CreateNew, Access = FileAccess.Write,
                UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
            });
            keyFile.Write(raw);
            keyFile.Flush(true);
        }
        finally { CryptographicOperations.ZeroMemory(raw); }
        File.WriteAllBytes(Path.Combine(root, "public-trust.json"), JsonSerializer.SerializeToUtf8Bytes(keys));
        File.WriteAllText(stepPath, "0");
        return;
    }
    if (args.Length != 4) throw new ArgumentException("Invalid CI fixture arguments.");
    var privateKey = File.ReadAllBytes(keyPath);
    try { signer.ImportPkcs8PrivateKey(privateKey, out _); }
    finally { CryptographicOperations.ZeroMemory(privateKey); }
    var step = int.Parse(File.ReadAllText(stepPath), System.Globalization.CultureInfo.InvariantCulture);
    var utc = DateTimeOffset.UtcNow;
    const string fixtureAllocation = "ci-node";
    byte[] fixtureEnvelope;
    if (args[0] == "--ci-revoke")
    {
        if (step != 6 || args[2] != fixtureAllocation) throw new InvalidOperationException("Unexpected fixture step.");
        fixtureEnvelope = FixtureSign("GCV1", new
        {
            schemaVersion = 1, product = "GatewayCore", licenseId = "ci-license",
            customerId = "ci-customer", deploymentId = "ci-deployment", allocationId = fixtureAllocation,
            installationKeySha256 = File.ReadAllText(bindingPath), revokedAt = utc.ToUnixTimeSeconds()
        }, signer);
    }
    else
    {
        var expected = step switch { 0 or 1 => "--ci-issue", 2 => "--ci-downgrade", 3 => "--ci-upgrade",
            4 => "--ci-short-renew", 5 => "--ci-resume", _ => "" };
        if (args[0] != expected) throw new InvalidOperationException("Unexpected fixture step.");
        var fixtureRequest = OfflineActivationRequest.Verify(File.ReadAllBytes(args[2]));
        if (step == 0) File.WriteAllText(bindingPath, fixtureRequest.InstallationKeySha256);
        else if (File.ReadAllText(bindingPath) != fixtureRequest.InstallationKeySha256)
            throw new CryptographicException("Fixture installation changed.");
        fixtureEnvelope = FixtureSign("GCL1", new
        {
            schemaVersion = 1, product = "GatewayCore", licenseId = "ci-license",
            customerId = "ci-customer", deploymentId = "ci-deployment", allocationId = fixtureAllocation,
            installationKeySha256 = fixtureRequest.InstallationKeySha256, edition = "standard",
            revision = step + 1, maxNodes = step >= 3 ? 2 : 1, maxSites = 1, issuedAt = utc.ToUnixTimeSeconds(),
            notBefore = utc.ToUnixTimeSeconds(), expiresAt = (step == 4 ? utc.AddSeconds(20) : utc.AddDays(2)).ToUnixTimeSeconds(),
            features = step switch
            {
                2 => new[] { "monitoring" },
                >= 3 => new[] { "l7", "tls", "monitoring", "ha", "fleet" },
                _ => new[] { "l7", "tls", "monitoring" }
            }
        }, signer);
    }
    using var output = new FileStream(args[3], FileMode.CreateNew, FileAccess.Write, FileShare.None);
    output.Write(fixtureEnvelope);
    output.Flush(true);
    File.WriteAllText(stepPath, (step + 1).ToString(System.Globalization.CultureInfo.InvariantCulture));
    return;
}
var model = new JsonObject
{
    ["schemaVersion"] = 1, ["product"] = "GatewayCore", ["licenseId"] = "test-license",
    ["customerId"] = "test-customer", ["deploymentId"] = "test-deployment",
    ["allocationId"] = "test-node", ["installationKeySha256"] = binding,
    ["edition"] = "professional", ["revision"] = 2, ["maxNodes"] = 2,
    ["maxSites"] = 1, ["issuedAt"] = now.AddDays(-1).ToUnixTimeSeconds(),
    ["notBefore"] = now.AddHours(-1).ToUnixTimeSeconds(),
    ["expiresAt"] = now.AddDays(30).ToUnixTimeSeconds(),
    ["features"] = new JsonArray("l7", "ha")
};
string B64(byte[] bytes) => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+','-').Replace('/','_');
byte[] Sign(string json, ECDsa? key = null, string kid = "test-1")
{
    var prefix = "GCL1." + kid + "." + B64(Encoding.UTF8.GetBytes(json));
    return Encoding.ASCII.GetBytes(prefix + "." + B64((key ?? signer).SignData(
        Encoding.ASCII.GetBytes(prefix), HashAlgorithmName.SHA256,
        DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
}
string Changed(string field, JsonNode? value)
{
    var next = (JsonObject)model.DeepClone();
    next[field] = value;
    return next.ToJsonString();
}
void Check(bool condition, string name)
{
    if (!condition) throw new Exception("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
}
void Reject(Action action, string name)
{
    try { action(); }
    catch (Exception e) when (e is CryptographicException or InvalidDataException or JsonException or FormatException or ArgumentException)
    { Console.WriteLine("PASS: rejects " + name); return; }
    throw new Exception("FAIL: accepted " + name);
}
var file = Sign(model.ToJsonString());
var valid = verifier.Verify(file, binding, now);
Check(valid.Allows("l7") && valid.Allows("ha") && !valid.Allows("waf") && valid.MaxNodes == 2, "signed feature and node entitlements");
Check(verifier.Verify(file, binding, now, valid.Checkpoint).Allows("ha"), "idempotent import");
Check(verifier.Verify(Sign(Changed("revision", 3)), binding, now, valid.Checkpoint).Revision == 3, "signed renewal revision");
Check(!verifier.Verify(file, binding, now.AddDays(31)).Allows("l7"), "expired license has no active entitlement");
var future = verifier.Verify(Sign(Changed("notBefore", now.AddDays(1).ToUnixTimeSeconds())), binding, now);
Check(future.Validity == LicenseValidity.NotYetValid && !future.Allows("l7"), "future license has no active entitlement");
var segments = Encoding.ASCII.GetString(file).Split('.');
segments[2] = B64(Encoding.UTF8.GetBytes(Changed("maxNodes", 1000)));
Reject(() => verifier.Verify(Encoding.ASCII.GetBytes(string.Join(".", segments)), binding, now), "edited allocation with original signature");
Reject(() => verifier.Verify(Sign(model.ToJsonString(), other), binding, now), "forged signature");
Reject(() => verifier.Verify(Sign(model.ToJsonString(), signer, "unknown"), binding, now), "unknown signing key");
Reject(() => verifier.Verify(file, new string('A', 64), now), "different installation");
Reject(() => verifier.Verify(Sign(Changed("revision", 1)), binding, now, valid.Checkpoint), "older signed revision");
Reject(() => verifier.Verify(Sign(Changed("maxNodes", 3)), binding, now, valid.Checkpoint), "same revision with different payload");
Reject(() => verifier.Verify(Sign(Changed("allocationId", "another-node")), binding, now, valid.Checkpoint), "unauthorized allocation replacement");
Reject(() => verifier.Verify(Sign(model.ToJsonString()[..^1] + ",\"edition\":\"enterprise\"}"), binding, now), "duplicate property");
Reject(() => verifier.Verify(Sign(Changed("unrecognized", true)), binding, now), "unknown property");
Reject(() => verifier.Verify(Sign(Changed("features", new JsonArray("ha", "ha"))), binding, now), "duplicate feature");
Reject(() => verifier.Verify(Sign(Changed("features", new JsonArray("unlimited"))), binding, now), "unknown feature");
Reject(() => verifier.Verify(Sign(Changed("maxNodes", 0)), binding, now), "invalid node limit");
Reject(() => verifier.Verify(Sign(Changed("expiresAt", now.AddDays(-3).ToUnixTimeSeconds())), binding, now), "reversed dates");
Reject(() => verifier.Verify(Sign(Changed("issuedAt", now.AddDays(1).ToUnixTimeSeconds())), binding, now), "future issuance");
Reject(() => verifier.Verify(new byte[OfflineLicenseVerifier.MaxLicenseBytes + 1], binding, now), "oversized file");
Reject(() => verifier.Verify(file.Concat(new byte[]{10}).ToArray(), binding, now), "trailing newline");
Reject(() => new OfflineLicenseVerifier(new Dictionary<string, byte[]>()), "missing trust root");
using var wrongCurve = ECDsa.Create(ECCurve.NamedCurves.nistP384);
Reject(() => new OfflineLicenseVerifier(new Dictionary<string, byte[]> { ["wrong"] = wrongCurve.ExportSubjectPublicKeyInfo() }), "wrong curve");
keys["test-1"][0] ^= 255;
Check(verifier.Verify(file, binding, now).Allows("l7"), "trust keys defensively copied");
Reject(() => verifier.Verify(Sign(Changed("customerId", "other-customer")), binding, now, valid.Checkpoint), "customer replacement");
Reject(() => verifier.Verify(Sign(Changed("deploymentId", "other-deployment")), binding, now, valid.Checkpoint), "deployment replacement");

FleetProofAcceptance.Run();
var directory = Path.Combine(Path.GetTempPath(), "gc-license-" + Guid.NewGuid().ToString("N"));
var directory2 = directory + "-second";
try
{
    var store = new OfflineLicenseStore(directory, verifier);
    store.Initialize();
    Check(store.Inspect(now) is null, "explicitly provisioned unlicensed state");
    var request = store.ExportActivationRequest();
    var parsed = OfflineActivationRequest.Verify(request);
    Check(OfflineActivationRequest.Verify(store.ExportActivationRequest()).RequestId != parsed.RequestId,
        "unique request ID and proof of possession");
    var modified = request.ToArray();
    modified[^2] = modified[^2] == (byte)'A' ? (byte)'B' : (byte)'A';
    Reject(() => OfflineActivationRequest.Verify(modified), "tampered request");
    var first = (JsonObject)model.DeepClone();
    first["installationKeySha256"] = parsed.InstallationKeySha256;
    var firstFile = Sign(first.ToJsonString());
    Check(store.Import(firstFile, now).Allows("ha"), "offline activation");
    var reopened = new OfflineLicenseStore(directory, verifier);
    Check(reopened.Inspect(now.AddMinutes(1))?.Allows("ha") == true, "restart preserves activation");
    first["revision"] = 3;
    Check(reopened.Import(Sign(first.ToJsonString()), now.AddMinutes(2)).Revision == 3, "offline renewal");
    Reject(() => reopened.Import(firstFile, now.AddMinutes(3)), "persisted revision rollback");
    Reject(() => reopened.Inspect(now.AddHours(-1)), "observed clock rollback");
    var otherStore = new OfflineLicenseStore(directory2, verifier);
    otherStore.Initialize();
    Reject(() => otherStore.Import(firstFile, now), "copy license to independent installation");
    var statePath = Path.Combine(directory, "license.state");
    var stateBytes = File.ReadAllBytes(statePath);
    var corrupted = stateBytes.ToArray();
    corrupted[8] = corrupted[8] == (byte)'A' ? (byte)'B' : (byte)'A';
    File.WriteAllBytes(statePath, corrupted);
    Reject(() => reopened.Inspect(now.AddMinutes(3)), "edited persistent state");
    File.WriteAllBytes(statePath, stateBytes);
    Check(reopened.Inspect(now.AddDays(31))?.Validity == LicenseValidity.Expired, "expiry persists across restart");
    File.Delete(statePath);
    try { reopened.Inspect(now); throw new Exception("FAIL: missing state accepted"); }
    catch (FileNotFoundException) { Console.WriteLine("PASS: missing state fails closed"); }
    try { reopened.Initialize(); throw new Exception("FAIL: silent reinitialization"); }
    catch (InvalidOperationException) { Console.WriteLine("PASS: no silent identity regeneration"); }
}
finally
{
    if (Directory.Exists(directory)) Directory.Delete(directory, true);
    if (Directory.Exists(directory2)) Directory.Delete(directory2, true);
}
// Customer-side revocation acceptance, with synthetic signed documents.
// Real issuance, seat/site limits and issuer ledger tests live in authority CI.
var revokeDir = Path.Combine(Path.GetTempPath(), "gc-revoke-" + Guid.NewGuid().ToString("N"));
try
{
    var revokeStore = new OfflineLicenseStore(revokeDir, verifier);
    revokeStore.Initialize();
    var revokeBinding = OfflineActivationRequest.Verify(revokeStore.ExportActivationRequest()).InstallationKeySha256;
    var entitlement = (JsonObject)model.DeepClone();
    entitlement["installationKeySha256"] = revokeBinding;
    var activeFile = Sign(entitlement.ToJsonString());
    var activeLicense = revokeStore.Import(activeFile, now);
    byte[] MakeRevocation(string allocation) => FixtureSign("GCV1", new
    {
        schemaVersion = 1, product = "GatewayCore", licenseId = activeLicense.LicenseId,
        customerId = activeLicense.CustomerId, deploymentId = activeLicense.DeploymentId,
        allocationId = allocation, installationKeySha256 = revokeBinding, revokedAt = now.ToUnixTimeSeconds()
    }, signer);
    Reject(() => revokeStore.ImportRevocation(MakeRevocation("wrong-node"), now), "different allocation revocation");
    var revocation = MakeRevocation(activeLicense.AllocationId);
    var edited = revocation.ToArray();
    edited[^2] = edited[^2] == (byte)'A' ? (byte)'B' : (byte)'A';
    Reject(() => revokeStore.ImportRevocation(edited, now), "forged revocation");
    Check(revokeStore.Inspect(now)?.Allows("ha") == true, "invalid revocation leaves entitlement intact");
    Check(revokeStore.ImportRevocation(revocation, now).Validity == LicenseValidity.Revoked, "valid offline revocation");
    var reopened = new OfflineLicenseStore(revokeDir, verifier);
    Check(reopened.Inspect(now.AddMinutes(1))?.Validity == LicenseValidity.Revoked, "revocation survives restart");
    Reject(() => reopened.Import(activeFile, now.AddMinutes(1)), "revoked allocation cannot import old license");
}
finally { if (Directory.Exists(revokeDir)) Directory.Delete(revokeDir, true); }
var package = Path.Combine(Path.GetTempPath(), "gc-package-" + Guid.NewGuid().ToString("N"));
try
{
    Directory.CreateDirectory(package);
    var assembly = Path.Combine(package, "GatewayCoreYarp.dll");
    var contents = Encoding.UTF8.GetBytes("disposable binary fixture");
    File.WriteAllBytes(assembly, contents);
    using var releaseSigner = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var releaseVerifier = new ReleaseIntegrityVerifier(new Dictionary<string, byte[]>
    { ["release-test"] = releaseSigner.ExportSubjectPublicKeyInfo() });
    var commit = new string('a', 40);
    var manifestPath = Path.Combine(package, ReleaseIntegrityVerifier.ManifestName);
    var fileHash = Convert.ToHexString(SHA256.HashData(contents));
    void Manifest(string path, ECDsa releaseKey)
    {
        var payload = JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 1, product = "GatewayCore", sourceCommit = commit,
            files = new[] { new { path, size = contents.Length, sha256 = fileHash } }
        });
        var prefix = "GCM1.release-test." + B64(payload);
        File.WriteAllText(manifestPath, prefix + "." + B64(releaseKey.SignData(Encoding.ASCII.GetBytes(prefix),
            HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)), Encoding.ASCII);
    }
    Manifest("GatewayCoreYarp.dll", releaseSigner);
    Check(releaseVerifier.Verify(package, commit) == commit, "independently signed release inventory");
    File.WriteAllBytes(assembly, Encoding.UTF8.GetBytes("modified binary fixture!!"));
    Reject(() => releaseVerifier.Verify(package, commit), "modified packaged binary");
    File.WriteAllBytes(assembly, contents);
    var extra = Path.Combine(package, "injected.dll");
    File.WriteAllText(extra, "unexpected");
    Reject(() => releaseVerifier.Verify(package, commit), "injected package file");
    File.Delete(extra);
    Reject(() => releaseVerifier.Verify(package, new string('b', 40)), "different release commit");
    Manifest("../GatewayCoreYarp.dll", releaseSigner);
    Reject(() => releaseVerifier.Verify(package, commit), "signed traversal path");
    Manifest("GatewayCoreYarp.dll", signer);
    Reject(() => releaseVerifier.Verify(package, commit), "license signing key is not release trust");
    Manifest("GatewayCoreYarp.dll", releaseSigner);
    File.Delete(assembly);
    Reject(() => releaseVerifier.Verify(package, commit), "missing package binary");
}
finally { if (Directory.Exists(package)) Directory.Delete(package, true); }
Console.WriteLine("OFFLINE_LICENSE_VERIFIER_ACCEPTANCE_PASS");

// Test-only envelope construction, never included in shipping projects.
byte[] FixtureSign(string kind, object payload, ECDsa key)
{
    var prefix = kind + ".test-1." + B64(JsonSerializer.SerializeToUtf8Bytes(payload));
    return Encoding.ASCII.GetBytes(prefix + "." + B64(key.SignData(Encoding.ASCII.GetBytes(prefix),
        HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)));
}
