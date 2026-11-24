using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using GatewayCore.Licensing;
using GatewayCore.LicenseAuthority;

// Test-only ephemeral signing keys; no issuer or reusable private key ships.
using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var installation = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var binding = Convert.ToHexString(SHA256.HashData(installation.ExportSubjectPublicKeyInfo()));
var now = DateTimeOffset.FromUnixTimeSeconds(1800000000);
var keys = new Dictionary<string, byte[]> { ["test-1"] = signer.ExportSubjectPublicKeyInfo() };
var verifier = new OfflineLicenseVerifier(keys);
if (args.Length == 2 && args[0] == "--ci-trust")
{
    // Disposable public-only trust resource for commercial compile CI.
    File.WriteAllBytes(args[1], JsonSerializer.SerializeToUtf8Bytes(keys));
    return;
}
if (args.Length >= 2 && args[0] is "--ci-authority" or "--ci-issue" or "--ci-revoke" or "--ci-downgrade" or "--ci-upgrade")
{
    if (Environment.GetEnvironmentVariable("CI") != "true" ||
        Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" || !OperatingSystem.IsLinux())
        throw new InvalidOperationException("Disposable Linux CI fixture only.");
    var root = Path.GetFullPath(args[1]);
    var keyPath = Path.Combine(root, "disposable-ci-issuer.pk8");
    var ledgerPath = Path.Combine(root, "issuer.json");
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
        var issuer = new OfflineIssuer(ledgerPath, signer, "test-1");
        issuer.Initialize(new Subscription("ci-license", "ci-customer", "ci-deployment", "standard",
            1, 1, DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds(), new[] {"l7", "tls", "monitoring"}),
            DateTimeOffset.UtcNow);
        return;
    }
    if (args.Length != 4) throw new ArgumentException("Invalid CI fixture arguments.");
    var privateKey = File.ReadAllBytes(keyPath);
    try { signer.ImportPkcs8PrivateKey(privateKey, out _); }
    finally { CryptographicOperations.ZeroMemory(privateKey); }
    var authority = new OfflineIssuer(ledgerPath, signer, "test-1");
    if (args[0] is "--ci-downgrade" or "--ci-upgrade")
    {
        authority.RenewSubscription(new Subscription("ci-license", "ci-customer", "ci-deployment", "standard",
            1, 1, DateTimeOffset.UtcNow.AddDays(2).ToUnixTimeSeconds(),
            args[0] == "--ci-downgrade" ? new[] {"monitoring"} : new[] {"l7", "tls", "monitoring"}),
            DateTimeOffset.UtcNow);
    }
    var fixtureEnvelope = args[0] switch
    {
        "--ci-issue" or "--ci-downgrade" or "--ci-upgrade" => authority.Issue(File.ReadAllBytes(args[2]), "ci-dc", DateTimeOffset.UtcNow),
        "--ci-revoke" => authority.Revoke(args[2], DateTimeOffset.UtcNow),
        _ => throw new ArgumentException("Invalid CI command.")
    };
    using var output = new FileStream(args[3], FileMode.CreateNew, FileAccess.Write, FileShare.None);
    output.Write(fixtureEnvelope);
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
var issuerDir = Path.Combine(Path.GetTempPath(), "gc-issuer-" + Guid.NewGuid().ToString("N"));
var nodeDirs = Enumerable.Range(0,3).Select(i => issuerDir + "-node-" + i).ToArray();
try
{
    if (OperatingSystem.IsLinux()) Directory.CreateDirectory(issuerDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
    else Directory.CreateDirectory(issuerDir);
    var authority = new OfflineIssuer(Path.Combine(issuerDir, "subscription.json"), signer, "test-1");
    var terms = new Subscription("business-license", "business-customer", "business-deployment",
        "professional", 2, 1, now.AddDays(30).ToUnixTimeSeconds(), new[] {"l7", "ha"});
    authority.Initialize(terms, now);
    var nodes = nodeDirs.Select(path => new OfflineLicenseStore(path, verifier)).ToArray();
    foreach (var node in nodes) node.Initialize();
    var req = nodes[0].ExportActivationRequest();
    var issued = authority.Issue(req, "dc", now);
    Check(nodes[0].Import(issued, now).Allows("ha"), "real issuer-to-installation offline activation");
    Check(issued.SequenceEqual(authority.Issue(req, "dc", now.AddMinutes(1))), "issuer committed request replay returns original bytes");
    try { authority.Issue(nodes[1].ExportActivationRequest(), "dr", now); throw new Exception("FAIL: site limit"); }
    catch (InvalidOperationException) { Console.WriteLine("PASS: issuer denies excess site"); }
    Check(nodes[1].Import(authority.Issue(nodes[1].ExportActivationRequest(), "dc", now), now).Allows("ha"), "second allocated node");
    try { authority.Issue(nodes[2].ExportActivationRequest(), "dc", now); throw new Exception("FAIL: seat limit"); }
    catch (InvalidOperationException) { Console.WriteLine("PASS: issuer denies excess node"); }
    var recovered = new OfflineIssuer(Path.Combine(issuerDir, "subscription.json"), signer, "test-1");
    recovered.RenewSubscription(terms with { ExpiresAt = now.AddDays(365).ToUnixTimeSeconds() }, now.AddMinutes(2));
    var renewed = nodes[0].Import(recovered.Issue(nodes[0].ExportActivationRequest(), "dc", now.AddMinutes(2)), now.AddMinutes(2));
    Check(renewed.Revision == 2 && renewed.ExpiresAt > now.AddDays(360), "issuer renewal retains allocation and advances revision");
    Reject(() => nodes[0].Import(issued, now.AddMinutes(3)), "old issuer license after renewal");
    var revoked = recovered.Revoke(renewed.AllocationId, now.AddMinutes(4));
    Check(revoked.SequenceEqual(recovered.Revoke(renewed.AllocationId, now.AddMinutes(5))), "revocation retry is idempotent");
    Reject(() => nodes[1].ImportRevocation(revoked, now.AddMinutes(4)), "revocation for different allocation");
    var tampered = revoked.ToArray();
    tampered[^2] = tampered[^2] == (byte)'A' ? (byte)'B' : (byte)'A';
    Reject(() => nodes[0].ImportRevocation(tampered, now.AddMinutes(4)), "forged revocation");
    Check(nodes[0].Inspect(now.AddMinutes(4))?.Allows("ha") == true, "invalid revocation leaves entitlement intact");
    Check(nodes[0].ImportRevocation(revoked, now.AddMinutes(4)).Validity == LicenseValidity.Revoked, "valid offline revocation");
    var reopenedRevoked = new OfflineLicenseStore(nodeDirs[0], verifier);
    Check(reopenedRevoked.Inspect(now.AddMinutes(5))?.Validity == LicenseValidity.Revoked, "revocation survives restart");
    Reject(() => reopenedRevoked.Import(issued, now.AddMinutes(5)), "revoked allocation cannot import old license");
    try { recovered.Issue(nodes[0].ExportActivationRequest(), "dc", now.AddMinutes(5)); throw new Exception("FAIL: revoked renewal"); }
    catch (InvalidOperationException) { Console.WriteLine("PASS: issuer denies revoked renewal"); }
    try { recovered.Issue(nodes[2].ExportActivationRequest(), "dc", now.AddMinutes(5)); throw new Exception("FAIL: revoked seat reused"); }
    catch (InvalidOperationException) { Console.WriteLine("PASS: offline revoked seat not silently reused"); }
}
finally
{
    foreach (var path in nodeDirs.Append(issuerDir)) if (Directory.Exists(path)) Directory.Delete(path, true);
}
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
