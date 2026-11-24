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
Console.WriteLine("OFFLINE_LICENSE_VERIFIER_ACCEPTANCE_PASS");
