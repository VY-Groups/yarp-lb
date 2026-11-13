using System.Security.Cryptography;
using System.Text.Json.Nodes;
using System.Text.Json;

static void Must(bool result, string label)
{
    if (!result) throw new Exception("FAIL: " + label);
    Console.WriteLine("PASS: " + label);
}
using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privatePem = key.ExportPkcs8PrivateKeyPem();
var publicPem = key.ExportSubjectPublicKeyInfoPem();
using var otherKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
const string revision = "D3E254A0977BA8FCD40AB1067B02E5C0915A3605EE118BA1A5BA7372D9FA90C0";
var p = JsonNode.Parse("""{"Routes":{"r":{"ClusterId":"c"}},"Clusters":{"c":{"Destinations":{"a":{"Address":"https://backend.example/"}}}}}""")!.AsObject();
var reordered = JsonNode.Parse("""{"Clusters":{"c":{"Destinations":{"a":{"Address":"https://backend.example/"}}}},"Routes":{"r":{"ClusterId":"c"}}}""")!.AsObject();
const string transaction = "rollout_ABC123456789";
var sig = FleetConfigSignature.Sign(privatePem, transaction, revision, p, now + 120);
Must(FleetConfigSignature.Verify(publicPem,transaction,revision,p,now+120,sig,now), "correct signature accepted");
Must(FleetConfigSignature.Verify(publicPem,transaction,revision,reordered,now+120,sig,now), "canonical property order stable");
Must(!FleetConfigSignature.Verify(publicPem,transaction+"X",revision,p,now+120,sig,now), "tampered transaction rejected");
Must(!FleetConfigSignature.Verify(publicPem,transaction,revision+"1",p,now+120,sig,now), "revision mismatch rejected");
Must(!FleetConfigSignature.Verify(otherKey.ExportSubjectPublicKeyInfoPem(),transaction,revision,p,now+120,sig,now), "wrong signing identity rejected");
Must(!FleetConfigSignature.Verify(publicPem,transaction,revision,p,now+120,sig,now+121), "expired signature rejected");
Must(!FleetConfigSignature.Verify(publicPem,transaction,revision,p,now+5000,sig,now), "overlong validity rejected");
Must(!FleetConfigSignature.Verify(publicPem,transaction,revision,p,now+120,"nonsense",now), "invalid signature rejected");
var tampered = p.DeepClone().AsObject();
tampered["Clusters"]!["c"]!["Destinations"]!["a"]!["Address"] = "https://evil.example/";
Must(!FleetConfigSignature.Verify(publicPem,transaction,revision,tampered,now+120,sig,now), "changed backend rejected");

var keyId = FleetConfigSignature.KeyIdFromPublicKey(publicPem);
var trusted = new Dictionary<string, string> { [keyId] = publicPem };
var signed = FleetConfigSignature.SignV2(privatePem, transaction, revision, p, now + 120, 21);
Must(signed.KeyId == keyId && signed.Sequence == 21, "v2 key ID and sequence bound");
Must(FleetConfigSignature.VerifyV2(trusted, transaction, revision, reordered, signed, now),
    "v2 signature survives canonical property reordering");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction, revision, tampered, signed, now),
    "v2 tampering rejected");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction + "bad", revision, p, signed, now),
    "v2 transaction altered rejected");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction, revision, p, signed with { Sequence = 20 }, now),
    "v2 altered sequence rejected");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction, revision, p, signed with { KeyId = "UNKNOWN" }, now),
    "v2 unknown signing key rejected");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction, revision, p, signed, now + 122),
    "v2 expired signature rejected");
using var nextKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var nextPrivate = nextKey.ExportPkcs8PrivateKeyPem();
var nextPublic = nextKey.ExportSubjectPublicKeyPem();
var rotated = new Dictionary<string, string>(trusted)
{
    [FleetConfigSignature.KeyIdFromPublicKey(nextPublic)] = nextPublic
};
var signedNew = FleetConfigSignature.SignV2(nextPrivate, transaction, revision, p, now + 120, 22);
Must(FleetConfigSignature.VerifyV2(rotated, transaction, revision, p, signed, now) &&
     FleetConfigSignature.VerifyV2(rotated, transaction, revision, p, signedNew, now),
    "dual pinned key window validates old and new signatures");
Must(!FleetConfigSignature.VerifyV2(trusted, transaction, revision, p, signedNew, now),
    "old-only pinned agent rejects untrusted rotated signing key");
var sequenceDirectory = Path.Combine(Path.GetTempPath(), "yarp-seq-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(sequenceDirectory);
try
{
    var state = Path.Combine(sequenceDirectory, "highwater.txt");
    Must(FleetSequenceState.Read(state) == 0, "sequence starts at zero");
    FleetSequenceState.Accept(state, 21);
    Must(FleetSequenceState.Read(state) == 21, "persisted high-water survives new object");
    var refusedOld = false;
    try { FleetSequenceState.Accept(state, 20); } catch (InvalidOperationException) { refusedOld = true; }
    Must(refusedOld && FleetSequenceState.Read(state) == 21, "old sequence rejected persistently");
    var refusedDuplicate = false;
    try { FleetSequenceState.Accept(state, 21); } catch (InvalidOperationException) { refusedDuplicate = true; }
    Must(refusedDuplicate, "duplicate sequence rejected");
    Must(FleetSequenceState.AllocateNext(state) == 22 && FleetSequenceState.Read(state) == 22,
        "controller allocates monotonic persisted sequence");
    File.WriteAllText(state, "CORRUPT");
    var failedClosed = false;
    try { FleetSequenceState.Read(state); } catch (InvalidDataException) { failedClosed = true; }
    Must(failedClosed, "corrupt sequence state fails closed");
}
finally { Directory.Delete(sequenceDirectory, recursive: true); }
Console.WriteLine("ALL fleet config signature acceptance tests passed.");
