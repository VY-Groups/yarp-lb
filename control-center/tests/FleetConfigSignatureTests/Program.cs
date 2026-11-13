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
Console.WriteLine("ALL fleet config signature acceptance tests passed.");
