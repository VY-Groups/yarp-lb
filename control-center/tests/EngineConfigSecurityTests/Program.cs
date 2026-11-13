using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using System.Text.Json.Nodes;

static void Must(bool condition, string name)
{
    if (!condition) throw new Exception("FAIL: "+name);
    Console.WriteLine("PASS: "+name);
}
using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
using var wrong=ECDsa.Create(ECCurve.NamedCurves.nistP256);
var privatePem=key.ExportPkcs8PrivateKeyPem();
var publicPem=key.ExportSubjectPublicKeyInfoPem();
var trust=new Dictionary<string,string> {
    [FleetConfigSignature.KeyIdFromPublicKey(publicPem)]=publicPem
};
var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
const string tx="engine_ABC123456789";
const string revision="9FDEB5DAB9C5B3BAF5CD20D4775191E2427AE3709354792A1BBCE467863AAEA9";
var l4=JsonNode.Parse("""
{"AllowNonLoopbackListeners":false,"Tcp":[{"Name":"inbound","ListenHost":"127.0.0.1",
 "ListenPort":18080,"Backends":[{"Host":"127.0.0.1","Port":8080}],"TcpIdleTimeoutSeconds":300}],
 "Udp":[]}
""")!.AsObject();
var dns=JsonNode.Parse("""
{"ListenHost":"127.0.0.1","ListenPort":15353,"ProbeIntervalSeconds":2,
 "MaxResponsesPerSecondPerClient":500,"AllowNonLoopbackListeners":false,
 "Zones":[{"Name":"test.example","TtlSeconds":30,
 "Sites":[{"Address":"127.0.0.20","HealthUrl":"http://127.0.0.1:8888/ready","Weight":1}]}]}
""")!.AsObject();
Must(EngineConfigContract.Validate("l4",l4,false), "loopback L4 candidate is valid");
Must(EngineConfigContract.Validate("gslb",dns,false), "loopback GSLB candidate is valid");
Must(!EngineConfigContract.Validate("waf",l4,false), "unimplemented WAF schema fails closed");
var signed=EngineConfigContract.Sign(privatePem,"l4",tx,revision,l4,now+120,4);
Must(EngineConfigContract.Verify(trust,"l4",tx,revision,l4,signed,now),
    "signed engine config validated against pinned controller key");
Must(!EngineConfigContract.Verify(trust,"gslb",tx,revision,l4,signed,now),
    "engine-identity substitution rejected");
Must(!EngineConfigContract.Verify(trust,"l4",tx,revision,l4,
     signed with { Sequence=5 },now), "changed sequence rejected");
Must(!EngineConfigContract.Verify(trust,"l4",tx,revision,l4,signed,now+121),
    "expired signature rejected");
Must(!EngineConfigContract.Verify(
    new Dictionary<string,string> {
        [FleetConfigSignature.KeyIdFromPublicKey(wrong.ExportSubjectPublicKeyInfoPem())]
            =wrong.ExportSubjectPublicKeyInfoPem()
    },"l4",tx,revision,l4,signed,now),"wrong trust root rejected");
var altered=l4.DeepClone().AsObject();
altered["Tcp"]![0]!["ListenPort"]=18081;
Must(!EngineConfigContract.Verify(trust,"l4",tx,revision,altered,signed,now),
    "tampered listener rejected");
var remote=l4.DeepClone().AsObject();
remote["Tcp"]![0]!["ListenHost"]="0.0.0.0";
Must(!EngineConfigContract.Validate("l4",remote,false),
    "unsafe wildcard bind rejected without signed and local opt-in");
remote["AllowNonLoopbackListeners"]=true;
Must(!EngineConfigContract.Validate("l4",remote,false),
    "controller cannot override local public-bind policy");
Must(EngineConfigContract.Validate("l4",remote,true),
    "both independent opt-ins allow explicitly configured listener");
var invalid=l4.DeepClone().AsObject();
invalid["Tcp"]![0]!["Backends"]![0]!["Port"]=0;
Must(!EngineConfigContract.Validate("l4",invalid,false), "invalid backend port rejected");
var badDns=dns.DeepClone().AsObject();
badDns["Zones"]![0]!["Sites"]![0]!["HealthUrl"]="file:///etc/passwd";
Must(!EngineConfigContract.Validate("gslb",badDns,false),
    "unsafe probe URL scheme rejected");
// Per-engine replay state must survive process restarts and reject duplicates.
var stageRoot = Path.Combine(Path.GetTempPath(), "engine-security-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(stageRoot);
try
{
    var l4Sequence = Path.Combine(stageRoot,"l4","last-accepted-sequence.txt");
    var gslbSequence = Path.Combine(stageRoot,"gslb","last-accepted-sequence.txt");
    Directory.CreateDirectory(Path.GetDirectoryName(l4Sequence)!);
    Directory.CreateDirectory(Path.GetDirectoryName(gslbSequence)!);
    FleetSequenceState.Accept(l4Sequence,4);
    Must(FleetSequenceState.Read(l4Sequence)==4, "L4 sequence is durable");
    Must(FleetSequenceState.Read(gslbSequence)==0, "GSLB sequence state is isolated");
    var replayRejected=false;
    try { FleetSequenceState.Accept(l4Sequence,4); }
    catch (InvalidOperationException) { replayRejected=true; }
    Must(replayRejected, "repeated signed L4 revision fails closed");
}
finally { Directory.Delete(stageRoot,true); }
var missingSignature = signed with { Signature = "" };
Must(!EngineConfigContract.Verify(trust,"l4",tx,revision,l4,missingSignature,now),
    "unsigned L4 payload rejected");
var signedDns=EngineConfigContract.Sign(privatePem,"gslb",tx,revision,dns,now+120,5);
Must(EngineConfigContract.Verify(trust,"gslb",tx,revision,dns,signedDns,now),
    "signed GSLB payload accepted");
Must(!EngineConfigContract.Verify(trust,"gslb",tx,revision,dns,
    signedDns with {Signature=""},now), "unsigned GSLB payload rejected");
var tamperedDns=dns.DeepClone().AsObject();
tamperedDns["Zones"]![0]!["Sites"]![0]!["Weight"]=2;
Must(!EngineConfigContract.Verify(trust,"gslb",tx,revision,tamperedDns,signedDns,now),
    "tampered GSLB site weight rejected");
Must(!EngineConfigContract.Verify(trust,"gslb",tx,revision,dns,signedDns,now+121),
    "expired GSLB signature rejected");
// This tests the actual policy invoked by every GatewayAgent route.
// Kestrel's certificate-chain trust and revocation must ALSO be verified in a
// separate real-TLS deployment test; a context test cannot prove TLS handshake.
using var certificateKey = RSA.Create(2048);
var certificateRequest = new CertificateRequest("CN=ci-controller",certificateKey,
    HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
using var clientCert = certificateRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddHours(1));
var pinned = AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{clientCert.Thumbprint});
var allowed = new DefaultHttpContext();
allowed.Request.Scheme = "https";
allowed.Connection.ClientCertificate = clientCert;
Must(AgentClientCertificatePolicy.IsAuthorized(allowed,pinned),
    "pinned certificate authorized only on HTTPS");
allowed.Request.Scheme = "http";
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,pinned),
    "plaintext request never authorizes with pinned cert");
allowed.Request.Scheme = "https";
allowed.Connection.ClientCertificate = null;
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,pinned),
    "missing client certificate denied");
using var otherCertKey = RSA.Create(2048);
var otherReq = new CertificateRequest("CN=untrusted",otherCertKey,
    HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
using var otherCert = otherReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
    DateTimeOffset.UtcNow.AddHours(1));
allowed.Connection.ClientCertificate = otherCert;
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,pinned),
    "untrusted client certificate denied");
allowed.Connection.ClientCertificate = clientCert;
var wrongPin = AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{otherCert.Thumbprint});
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,wrongPin),
    "correct presented client cert with wrong configured thumbprint denied");
allowed.Connection.ClientCertificate = otherCert;
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,pinned),
    "presented wrong identity rejected even when configured thumbprint is unchanged");
var invalidPins=false;
try { AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{"not-a-thumbprint"}); }
catch (InvalidOperationException) { invalidPins=true; }
Must(invalidPins, "invalid configured controller thumbprint rejects startup");
await AgentTlsNegativeAcceptance.RunAsync();
Console.WriteLine("ENGINE CONFIG CONTRACT ACCEPTANCE PASSED");
