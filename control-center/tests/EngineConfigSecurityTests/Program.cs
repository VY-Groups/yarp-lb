using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using System.Text.Json.Nodes;

static void Must(bool condition, string name)
{
    if (!condition) throw new Exception("FAIL: "+name);
    Console.WriteLine("PASS: "+name);
}
static bool RejectsOtlpEndpoint(string value)
{
    try { OtlpEndpointPolicy.Parse(value); return false; }
    catch (InvalidOperationException) { return true; }
}
Must(OtlpEndpointPolicy.Parse(null) is null && OtlpEndpointPolicy.Parse(" ") is null,
    "OTLP remains disabled without an endpoint");
Must(OtlpEndpointPolicy.Parse("https://collector.example:4318") is not null,
    "remote OTLP collector requires and accepts HTTPS");
Must(OtlpEndpointPolicy.Parse("http://127.0.0.1:4318") is not null &&
     OtlpEndpointPolicy.Parse("http://[::1]:4318") is not null,
    "loopback OTLP collector permits local HTTP for development");
Must(RejectsOtlpEndpoint("http://collector.example:4318") &&
     RejectsOtlpEndpoint("http://10.0.0.10:4318"),
    "remote OTLP collector rejects plaintext HTTP");
Must(RejectsOtlpEndpoint("https://user:secret@collector.example") &&
     RejectsOtlpEndpoint("https://collector.example/v1/traces") &&
     RejectsOtlpEndpoint("https://collector.example?token=secret") &&
     RejectsOtlpEndpoint("https://collector.example#fragment"),
    "OTLP endpoint rejects embedded credentials, path, query and fragment");
Must(RejectsOtlpEndpoint("not a URL") && RejectsOtlpEndpoint("ftp://collector.example"),
    "malformed and unsupported OTLP endpoints reject startup");
using (var privacyActivity = new System.Diagnostics.Activity("privacy-contract"))
{
    privacyActivity.SetTag("client.address", "203.0.113.8");
    privacyActivity.SetTag("network.peer.address", "203.0.113.8");
    privacyActivity.SetTag("url.full", "https://gateway.example/private?id=secret");
    privacyActivity.SetTag("url.path", "/private");
    privacyActivity.SetTag("url.query", "id=secret");
    privacyActivity.SetTag("http.request.header.authorization", "Bearer secret");
    privacyActivity.SetTag("gateway.route.id", "public_route");
    privacyActivity.Start();
    new GatewayTelemetryPrivacyProcessor().OnEnd(privacyActivity);
    Must(privacyActivity.GetTagItem("client.address") is null &&
         privacyActivity.GetTagItem("network.peer.address") is null &&
         privacyActivity.GetTagItem("url.full") is null &&
         privacyActivity.GetTagItem("url.path") is null &&
         privacyActivity.GetTagItem("url.query") is null &&
         privacyActivity.GetTagItem("http.request.header.authorization") is null,
        "OTLP privacy processor removes client address, raw URL and secret attributes");
    Must((string?)privacyActivity.GetTagItem("gateway.route.id") == "public_route",
        "OTLP privacy processor preserves bounded route attribution");
}
await GatewayOtlpExporterAcceptance.RunAsync();
await GatewayOtlpExporterAcceptance.RunWithoutCollectorAsync();
await GatewayOtlpOverheadAcceptance.RunAsync();
var containerCollectorEndpoint = Environment.GetEnvironmentVariable("GATEWAY_OTLP_CONTAINER_ENDPOINT");
if (!string.IsNullOrWhiteSpace(containerCollectorEndpoint))
    await GatewayOtlpExporterAcceptance.RunAgainstCollectorAsync(containerCollectorEndpoint);
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
var publicDns53 = dns.DeepClone().AsObject();
publicDns53["ListenHost"] = "0.0.0.0";
publicDns53["ListenPort"] = 53;
publicDns53["AllowNonLoopbackListeners"] = true;
Must(!EngineConfigContract.Validate("gslb",publicDns53,false),
    "public authoritative DNS on port 53 still requires local public-bind approval");
Must(EngineConfigContract.Validate("gslb",publicDns53,true),
    "explicitly approved GSLB listener may bind public DNS port 53");
publicDns53["AllowNonLoopbackListeners"] = false;
Must(!EngineConfigContract.Validate("gslb",publicDns53,true),
    "DNS port 53 listener rejects missing engine opt-in");
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
var tcpDns = dns.DeepClone().AsObject();
tcpDns["ListenHost"] = "::1";
var tcpSite = tcpDns["Zones"]![0]!["Sites"]![0]!.AsObject();
tcpSite["Address"] = "2001:db8::17";
tcpSite["HealthCheckType"] = "Tcp";
tcpSite.Remove("HealthUrl");
tcpSite["TcpPort"] = 443;
Must(EngineConfigContract.Validate("gslb",tcpDns,false), "native IPv6 DNS and TCP probe can stage");
tcpDns["ListenHost"] = "::";
Must(!EngineConfigContract.Validate("gslb",tcpDns,false), "IPv6 wildcard requires both bind permissions");
tcpDns["AllowNonLoopbackListeners"] = true;
Must(!EngineConfigContract.Validate("gslb",tcpDns,false), "signed opt-in alone cannot publish IPv6");
Must(EngineConfigContract.Validate("gslb",tcpDns,true), "both opt-ins permit native IPv6 public bind");
tcpSite["HealthUrl"] = "https://localhost/ready";
Must(!EngineConfigContract.Validate("gslb",tcpDns,true), "TCP probe with conflicting HTTP URL rejected");
tcpSite["HealthCheckType"] = "Http";
Must(!EngineConfigContract.Validate("gslb",tcpDns,true), "HTTP probe with nonzero TCP port rejected");
var authoritativeDns = dns.DeepClone().AsObject();
authoritativeDns["Zones"]![0]!["SoaSerial"] = 2026111601u;
authoritativeDns["Zones"]![0]!["SoaContact"] = "hostmaster.test.example";
authoritativeDns["Zones"]![0]!["NameServers"] = new JsonArray(
    new JsonObject { ["Host"] = "ns1.test.example", ["Address"] = "127.0.0.53" });
var sameAuthoritativeDns = authoritativeDns.DeepClone().AsObject();
Must(EngineConfigContract.ValidSoaSerialTransition(authoritativeDns,sameAuthoritativeDns),
    "unchanged authoritative GSLB zone may retain its SOA serial");
var changedZoneWithoutBump = authoritativeDns.DeepClone().AsObject();
changedZoneWithoutBump["Zones"]![0]!["Sites"]![0]!["Address"] = "127.0.0.21";
Must(!EngineConfigContract.ValidSoaSerialTransition(authoritativeDns,changedZoneWithoutBump),
    "changed authoritative GSLB data cannot reuse its SOA serial");
var changedZoneWithBump = changedZoneWithoutBump.DeepClone().AsObject();
changedZoneWithBump["Zones"]![0]!["SoaSerial"] = 2026111602u;
Must(EngineConfigContract.ValidSoaSerialTransition(authoritativeDns,changedZoneWithBump),
    "changed authoritative GSLB data accepts an increasing SOA serial");
var serialRollback = authoritativeDns.DeepClone().AsObject();
serialRollback["Zones"]![0]!["SoaSerial"] = 2026111600u;
Must(!EngineConfigContract.ValidSoaSerialTransition(authoritativeDns,serialRollback),
    "authoritative GSLB SOA serial rollback is rejected");
var serialWrapCurrent = authoritativeDns.DeepClone().AsObject();
serialWrapCurrent["Zones"]![0]!["SoaSerial"] = uint.MaxValue;
var serialWrapCandidate = serialWrapCurrent.DeepClone().AsObject();
serialWrapCandidate["Zones"]![0]!["SoaSerial"] = 1u;
Must(EngineConfigContract.ValidSoaSerialTransition(serialWrapCurrent,serialWrapCandidate),
    "RFC 1982 SOA serial wraparound is accepted");
var serialHalfRange = serialWrapCurrent.DeepClone().AsObject();
serialHalfRange["Zones"]![0]!["SoaSerial"] = 0x7FFFFFFFu;
Must(!EngineConfigContract.ValidSoaSerialTransition(serialWrapCurrent,serialHalfRange),
    "ambiguous half-range SOA serial transition is rejected");
var zeroSerial = authoritativeDns.DeepClone().AsObject();
zeroSerial["Zones"]![0]!["SoaSerial"] = 0u;
Must(!EngineConfigContract.Validate("gslb",zeroSerial,false),
    "zero GSLB SOA serial is rejected by staging schema");
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
GslbAgentReportStatusParserTests.Run();
await AgentLabCaTlsAcceptance.RunAsync();
await AgentFleetRotationAcceptance.RunAsync();
await AgentFleetRotationAcceptance.RunCleanupFailureAcceptanceAsync();
if (OperatingSystem.IsLinux() || OperatingSystem.IsWindows())
    await AgentCrlAcceptance.RunAsync();
if (OperatingSystem.IsWindows())
    WindowsDpapiAcceptance.Run();
Console.WriteLine("ENGINE CONFIG CONTRACT ACCEPTANCE PASSED");
