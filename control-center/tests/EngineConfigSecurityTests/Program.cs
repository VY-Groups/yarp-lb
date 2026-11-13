using System.Security.Cryptography;
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
Console.WriteLine("ENGINE CONFIG CONTRACT ACCEPTANCE PASSED");
