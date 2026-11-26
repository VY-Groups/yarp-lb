using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using System.Text.Json.Nodes;

if (args.Length > 0 && args[0] == "--fleet-recovery-fixture")
{
    await FleetRecoveryProcessAcceptance.RunAsync(args[1..]);
    return;
}

await GatewayLogFilteringAcceptance.RunAsync();

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
GatewayTelemetryLifecycleTests.Run();
var linuxGslbCommand = GslbServiceRestart.Build(false, "/usr/bin/systemctl");
var windowsGslbCommand = GslbServiceRestart.Build(true, @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe");
Must(!linuxGslbCommand.UseShellExecute && linuxGslbCommand.ArgumentList.SequenceEqual(
    new[] { "--no-ask-password", "restart", "gatewaycore-gslb.service" }),
    "Linux GSLB restart is fixed to the authorized service");
Must(!windowsGslbCommand.UseShellExecute &&
    windowsGslbCommand.ArgumentList.Contains("-NonInteractive") &&
    windowsGslbCommand.ArgumentList.Last().Contains("GatewayCoreGslb", StringComparison.Ordinal) &&
    !windowsGslbCommand.ArgumentList.Last().Contains("-Force", StringComparison.Ordinal),
    "Windows GSLB restart uses bounded fixed SCM controls without forcing dependents");
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
var metricDimensionBudget = new GatewayTelemetryDimensionBudget(2);
var trackedMetricTags = metricDimensionBudget.CreateTags("route_a", "cluster_a", "destination_a", "5xx");
var overflowMetricTags = metricDimensionBudget.CreateTags("route_b", "cluster_b", "destination_b", "2xx");
var unsafeMetricTags = metricDimensionBudget.CreateTags("route/with/path", "cluster_a", "destination_a", "4xx");
Must(metricDimensionBudget.TrackedTuples == 1 &&
     (string?)trackedMetricTags.First(x => x.Key == "gateway.route.id").Value == "route_a" &&
     (string?)trackedMetricTags.First(x => x.Key == "gateway.cluster.id").Value == "cluster_a" &&
     (string?)trackedMetricTags.First(x => x.Key == "gateway.destination.id").Value == "destination_a" &&
     (string?)overflowMetricTags.First(x => x.Key == "gateway.route.id").Value == "_other" &&
     (string?)overflowMetricTags.First(x => x.Key == "gateway.cluster.id").Value == "_other" &&
     (string?)overflowMetricTags.First(x => x.Key == "gateway.destination.id").Value == "_other" &&
     (string?)unsafeMetricTags.First(x => x.Key == "gateway.route.id").Value == "_other",
    "OTLP proxy metrics reserve the overflow tuple within the hard cardinality cap and validate configured IDs");
var concurrentDimensionBudget = new GatewayTelemetryDimensionBudget(16);
var concurrentTags = new System.Collections.Concurrent.ConcurrentBag<System.Diagnostics.TagList>();
Parallel.For(0, 256, index => concurrentTags.Add(concurrentDimensionBudget.CreateTags(
    $"route_{index}", $"cluster_{index}", $"destination_{index}", "2xx")));
var concurrentRouteValues = concurrentTags.Select(tags => (string?)tags.First(x => x.Key == "gateway.route.id").Value)
    .Distinct(StringComparer.Ordinal).ToArray();
Must(concurrentDimensionBudget.TrackedTuples <= 15 && concurrentRouteValues.Length <= 16 &&
     concurrentRouteValues.Contains("_other", StringComparer.Ordinal),
    "concurrent OTLP dimension registration stays inside named-plus-reserved overflow tuple budget");
static long MeasureWarmDimensionTagAllocations(GatewayTelemetryDimensionBudget budget)
{
    var tags = default(System.Diagnostics.TagList);
    for (var i = 0; i < 20_000; i++)
        tags = budget.CreateTags("route_fixed", "cluster_fixed", "destination_fixed", "2xx");
    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();
    var before = GC.GetAllocatedBytesForCurrentThread();
    for (var i = 0; i < 100_000; i++)
        tags = budget.CreateTags("route_fixed", "cluster_fixed", "destination_fixed", "2xx");
    var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
    GC.KeepAlive(tags);
    return allocated;
}
var allocationMeasurement = MeasureWarmDimensionTagAllocations(new GatewayTelemetryDimensionBudget());
Console.WriteLine($"DIMENSION_TAG_WARM_ALLOCATIONS bytes={allocationMeasurement} calls=100000 bytes_per_call={allocationMeasurement / 100000.0:F3}");
Must(allocationMeasurement <= 100_000,
    "warmed OTLP dimension tag creation stays at or below 1 allocated byte per request after registration");
using (var privacyActivity = new System.Diagnostics.Activity("privacy-contract"))
{
    privacyActivity.SetTag("client.address", "203.0.113.8");
    privacyActivity.SetTag("network.peer.address", "203.0.113.8");
    privacyActivity.SetTag("url.full", "https://gateway.example/private?id=secret");
    privacyActivity.SetTag("url.path", "/private");
    privacyActivity.SetTag("url.query", "id=secret");
    privacyActivity.SetTag("http.request.header.authorization", "Bearer secret");
    privacyActivity.SetTag("gateway.route.id", "public_route");
    privacyActivity.SetTag("http.request.header.x-api-key", "custom-header-secret");
    privacyActivity.SetTag("http.request.header.x-customer-id", new[] { "customer-secret" });
    privacyActivity.SetTag("custom.enrichment", "arbitrary-secret");
    privacyActivity.SetTag("gateway.cluster.id", "invalid/id");
    privacyActivity.SetTag("http.response.status_code", 503);
    privacyActivity.SetTag("network.protocol.version", "2");
    privacyActivity.Start();
    new GatewayTelemetryPrivacyProcessor().OnEnd(privacyActivity);
    Must(privacyActivity.GetTagItem("client.address") is null &&
         privacyActivity.GetTagItem("network.peer.address") is null &&
         privacyActivity.GetTagItem("url.full") is null &&
         privacyActivity.GetTagItem("url.path") is null &&
         privacyActivity.GetTagItem("url.query") is null &&
         privacyActivity.GetTagItem("http.request.header.authorization") is null,
        "OTLP privacy processor removes client address, raw URL and secret attributes");
    Must((string?)privacyActivity.GetTagItem("gateway.route.id") == "public_route" &&
         privacyActivity.GetTagItem("http.response.status_code") is 503 &&
         (string?)privacyActivity.GetTagItem("network.protocol.version") == "2",
        "OTLP privacy processor preserves bounded route, status and protocol attribution");
    Must(privacyActivity.GetTagItem("http.request.header.x-api-key") is null &&
         privacyActivity.GetTagItem("http.request.header.x-customer-id") is null &&
         privacyActivity.GetTagItem("custom.enrichment") is null &&
         privacyActivity.GetTagItem("gateway.cluster.id") is null,
        "OTLP span attribute allowlist rejects unknown header arrays, custom data and invalid attribution");
}
// Exercise the pooled reject-key buffer beyond its initial 16 entries,
// across repeated spans, including known-good route/status attributes.
// Unknown enrichment and raw client fields must still be removed, regardless
// of the number or ordering of tags.
foreach (var validId in new[] { "route_1", "ROUTE-ABC", new string('A', 80) })
    Must(GatewayOpenTelemetry.IsSafeTelemetryId(validId),
        "safe trace ID preserved by allocation-free ASCII scan");
foreach (var invalidId in new[] { "", "route/name", "route\n", "route\r",
    "route\nforged", "nonascii_é", "route id", new string('A', 81) })
    Must(!GatewayOpenTelemetry.IsSafeTelemetryId(invalidId),
        "invalid newline and oversized trace IDs rejected");

var privacyProcessor = new GatewayTelemetryPrivacyProcessor();
using (var invalidIdSpan = new System.Diagnostics.Activity("unsafe-id-contract"))
{
    invalidIdSpan.SetTag("gateway.route.id", "route\n");
    invalidIdSpan.SetTag("gateway.cluster.id", "safe_cluster");
    invalidIdSpan.Start();
    privacyProcessor.OnEnd(invalidIdSpan);
    Must(invalidIdSpan.GetTagItem("gateway.route.id") is null &&
        (string?)invalidIdSpan.GetTagItem("gateway.cluster.id") == "safe_cluster",
        "OTLP privacy scrub removes newline route IDs and preserves valid cluster");
}

for (var iteration = 0; iteration < 4; iteration++)
{
    using var span = new System.Diagnostics.Activity("large-privacy-contract");
    span.SetTag("http.response.status_code", 503);
    span.SetTag("gateway.route.id", "public_route");
    for (var index = 0; index < 96; index++)
        span.SetTag("untrusted.enrichment." + index,
            "sensitive-" + iteration + "-" + index);
    span.SetTag("url.full", "https://example.invalid/private?token=secret");
    span.Start();
    privacyProcessor.OnEnd(span);
    for (var index = 0; index < 96; index++)
        Must(span.GetTagItem("untrusted.enrichment." + index) is null,
            "pooled trace tag filter removes every unknown enrichment");
    Must(span.GetTagItem("url.full") is null &&
         (string?)span.GetTagItem("gateway.route.id") == "public_route" &&
         span.GetTagItem("http.response.status_code") is 503,
        "pooled trace filter preserves permitted attributes and rejects URL secrets");
}
Console.WriteLine("PASS: pooled OTLP trace cleanup handles 96 unknown tags without privacy regression");

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
 "Sites":[{"Address":"10.0.0.20","HealthUrl":"http://127.0.0.1:8888/ready","Weight":1}]}]}
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
var rollbackFixture = Directory.CreateTempSubdirectory("gc-engine-rollback-");
try
{
    var current = Directory.CreateDirectory(Path.Combine(rollbackFixture.FullName, "current")).FullName;
    var successor = Directory.CreateDirectory(Path.Combine(rollbackFixture.FullName, "successor")).FullName;
    Must(!EngineConfigContract.IsRollbackFenced(current), "new engine transaction is not fenced");
    EngineConfigContract.MarkRollback(current);
    Must(EngineConfigContract.IsRollbackFenced(current) &&
        File.ReadAllBytes(Path.Combine(current, "rollback-fence")).SequenceEqual(new byte[] { 1 }),
        "engine rollback persists its activation-denial marker");
    EngineConfigContract.MarkRollback(current);
    Must(EngineConfigContract.IsRollbackFenced(current) && !EngineConfigContract.IsRollbackFenced(successor),
        "engine rollback is idempotent and does not fence a different transaction");
}
finally { rollbackFixture.Delete(recursive: true); }
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
var admissionConfig = l4.DeepClone().AsObject();
var admissionListener = admissionConfig["Tcp"]![0]!.AsObject();
foreach (var field in new[] { "TcpMaxConnections", "UdpMaxSessions" })
{
    foreach (var value in new[] { 1, 1024, 4096 })
    {
        admissionListener[field] = value;
        Must(EngineConfigContract.Validate("l4",admissionConfig,false),
            "signed L4 admission accepts " + field + "=" + value);
    }
    foreach (var value in new[] { 0, -1, 4097 })
    {
        admissionListener[field] = value;
        Must(!EngineConfigContract.Validate("l4",admissionConfig,false),
            "signed L4 admission rejects " + field + "=" + value);
    }
    admissionListener[field] = null;
    Must(!EngineConfigContract.Validate("l4",admissionConfig,false), "signed L4 admission rejects null");
    admissionListener[field] = "2";
    Must(!EngineConfigContract.Validate("l4",admissionConfig,false), "signed L4 admission rejects strings");
    admissionListener.Remove(field);
}
var udpIdleConfig = l4.DeepClone().AsObject();
var udpIdleListener = udpIdleConfig["Tcp"]![0]!.DeepClone().AsObject();
udpIdleListener.Remove("TcpIdleTimeoutSeconds");
udpIdleConfig["Tcp"] = new JsonArray();
udpIdleConfig["Udp"] = new JsonArray(udpIdleListener);
Must(EngineConfigContract.Validate("l4",udpIdleConfig,false), "UDP idle timeout defaults remain valid");
foreach (var value in new[] { 1, 30, 3600 })
{
    udpIdleListener["UdpIdleTimeoutSeconds"] = value;
    Must(EngineConfigContract.Validate("l4",udpIdleConfig,false),
        "signed UDP configuration accepts bounded idle timeout " + value);
}
foreach (var value in new[] { 0, -1, 3601 })
{
    udpIdleListener["UdpIdleTimeoutSeconds"] = value;
    Must(!EngineConfigContract.Validate("l4",udpIdleConfig,false),
        "signed UDP configuration rejects out-of-range idle timeout " + value);
}
udpIdleListener["UdpIdleTimeoutSeconds"] = "30";
Must(!EngineConfigContract.Validate("l4",udpIdleConfig,false), "signed UDP configuration rejects string idle timeout");
udpIdleListener["UdpIdleTimeoutSeconds"] = null;
Must(!EngineConfigContract.Validate("l4",udpIdleConfig,false), "signed UDP configuration rejects explicit null idle timeout");
var dnsBudget = dns.DeepClone().AsObject();
foreach (var value in new[] {0,20,200000})
{
    dnsBudget["MaxUdpQueriesPerSecond"] = value;
    Must(EngineConfigContract.Validate("gslb",dnsBudget,false), "signed DNS UDP aggregate bound accepts " + value);
}
foreach (var value in new[] {-1,1,19,200001})
{
    dnsBudget["MaxUdpQueriesPerSecond"] = value;
    Must(!EngineConfigContract.Validate("gslb",dnsBudget,false), "signed DNS UDP aggregate bound rejects " + value);
}
dnsBudget["MaxUdpQueriesPerSecond"] = null;
Must(!EngineConfigContract.Validate("gslb",dnsBudget,false), "signed DNS aggregate null rejected");
dnsBudget["MaxUdpQueriesPerSecond"] = "20";
Must(!EngineConfigContract.Validate("gslb",dnsBudget,false), "signed DNS aggregate string rejected");
dnsBudget["MaxUdpQueriesPerSecond"] = 20;
dnsBudget["GroupIpv6UdpClientsByPrefix"] = true;
Must(EngineConfigContract.Validate("gslb",dnsBudget,false), "signed IPv6 prefix grouping accepted");
dnsBudget["GroupIpv6UdpClientsByPrefix"] = "true";
Must(!EngineConfigContract.Validate("gslb",dnsBudget,false), "signed IPv6 grouping rejects string");
dnsBudget["GroupIpv6UdpClientsByPrefix"] = null;
Must(!EngineConfigContract.Validate("gslb",dnsBudget,false), "signed IPv6 grouping rejects null");
var badDns=dns.DeepClone().AsObject();
badDns["Zones"]![0]!["Sites"]![0]!["HealthUrl"]="file:///etc/passwd";
Must(!EngineConfigContract.Validate("gslb",badDns,false),
    "unsafe probe URL scheme rejected");
var tcpDns = dns.DeepClone().AsObject();
tcpDns["ListenHost"] = "::1";
var tcpSite = tcpDns["Zones"]![0]!["Sites"]![0]!.AsObject();
tcpSite["Address"] = "fd00::17";
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
    new JsonObject { ["Host"] = "ns1.test.example", ["Address"] = "10.0.0.53" });
// Signed gateway staging must reject the same non-unicast published
// destination addresses as the running GSLB engine, rather than accepting
// a signed revision that inevitably fails DNS startup.
foreach (var badAddress in new[] {
    "0.0.0.0", "169.254.1.2", "224.0.0.1", "240.0.0.1",
    "::", "ff02::1", "fe80::12%2", "::ffff:192.0.2.1"
})
{
    var invalidSite = dns.DeepClone().AsObject();
    invalidSite["Zones"]![0]!["Sites"]![0]!["Address"] = badAddress;
    Must(!EngineConfigContract.Validate("gslb", invalidSite, false),
        "signed GSLB staging rejects published backend " + badAddress);
    var invalidNs = authoritativeDns.DeepClone().AsObject();
    invalidNs["Zones"]![0]!["NameServers"]![0]!["Address"] = badAddress;
    Must(!EngineConfigContract.Validate("gslb", invalidNs, false),
        "signed GSLB staging rejects authoritative NS " + badAddress);
}
var delegatedDns = authoritativeDns.DeepClone().AsObject();
delegatedDns["Zones"]![0]!["Delegations"] = new JsonArray(
    new JsonObject {
        ["Name"] = "child.test.example",
        ["NameServers"] = new JsonArray(
            new JsonObject { ["Host"] = "ns.child.test.example", ["Address"] = "10.1.2.3" })
    });
Must(EngineConfigContract.Validate("gslb", delegatedDns, false),
    "signed GSLB staging accepts private unicast delegated NS");
foreach (var badAddress in new[] { "0.0.0.0", "224.0.0.1", "fe80::53%3", "ff02::1" })
{
    var invalidDelegation = delegatedDns.DeepClone().AsObject();
    invalidDelegation["Zones"]![0]!["Delegations"]![0]!["NameServers"]![0]!["Address"] = badAddress;
    Must(!EngineConfigContract.Validate("gslb", invalidDelegation, false),
        "signed GSLB staging rejects delegated NS " + badAddress);
}
var privateSite = dns.DeepClone().AsObject();
privateSite["Zones"]![0]!["Sites"]![0]!["Address"] = "fd00::9";
Must(EngineConfigContract.Validate("gslb", privateSite, false),
    "signed GSLB staging retains IPv6 unique-local on-premises backend support");
foreach (var documented in new[] { "192.0.2.80", "198.51.100.53", "203.0.113.17", "2001:db8::17" })
{
    var productionCandidate = dns.DeepClone().AsObject();
    productionCandidate["Zones"]![0]!["Sites"]![0]!["Address"] = documented;
    Must(!EngineConfigContract.Validate("gslb", productionCandidate, false),
        "production signed staging refuses RFC documentation backend " + documented);
    productionCandidate["AllowDocumentationAddressesForTesting"] = true;
    Must(EngineConfigContract.Validate("gslb", productionCandidate, false),
        "explicit loopback fixture allows documentation backend " + documented);
    productionCandidate["AllowNonLoopbackListeners"] = true;
    Must(!EngineConfigContract.Validate("gslb", productionCandidate, true),
        "external bind opt-in cannot coexist with documentation fixture permission");
    productionCandidate["AllowNonLoopbackListeners"] = false;
    productionCandidate["ListenHost"] = "0.0.0.0";
    Must(!EngineConfigContract.Validate("gslb", productionCandidate, true),
        "non-loopback listener cannot enable documentation fixture permission");
}
var fixtureNs = authoritativeDns.DeepClone().AsObject();
fixtureNs["Zones"]![0]!["NameServers"]![0]!["Address"] = "192.0.2.53";
Must(!EngineConfigContract.Validate("gslb", fixtureNs, false),
    "signed staging refuses production documentation authoritative NS");
fixtureNs["AllowDocumentationAddressesForTesting"] = true;
Must(EngineConfigContract.Validate("gslb", fixtureNs, false),
    "signed staging accepts explicit isolated lab documentation NS");
var fixtureChild = delegatedDns.DeepClone().AsObject();
fixtureChild["Zones"]![0]!["Delegations"]![0]!["NameServers"]![0]!["Address"] = "2001:db8::53";
Must(!EngineConfigContract.Validate("gslb", fixtureChild, false),
    "signed staging refuses production documentation delegated NS");
fixtureChild["AllowDocumentationAddressesForTesting"] = true;
Must(EngineConfigContract.Validate("gslb", fixtureChild, false),
    "signed staging accepts explicit isolated lab documentation delegated NS");
var invalidFlag = dns.DeepClone().AsObject();
invalidFlag["AllowDocumentationAddressesForTesting"] = "true";
Must(!EngineConfigContract.Validate("gslb", invalidFlag, false),
    "signed staging rejects non-boolean fixture opt-in");
foreach (var loopback in new[] { "127.0.0.1", "127.7.8.9", "::1" })
{
    var siteLoopback = dns.DeepClone().AsObject();
    siteLoopback["Zones"]![0]!["Sites"]![0]!["Address"] = loopback;
    Must(!EngineConfigContract.Validate("gslb", siteLoopback, false),
        "production signed staging rejects advertised loopback site " + loopback);
    siteLoopback["AllowDocumentationAddressesForTesting"] = true;
    Must(EngineConfigContract.Validate("gslb", siteLoopback, false),
        "isolated lab signed staging explicitly permits loopback site " + loopback);
    siteLoopback["AllowNonLoopbackListeners"] = true;
    Must(!EngineConfigContract.Validate("gslb", siteLoopback, true),
        "external listener opt-in rejects loopback fixture permission " + loopback);

    var parentLoopback = authoritativeDns.DeepClone().AsObject();
    parentLoopback["Zones"]![0]!["NameServers"]![0]!["Address"] = loopback;
    Must(!EngineConfigContract.Validate("gslb", parentLoopback, false),
        "production signed staging rejects parent NS loopback " + loopback);
    parentLoopback["AllowDocumentationAddressesForTesting"] = true;
    Must(EngineConfigContract.Validate("gslb", parentLoopback, false),
        "isolated lab signed staging explicitly permits parent NS loopback " + loopback);

    var childLoopback = delegatedDns.DeepClone().AsObject();
    childLoopback["Zones"]![0]!["Delegations"]![0]!["NameServers"]![0]!["Address"] = loopback;
    Must(!EngineConfigContract.Validate("gslb", childLoopback, false),
        "production signed staging rejects delegated NS loopback " + loopback);
    childLoopback["AllowDocumentationAddressesForTesting"] = true;
    Must(EngineConfigContract.Validate("gslb", childLoopback, false),
        "isolated lab signed staging explicitly permits delegated NS loopback " + loopback);
}
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
    "legacy SHA-1 pinned certificate authorized only on HTTPS");
var sha256Pin = "SHA256:" + Convert.ToHexString(SHA256.HashData(clientCert.RawData));
var sha256Pinned = AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{sha256Pin});
Must(AgentClientCertificatePolicy.IsAuthorized(allowed,sha256Pinned),
    "SHA-256 certificate pin authorizes the exact DER certificate");
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
allowed.Connection.ClientCertificate = clientCert;
var wrongSha256Pin = AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{
    "SHA256:" + Convert.ToHexString(SHA256.HashData(otherCert.RawData)) });
Must(!AgentClientCertificatePolicy.IsAuthorized(allowed,wrongSha256Pin),
    "SHA-256 pin for a different certificate is rejected without SHA-1 downgrade");
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
// Exercise the live request gate, separately from TLS transport acceptance.
var livePins = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string,string?>
{
    ["Agent:TrustedClientThumbprints:0"] = sha256Pin
}).Build();
allowed.Request.Scheme = "https";
allowed.Connection.ClientCertificate = clientCert;
Must(AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "live pin policy grants only a configured trusted certificate");
allowed.Connection.ClientCertificate = otherCert;
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "empty denylist does not authorize an untrusted certificate");
allowed.Connection.ClientCertificate = clientCert;
livePins["Agent:RevokedClientThumbprints:0"] = sha256Pin;
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "revocation overrides an exact trusted SHA-256 pin");
livePins["Agent:RevokedClientThumbprints:0"] = otherCert.Thumbprint;
Must(AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "revocation of another certificate does not deny the trusted identity");
livePins["Agent:RevokedClientThumbprints:0"] = "invalid";
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "malformed live revocation configuration fails closed");
livePins["Agent:RevokedClientThumbprints:0"] = clientCert.Thumbprint;
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "legacy deny pin overrides a modern trust pin for the same certificate");
allowed.Request.Scheme = "http";
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "plaintext live request denied");
allowed.Request.Scheme = "https";
allowed.Connection.ClientCertificate = null;
Must(!AgentClientCertificatePolicy.IsAuthorizedLive(allowed,livePins),
    "missing TLS identity denied");
var invalidPins=false;
try { AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{"not-a-thumbprint"}); }
catch (InvalidOperationException) { invalidPins=true; }
Must(invalidPins, "invalid configured controller thumbprint rejects startup");
var malformedSha256Pins=false;
try { AgentClientCertificatePolicy.ParsePinnedThumbprints(new[]{"SHA256:"+new string('A',40)}); }
catch (InvalidOperationException) { malformedSha256Pins=true; }
Must(malformedSha256Pins, "malformed explicit SHA-256 pin is rejected without legacy fallback");
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
