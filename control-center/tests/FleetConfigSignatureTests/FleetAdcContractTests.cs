using System.Security.Cryptography;
using System.Text.Json.Nodes;

internal static class FleetAdcContractTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("Fleet ADC: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var draft = JsonNode.Parse("""
        {"routes":{"web":{"ClusterId":"pool"}},"clusters":{"pool":{"Destinations":{"app":{"Address":"https://app.invalid/"}}}},
        "disabled":{"pool::standby":{"Address":"https://standby.invalid/"}},
        "monitorProfiles":{"health":{"Active":{"Enabled":true,"Path":"/ready","Interval":"00:00:15","Timeout":"00:00:05","Policy":"RiseFall"},"Metadata":{}}},
        "realServers":{"app":{"Address":"https://app.invalid/","Description":"Backend"}},
        "serviceGroups":{"web":{"Policy":"RoundRobin","MonitorProfile":"health","Members":{"app":{"Weight":"3","TrafficRole":"primary"}}}}}
        """)!.AsObject();
        Check(FleetAdcContract.TryBuildApproved(draft,new(),out var snapshot,out _),"build complete reviewed snapshot");
        Check(snapshot["AdminDisabledDestinations"] is JsonObject { Count:1 } &&
            snapshot["AdminMonitorProfiles"] is JsonObject { Count:1 } &&
            snapshot["AdminRealServers"] is JsonObject { Count:1 } &&
            snapshot["AdminServiceGroups"] is JsonObject { Count:1 },"all ADC sections copied");
        Check(FleetAdcContract.Validate(snapshot,new()) is null,"receiver accepts signed object snapshot");
        var legacy = JsonNode.Parse("""{"Routes":{},"Clusters":{}}""")!.AsObject();
        Check(FleetAdcContract.Validate(legacy,new()) is null,"legacy empty node compatible");
        Check(FleetAdcContract.Validate(legacy,snapshot) is not null,"legacy omission cannot erase node catalog");
        var bad = snapshot.DeepClone().AsObject();
        bad["AdminRealServers"] = new JsonObject();
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"dangling signed service-group member rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["AdminMonitorProfiles"] = new JsonObject();
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"dangling signed monitor reference rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["AdminDisabledDestinations"]!["missing::origin"] = new JsonObject { ["Address"]="https://app.invalid/" };
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"invalid disabled destination rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["Clusters"]!["pool"]!["Metadata"] = new JsonObject { ["ADC.Health.CompoundMode"]="AND" };
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"incomplete compound active config rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["Clusters"]!["pool"]!["SessionAffinity"] = new JsonObject { ["Enabled"]=true,["Policy"]="GatewayCoreExpiringCookie" };
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"invalid signed secure affinity rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["Routes"]!["web"]!["Metadata"] = new JsonObject { [ApplicationAccessPolicy.NetworksKey]="invalid" };
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"invalid signed route access rejected");
        var rules = new Dictionary<string,string> { [ApplicationAccessPolicy.HttpsKey]="true",
            [ApplicationAccessPolicy.NetworksKey]="192.0.2.0/24,2001:db8::/32" };
        Check(ApplicationAccessPolicy.TryParse(rules,out var access) &&
            access.Permits(true,System.Net.IPAddress.Parse("192.0.2.7")) &&
            access.Permits(true,System.Net.IPAddress.Parse("::ffff:192.0.2.7")) &&
            access.Permits(true,System.Net.IPAddress.Parse("2001:db8::7")) &&
            !access.Permits(false,System.Net.IPAddress.Parse("192.0.2.7")) &&
            !access.Permits(true,System.Net.IPAddress.Parse("198.51.100.7")) &&
            !access.Permits(true,null),"actual peer and TLS required; mapped IPv4 and IPv6 supported");
        rules[ApplicationAccessPolicy.NetworksKey]="0.0.0.0/0";
        Check(!ApplicationAccessPolicy.TryParse(rules,out _),"unbounded CIDR rejected");
        rules[ApplicationAccessPolicy.NetworksKey]="192.0.2.0/24,";
        Check(!ApplicationAccessPolicy.TryParse(rules,out _),"empty allowlist member rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["Routes"]!["web"]!["Metadata"] = new JsonObject { [ApplicationAccessPolicy.CompressionKey]="true" };
        Check(FleetAdcContract.Validate(bad,snapshot) is null,"signed public HTTP compression accepted");
        bad["Routes"]!["web"]!["Metadata"]![ApplicationAccessPolicy.HttpsKey] = "true";
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"HTTP compression and mandatory HTTPS conflict rejected");
        bad["Routes"]!["web"]!["Metadata"] = new JsonObject { [ApplicationAccessPolicy.CompressionKey]=true };
        Check(FleetAdcContract.Validate(bad,snapshot) is not null,"malformed signed compression policy rejected");
        bad = snapshot.DeepClone().AsObject();
        bad["Routes"]!["web"]!["Metadata"] = new JsonObject { [ApplicationAccessPolicy.MethodsKey]="GET,HEAD" };
        Check(FleetAdcContract.Validate(bad,snapshot) is null,"signed method allowlist accepted");
        Check(ApplicationAccessPolicy.TryParse(new Dictionary<string,string> { [ApplicationAccessPolicy.MethodsKey]="GET,HEAD" },out var methodPolicy) &&
            methodPolicy.PermitsMethod("GET") && methodPolicy.PermitsMethod("HEAD") &&
            !methodPolicy.PermitsMethod("POST") && !methodPolicy.PermitsMethod("get"),"method admission is exact and case sensitive");
        foreach (var invalid in new[] {"","GET,GET","GET,","get","TRACE","CONNECT","*"})
        {
            bad["Routes"]!["web"]!["Metadata"]![ApplicationAccessPolicy.MethodsKey] = invalid;
            Check(FleetAdcContract.Validate(bad,snapshot) is not null,"invalid method contract rejected: "+invalid);
        }
        using var key=ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub=key.ExportSubjectPublicKeyInfoPem();
        var trusted=new Dictionary<string,string> { [FleetConfigSignature.KeyIdFromPublicKey(pub)] = pub };
        var now=DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        const string tx="rollout_ADC12345678";
        var revision=new string('A',64);
        var signed=FleetConfigSignature.SignV2(key.ExportPkcs8PrivateKeyPem(),tx,revision,snapshot,now+120,1);
        Check(FleetConfigSignature.VerifyV2(trusted,tx,revision,snapshot,signed,now),"complete snapshot signature verified");
        var tampered=snapshot.DeepClone().AsObject();
        tampered["AdminRealServers"]!["app"]!["Address"]="https://changed.invalid/";
        Check(!FleetConfigSignature.VerifyV2(trusted,tx,revision,tampered,signed,now),"catalog mutation invalidates signature");
        var empty=JsonNode.Parse("""{"routes":{},"clusters":{},"disabled":{},"monitorProfiles":{},"realServers":{},"serviceGroups":{}}""")!.AsObject();
        Check(FleetAdcContract.TryBuildApproved(empty,snapshot,out var clear,out _) &&
            FleetAdcContract.Validate(clear,snapshot) is null,"explicit reviewed atomic removal accepted");
    }
}
