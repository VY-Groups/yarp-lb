using System.Text.Json.Nodes;
internal static class MonitorProfileRegistryTests
{
    public static void Run()
    {
        static void Check(bool valid, string label)
        {
            if (!valid) throw new Exception("Monitor registry: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var payload = JsonNode.Parse("""
        {"monitorProfiles":{"web":{"Active":{"Enabled":true,"Path":"/ready","Interval":"00:00:10","Timeout":"00:00:03","Policy":"RiseFall"},"Metadata":{"RiseFall.Rise":"2","RiseFall.Fall":"3","ADC.Health.CompoundMode":"AND","ADC.Health.SecondaryPath":"/deps"}}}}
        """)!.AsObject();
        Check(MonitorProfileRegistry.Validate(new JsonObject()) is null, "legacy omission preserves registry");
        Check(MonitorProfileRegistry.Validate(payload) is null, "valid reusable compound profile");
        var profile = payload["monitorProfiles"]!["web"]!.AsObject();
        var meta = profile["Metadata"]!.AsObject();
        meta["BackendClientCertificateThumbprint"] = "no";
        Check(MonitorProfileRegistry.Validate(payload) is not null, "unrelated security metadata rejected");
        meta.Remove("BackendClientCertificateThumbprint");
        meta["ADC.Health.SecondaryPath"] = "/ready";
        Check(MonitorProfileRegistry.Validate(payload) is not null, "duplicate readiness path rejected");
        meta["ADC.Health.SecondaryPath"] = "/deps";
        profile["Active"]!["Timeout"] = "00:00:20";
        Check(MonitorProfileRegistry.Validate(payload) is not null, "timeout exceeds interval rejected");
        profile["Active"]!["Timeout"] = "00:00:03";
        payload["monitorProfiles"]!["WEB"] = profile.DeepClone();
        Check(MonitorProfileRegistry.Validate(payload) is not null, "case-colliding IDs rejected");
        payload["monitorProfiles"]!.AsObject().Remove("WEB");
        meta["RiseFall.Rise"] = "11";
        Check(MonitorProfileRegistry.Validate(payload) is not null, "out of bounds threshold rejected");
        meta["RiseFall.Rise"] = "2";
        Check(MonitorProfileRegistry.Validate(payload) is null, "valid registry remains accepted");
    }
}
