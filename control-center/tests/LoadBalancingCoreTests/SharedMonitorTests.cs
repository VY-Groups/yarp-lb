using System.Text.Json.Nodes;

internal static class SharedMonitorTests
{
    public static void Run()
    {
        static JsonObject Fixture() => JsonNode.Parse("""
        {"owner":{"HealthCheck":{"Active":{"Enabled":true,"Path":"/ready","Interval":"00:00:15","Timeout":"00:00:05","Policy":"RiseFall"}},"Metadata":{"RiseFall.Rise":"2"}},
         "member":{"HealthCheck":{"Active":{"Enabled":true,"Path":"/ready","Interval":"00:00:15","Timeout":"00:00:05","Policy":"RiseFall"}},"Metadata":{"RiseFall.Rise":"2","ADC.HealthMonitorSource":"owner"}}}
        """)!.AsObject();
        static void Expect(JsonObject clusters, bool valid, string name)
        {
            if ((SharedMonitorContract.Validate(clusters) is null) != valid)
                throw new Exception("Shared monitor contract failed: " + name);
            Console.WriteLine("PASS: shared monitor " + name);
        }
        Expect(Fixture(), true, "valid linked snapshot");
        var missing = Fixture(); missing.Remove("owner"); Expect(missing, false, "missing source");
        var cycle = Fixture(); cycle["owner"]!["Metadata"]![SharedMonitorContract.SourceKey] = "member"; Expect(cycle, false, "cycle");
        var self = Fixture(); self["member"]!["Metadata"]![SharedMonitorContract.SourceKey] = "member"; Expect(self, false, "self reference");
        var divergence = Fixture(); divergence["member"]!["HealthCheck"]!["Active"]!["Path"] = "/other"; Expect(divergence, false, "divergent snapshot");
        var disabled = Fixture(); disabled["owner"]!["HealthCheck"]!["Active"]!["Enabled"] = false; Expect(disabled, false, "disabled source");
        var threshold = Fixture(); threshold["member"]!["Metadata"]!["RiseFall.Rise"] = "3"; Expect(threshold, false, "divergent threshold");
        var timing = Fixture(); timing["owner"]!["HealthCheck"]!["Active"]!["Timeout"] = "00:00:30"; Expect(timing, false, "invalid timing");
        var unlink = Fixture(); unlink["member"]!["Metadata"]!.AsObject().Remove(SharedMonitorContract.SourceKey); unlink.Remove("owner"); Expect(unlink, true, "explicit unlink");
    }
}
