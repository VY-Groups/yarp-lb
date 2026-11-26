using System.Text.Json.Nodes;
internal static class RealServerCatalogTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("Real server catalog: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var payload = JsonNode.Parse("""
        {"realServers":{"app-01":{"Address":"https://app.example.invalid:8443/api/","Description":"Application server"}}}
        """)!.AsObject();
        Check(RealServerCatalog.Validate(payload) is null, "valid named server");
        Check(RealServerCatalog.Validate(new JsonObject()) is null, "legacy omission");
        foreach (var value in new[] {"ftp://example.invalid/", "https://u:p@example.invalid/", "https://example.invalid/?a=b", "https://example.invalid/#x", "https://example.invalid", "https://example.invalid/\\", "https://example.invalid/\n"})
            Check(!RealServerCatalog.ValidOrigin(value), "invalid origin rejected");
        var servers = payload["realServers"]!.AsObject();
        servers["APP-01"] = servers["app-01"]!.DeepClone();
        Check(RealServerCatalog.Validate(payload) is not null, "case-insensitive duplicate rejected");
        servers.Remove("APP-01");
        servers["app-01"]!["Secret"] = "invalid";
        Check(RealServerCatalog.Validate(payload) is not null, "unexpected field rejected");
        servers["app-01"]!.AsObject().Remove("Secret");
        Check(RealServerCatalog.Validate(payload) is null, "restored valid catalog");
    }
}
