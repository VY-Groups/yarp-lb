using GatewayConfigPlan;

static void Check(bool ok, string message) { if (!ok) throw new InvalidOperationException(message); }
static string Doc(string routes = "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"/{**catch-all}\"}}", string address = "http://127.0.0.1:8080") =>
    $"{{\"schemaVersion\":1,\"routes\":{{{routes}}},\"clusters\":{{\"app\":{{\"Destinations\":{{\"one\":{{\"Address\":\"{address}\"}}}}}}}},\"disabled\":{{}}}}";

var baseline = Doc();
var unchanged = PlanEngine.Build(baseline, baseline);
Check(unchanged.Status == "valid" && unchanged.Changes.Count == 0, "unchanged config should have an empty plan");
var changed = PlanEngine.Build(baseline, Doc(address: "https://127.0.0.1:8443"));
Check(changed.Changes.SequenceEqual([new PlanChange("update", "cluster:app")]), "address edit should report one cluster update by ID only");
Check(!System.Text.Json.JsonSerializer.Serialize(changed).Contains("127.0.0.1"), "plan output must not include backend addresses");

foreach (var bad in new[]
{
    Doc(routes: "\"web\":{\"ClusterId\":\"missing\",\"Match\":{\"Path\":\"/\"}}"),
    Doc(address: "https://user:secret@example.test"),
    Doc(routes: "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"relative\"}}"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
    baseline.Replace("\"Path\":\"/{**catch-all}\"", "\"Path\":7"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"secret\":\"must-not-be-accepted\"")
})
{
    try { PlanEngine.Build(baseline, bad); throw new InvalidOperationException("invalid input unexpectedly planned"); }
    catch (ArgumentException) { }
}

Console.WriteLine("PASS: versioned config plan validates references/origins, rejects unsupported schema and reports redacted deterministic changes");
