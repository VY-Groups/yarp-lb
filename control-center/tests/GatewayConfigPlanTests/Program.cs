using GatewayConfigPlan;

static void Check(bool ok, string message) { if (!ok) throw new InvalidOperationException(message); }
static string Doc(string routes = "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"/{**catch-all}\"}}", string address = "http://127.0.0.1:8080") =>
    $"{{\"schemaVersion\":1,\"routes\":{{{routes}}},\"clusters\":{{\"app\":{{\"Destinations\":{{\"one\":{{\"Address\":\"{address}\"}}}}}}}}}}";

var baseline = Doc();
var unchanged = PlanEngine.Build(baseline, baseline);
Check(unchanged.Status == "valid" && unchanged.Changes.Count == 0, "unchanged config should have an empty plan");
var changed = PlanEngine.Build(baseline, Doc(address: "https://127.0.0.1:8443"));
Check(changed.Changes.SequenceEqual([new PlanChange("update", "cluster:app")]), "address edit should report one cluster update by ID only");
Check(!System.Text.Json.JsonSerializer.Serialize(changed).Contains("127.0.0.1") &&
      !System.Text.Json.JsonSerializer.Serialize(changed).Contains("Revision"), "plan output must not include backend addresses or hashes");

foreach (var bad in new[]
{
    Doc(routes: "\"web\":{\"ClusterId\":\"missing\",\"Match\":{\"Path\":\"/\"}}"),
    Doc(address: "https://user:secret@example.test"),
    Doc(address: "https://example.test/path?token=secret"),
    Doc(routes: "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"relative\"}}"),
    Doc(routes: "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"/\"},\"Secret\":\"guessable\"}"),
    Doc().Replace("\"Destinations\":{", "\"Secret\":\"guessable\",\"Destinations\":{") ,
    Doc().Replace("\"Address\":\"http://127.0.0.1:8080\"", "\"Address\":\"http://127.0.0.1:8080\",\"HeaderValue\":\"secret\""),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":\"1\""),
    baseline.Replace("\"Path\":\"/{**catch-all}\"", "\"Path\":7"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"disabled\":\"malformed\"")
})
{
    try { PlanEngine.Build(baseline, bad); throw new InvalidOperationException("invalid input unexpectedly planned"); }
    catch (ArgumentException) { }
}

Console.WriteLine("PASS: versioned config plan validates references/origins, rejects unsupported schema and reports redacted deterministic changes");
