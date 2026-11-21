using GatewayConfigPlan;
using System.Diagnostics;

static void Check(bool ok, string message) { if (!ok) throw new InvalidOperationException(message); }
static string Doc(string routes = "\"web\":{\"ClusterId\":\"app\",\"Match\":{\"Path\":\"/{**catch-all}\"}}", string address = "http://127.0.0.1:8080") =>
    $"{{\"schemaVersion\":1,\"routes\":{{{routes}}},\"clusters\":{{\"app\":{{\"Destinations\":{{\"one\":{{\"Address\":\"{address}\"}}}}}}}}}}";

var baseline = Doc();
var validation = PlanEngine.Validate(baseline);
var validationJson = System.Text.Json.JsonSerializer.Serialize(validation);
Check(validation.Status == "valid" && validation.SchemaVersion == 1 &&
      validation.RouteCount == 1 && validation.ClusterCount == 1 && validation.DestinationCount == 1,
      "standalone desired document should return its schema and bounded object counts");
Check(!validationJson.Contains("127.0.0.1") && !validationJson.Contains("catch-all") &&
      !validationJson.Contains("Address", StringComparison.OrdinalIgnoreCase),
      "validation summary must not disclose paths, backend origins, or config fields");
try { PlanEngine.Validate(baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":9")); throw new InvalidOperationException("unsupported schema unexpectedly validated"); }
catch (ArgumentException) { }

// Duplicate names are ambiguous in reviewed JSON even when their values agree.
// Reject case aliases and Unicode escape aliases before JsonNode last-key-wins
// materialization, both for validation and plan current/desired inputs.
foreach (var ambiguous in new[]
{
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
    baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schema\\u0056ersion\":1"),
    baseline.Replace("\"Path\":\"/{**catch-all}\"", "\"Path\":\"/admin\",\"Path\":\"/{**catch-all}\""),
    baseline.Replace("\"Address\":\"http://127.0.0.1:8080\"",
                     "\"Address\":\"http://evil.invalid/\",\"Address\":\"http://127.0.0.1:8080\"")
})
{
    Check(ThrowsAmbiguous(() => PlanEngine.Validate(ambiguous)),
          "ambiguous desired JSON must be refused");
    Check(ThrowsAmbiguous(() => PlanEngine.Build(baseline, ambiguous)),
          "ambiguous desired JSON must never produce a plan");
    Check(ThrowsAmbiguous(() => PlanEngine.Build(ambiguous, baseline)),
          "ambiguous current JSON must never produce a plan");
}

var desiredPath = Path.Combine(Path.GetTempPath(), $"gateway-config-plan-{Guid.NewGuid():N}.json");
try
{
    File.WriteAllText(desiredPath, baseline);
    var cli = RunCli("validate", desiredPath);
    Check(cli.ExitCode == 0 && cli.StdOut.Contains("\"RouteCount\": 1") &&
          cli.StdOut.Contains("\"DestinationCount\": 1") && !cli.StdOut.Contains("127.0.0.1"),
          "validate CLI reports safe counts without config values");
    File.WriteAllText(desiredPath, baseline.Replace("\"schemaVersion\":1", "\"schemaVersion\":9"));
    cli = RunCli("validate", desiredPath);
    Check(cli.ExitCode == 1 && cli.StdErr.Contains("schemaVersion must be 1"),
          "validate CLI exits nonzero for unsupported schema versions");
    File.WriteAllText(desiredPath, baseline.Replace("\"schemaVersion\":1",
        "\"schemaVersion\":1,\"schemaVersion\":9"));
    cli = RunCli("validate", desiredPath);
    Check(cli.ExitCode == 1 && cli.StdOut.Length == 0 &&
          !cli.StdErr.Contains("127.0.0.1"),
          "validate CLI rejects duplicate JSON without exposing gateway values");
    File.WriteAllText(desiredPath, new string(' ', 524289) + baseline);
    cli = RunCli("validate", desiredPath);
    Check(cli.ExitCode == 1 && cli.StdOut.Length == 0,
          "oversized planner file is rejected before unbounded read");
    File.WriteAllBytes(desiredPath, [0xC3, 0x28]); // Invalid UTF-8 continuation.
    cli = RunCli("validate", desiredPath);
    Check(cli.ExitCode == 1 && cli.StdOut.Length == 0 &&
          !cli.StdErr.Contains("System.Text.", StringComparison.Ordinal),
          "invalid UTF-8 is rejected without an unhandled exception trace");
}
finally { File.Delete(desiredPath); }

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

var bundle = """
{
  "gatewayClass": {"apiVersion":"gateway.networking.k8s.io/v1","kind":"GatewayClass","metadata":{"name":"lab"},"spec":{"controllerName":"gatewaycore.example/offline"}},
  "gateway": {"apiVersion":"gateway.networking.k8s.io/v1","kind":"Gateway","metadata":{"name":"edge","namespace":"apps"},"spec":{"gatewayClassName":"lab","listeners":[{"name":"http","protocol":"HTTP","port":80,"allowedRoutes":{"namespaces":{"from":"Same"}}}]}},
  "httpRoutes": [{"apiVersion":"gateway.networking.k8s.io/v1","kind":"HTTPRoute","metadata":{"name":"web","namespace":"apps"},"spec":{"parentRefs":[{"name":"edge","sectionName":"http"}],"rules":[{"matches":[{"path":{"type":"PathPrefix","value":"/"}}],"backendRefs":[{"name":"api","port":8080}]}]}}],
  "services": [{"apiVersion":"v1","kind":"Service","metadata":{"name":"api","namespace":"apps"},"spec":{"type":"ClusterIP","ports":[{"port":8080,"protocol":"TCP","appProtocol":"http"}]}}]
}
""";
var imported = GatewayApiImport.Translate(bundle);
Check(imported["routes"]!["web"]!["Match"]!["Path"]!.ToString() == "/{**catch-all}" &&
      imported["clusters"]!["svc-api-8080"]!["Destinations"]!["service"]!["Address"]!.ToString() ==
        "http://api.apps.svc.cluster.local:8080/", "Gateway API root prefix maps to explicit same namespace service origin");
Check(PlanEngine.Validate(imported.ToJsonString()).RouteCount == 1 &&
      PlanEngine.Build(imported.ToJsonString(), GatewayApiImport.Translate(bundle).ToJsonString()).Changes.Count == 0,
      "Gateway API import is deterministic and passes supported declarative planner");
foreach (var bad in new[] {
    bundle.Replace("\"from\":\"Same\"", "\"from\":\"All\""),
    bundle.Replace("\"sectionName\":\"http\"", "\"sectionName\":\"other\""),
    bundle.Replace("\"gatewayClassName\":\"lab\"", "\"gatewayClassName\":\"other\""),
    bundle.Replace("\"name\":\"web\",\"namespace\":\"apps\"", "\"name\":\"web\",\"namespace\":\"other\""),
    bundle.Replace("\"name\":\"api\",\"namespace\":\"apps\"", "\"name\":\"api\",\"namespace\":\"other\""),
    bundle.Replace("\"name\":\"api\",\"port\":8080", "\"name\":\"api\",\"port\":8081"),
    bundle.Replace("\"name\":\"api\",\"port\":8080", "\"name\":\"api\",\"port\":8080,\"namespace\":\"other\""),
    bundle.Replace("\"type\":\"PathPrefix\"", "\"type\":\"Exact\""),
    bundle.Replace("\"value\":\"/\"", "\"value\":\"/api\""),
    bundle.Replace("\"protocol\":\"HTTP\"", "\"protocol\":\"HTTPS\""),
    bundle.Replace("\"type\":\"ClusterIP\"", "\"type\":\"ExternalName\""),
    bundle.Replace("\"appProtocol\":\"http\"", "\"appProtocol\":\"h2c\""),
    bundle.Replace("\"sectionName\":\"http\"", "\"sectionName\":\"http\",\"SectionName\":\"http\""),
    bundle.Replace("\"backendRefs\":[", "\"filters\":[],\"backendRefs\":["),
    bundle.Replace("\"kind\":\"HTTPRoute\"", "\"kind\":\"TLSRoute\""),
    new string(' ',524289) + bundle
})
{
    try { GatewayApiImport.Translate(bad); throw new InvalidOperationException("Unsupported Gateway API import succeeded"); }
    catch (ArgumentException) { }
}
var bundlePath = Path.Combine(Path.GetTempPath(), $"gateway-api-{Guid.NewGuid():N}.json");
try
{
    File.WriteAllText(bundlePath,bundle);
    var cli = RunCli("import-gateway-api",bundlePath);
    Check(cli.ExitCode == 0 && System.Text.Json.Nodes.JsonNode.DeepEquals(
        System.Text.Json.Nodes.JsonNode.Parse(cli.StdOut),imported), "offline import CLI produces validated desired JSON");
    File.WriteAllText(bundlePath,bundle.Replace("\"from\":\"Same\"", "\"from\":\"All\""));
    cli = RunCli("import-gateway-api",bundlePath);
    Check(cli.ExitCode == 1 && cli.StdOut.Length == 0 && !cli.StdErr.Contains("api.apps"),
        "unsafe import exits nonzero without partially translated config");
}
finally { File.Delete(bundlePath); }

Console.WriteLine("PASS: standalone declarative validation, redacted deterministic planning and strict Gateway API import");

static bool ThrowsAmbiguous(Action action)
{
    try { action(); return false; }
    catch (ArgumentException) { return true; }
}

static (int ExitCode, string StdOut, string StdErr) RunCli(params string[] args)
{
    var start = new ProcessStartInfo("dotnet")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false
    };
    start.ArgumentList.Add(Path.Combine(AppContext.BaseDirectory, "GatewayConfigPlan.dll"));
    foreach (var arg in args) start.ArgumentList.Add(arg);
    using var process = Process.Start(start) ?? throw new InvalidOperationException("Could not launch config planner CLI");
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    if (!process.WaitForExit(10_000))
    {
        process.Kill(entireProcessTree: true);
        throw new TimeoutException("Config planner CLI did not exit within 10 seconds");
    }
    return (process.ExitCode, stdout.GetAwaiter().GetResult(), stderr.GetAwaiter().GetResult());
}
