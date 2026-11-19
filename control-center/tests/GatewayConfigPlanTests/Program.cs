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

Console.WriteLine("PASS: standalone declarative validation and redacted deterministic config planning");

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
