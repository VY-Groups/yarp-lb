using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

// Run from repository root: dotnet run --project tests/L7/Acceptance -c Release --no-build
var repo = args.Length >= 1 ? Path.GetFullPath(args[0]) : Directory.GetCurrentDirectory();
var holdForExternalLoad = args.Skip(1).Contains("--hold", StringComparer.Ordinal);
var backDll = Path.Combine(repo, "tests", "L7", "BackendLab", "bin", "Release", "net10.0", "BackendLab.dll");
var gateDll = Path.Combine(repo, "tests", "L7", "GatewayLab", "bin", "Release", "net10.0", "GatewayLab.dll");
var gatewayDir = Path.GetDirectoryName(gateDll)!;
var output = Path.Combine(repo, "artifacts", "l7");
Directory.CreateDirectory(output);
var stages = new List<object>();
var processes = new List<Process>();
var logs = new List<Task>();
var options = new JsonSerializerOptions { WriteIndented = true, PropertyNameCaseInsensitive = true };
using var client = new HttpClient(new SocketsHttpHandler {
    UseProxy = false,
    PooledConnectionLifetime = TimeSpan.FromSeconds(2)
}) { Timeout = TimeSpan.FromSeconds(22) };
const string proxy = "http://127.0.0.1:18080";
const string aUrl = "http://127.0.0.1:18081";
const string bUrl = "http://127.0.0.1:18082";

Process Start(string dll, string label, params string[] extra)
{
    var p = new Process();
    p.StartInfo = new ProcessStartInfo("dotnet") {
        WorkingDirectory = Path.GetDirectoryName(dll)!,
        UseShellExecute = false,
        CreateNoWindow = true,
        RedirectStandardOutput = true,
        RedirectStandardError = true
    };
    p.StartInfo.ArgumentList.Add(dll);
    foreach (var arg in extra) p.StartInfo.ArgumentList.Add(arg);
    if (!p.Start()) throw new InvalidOperationException("Failed to start " + label);
    processes.Add(p);
    logs.Add(Task.Run(async () =>
        await File.WriteAllTextAsync(Path.Combine(output, label + ".stdout.log"),
            await p.StandardOutput.ReadToEndAsync())));
    logs.Add(Task.Run(async () =>
        await File.WriteAllTextAsync(Path.Combine(output, label + ".stderr.log"),
            await p.StandardError.ReadToEndAsync())));
    return p;
}

async Task<bool> IsStatus(string url, HttpStatusCode status)
{
    try { using var res = await client.GetAsync(url); return res.StatusCode == status; }
    catch { return false; }
}

async Task WaitFor(string name, Func<Task<bool>> condition, int seconds = 30)
{
    var sw = Stopwatch.StartNew();
    while (sw.Elapsed < TimeSpan.FromSeconds(seconds))
    {
        if (await condition()) return;
        await Task.Delay(350);
    }
    throw new Exception("Timed out: " + name);
}

async Task SetReady(string url, bool ready)
{
    using var res = await client.PostAsync($"{url}/lab/ready/{ready.ToString().ToLowerInvariant()}", null);
    res.EnsureSuccessStatusCode();
}

async Task<int> InFlight(string url)
{
    using var res = await client.GetAsync(url + "/lab/inflight");
    res.EnsureSuccessStatusCode();
    using var json = JsonDocument.Parse(await res.Content.ReadAsStringAsync());
    return json.RootElement.GetProperty("count").GetInt32();
}

void Configure(string policy, int aWeight, int bWeight, bool drainA = false, int slowStartA = 0, bool drainKillA = false)
{
    var config = new {
        ReverseProxy = new {
            Routes = new Dictionary<string, object> {
                ["api"] = new { ClusterId = "api", Match = new { Path = "/api/{**catch-all}" } },
                ["kill"] = new { ClusterId = "kill", Match = new { Path = "/kill/{**catch-all}" } }
            },
            Clusters = new Dictionary<string, object> {
                ["api"] = new {
                    LoadBalancingPolicy = policy,
                    HealthCheck = new {
                        AvailableDestinationsPolicy = "HealthyAndUnknown",
                        Active = new {
                            Enabled = true, Interval = "00:00:01", Timeout = "00:00:01",
                            Policy = "ConsecutiveFailures", Path = "/health/ready"
                        }
                    },
                    Metadata = new Dictionary<string,string> {
                        ["ConsecutiveFailuresHealthPolicy.Threshold"] = "1"
                    },
                    Destinations = new Dictionary<string, object> {
                        ["A"] = new { Address = aUrl + "/", Metadata = new Dictionary<string,string> { ["Weight"] = aWeight.ToString(), ["TrafficState"] = drainA ? "draining" : "active", ["SlowStartSeconds"] = slowStartA.ToString() } },
                        ["B"] = new { Address = bUrl + "/", Metadata = new Dictionary<string,string> { ["Weight"] = bWeight.ToString() } }
                    }
                },
                ["kill"] = new { Destinations = new Dictionary<string, object> {
                    ["A"] = new { Address = aUrl + "/", Metadata = new Dictionary<string,string> { ["TrafficState"] = drainKillA ? "draining" : "active" } }
                } }
            }
        }
    };
    var path = Path.Combine(gatewayDir, "lab.json");
    var staged = path + ".next";
    File.WriteAllText(staged, JsonSerializer.Serialize(config, options), Encoding.UTF8);
    if (File.Exists(path)) File.Move(staged, path, overwrite: true);
    else File.Move(staged, path);
}

async Task<SampleResult> Sample(int count, int concurrency = 24, int pacingMs = 0)
{
    var nodes = new ConcurrentDictionary<string, int>();
    var codes = new ConcurrentDictionary<int, int>();
    await Parallel.ForEachAsync(Enumerable.Range(0, count),
        new ParallelOptions { MaxDegreeOfParallelism = concurrency }, async (_, _) =>
        {
            if (pacingMs > 0) await Task.Delay(pacingMs);
            try {
                using var response = await client.GetAsync(proxy + "/api/identity");
                codes.AddOrUpdate((int)response.StatusCode, 1, (_, n) => n + 1);
                if (response.IsSuccessStatusCode) {
                    using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
                    var node = json.RootElement.GetProperty("node").GetString() ?? "?";
                    nodes.AddOrUpdate(node, 1, (_, n) => n + 1);
                }
            }
            catch (HttpRequestException) { codes.AddOrUpdate(0, 1, (_, n) => n + 1); }
            catch (TaskCanceledException) { codes.AddOrUpdate(0, 1, (_, n) => n + 1); }
        });
    return new SampleResult(count, nodes.ToDictionary(x => x.Key, x => x.Value),
        codes.ToDictionary(x => x.Key, x => x.Value));
}

void Require(bool okay, string name)
{
    if (!okay) throw new InvalidOperationException("FAIL: " + name);
    Console.WriteLine("PASS: " + name);
}
void Record(string name, object details)
{
    stages.Add(new { name, details, utc = DateTimeOffset.UtcNow });
    Console.WriteLine("PASS STAGE: " + name);
}
async Task<bool> RoutesOnly(string node)
{
    // Two independent batches avoid accidental success from an 80%-weighted
    // destination before the asynchronous active health probe settles.
    var first = await Sample(80, 12);
    if (first.Success != 80 || first.Nodes.GetValueOrDefault(node) != 80) return false;
    await Task.Delay(300);
    var second = await Sample(80, 12);
    return second.Success == 80 && second.Nodes.GetValueOrDefault(node) == 80;
}

void CheckRendezvous()
{
    var oldIds = new[] { "A", "B", "C" };
    var newIds = new[] { "A", "B" };
    var moved = 0;
    var assignedRemoved = 0;
    for (var i = 0; i < 5000; i++)
    {
        var key = "client-" + i;
        var before = oldIds[LoadBalancingCore.PickRendezvousIndex(key, oldIds, new[] {1,1,1})];
        var after = newIds[LoadBalancingCore.PickRendezvousIndex(key, newIds, new[] {1,1})];
        if (before == "C") assignedRemoved++;
        if (before != after) {
            moved++;
            if (before != "C") throw new InvalidOperationException("Surviving client moved unexpectedly: " + key);
        }
    }
    Require(moved == assignedRemoved && moved is >= 1200 and <= 2100,
        "consistent hashing moves only removed node's clients");
    Record("rendezvous-remapping", new { moved, total = 5000 });
}

var passed = false;
try
{
    Require(File.Exists(backDll) && File.Exists(gateDll), "both compiled binaries exist");
    if (holdForExternalLoad)
    {
        Configure("WeightedRandom", 70, 30);
        _ = Start(backDll, "load-A", "18081", "A");
        _ = Start(backDll, "load-B", "18082", "B");
        await WaitFor("load backend A", () => IsStatus(aUrl + "/health/ready", HttpStatusCode.OK));
        await WaitFor("load backend B", () => IsStatus(bUrl + "/health/ready", HttpStatusCode.OK));
        _ = Start(gateDll, "load-gateway");
        await WaitFor("load proxy", () => IsStatus(proxy + "/lab/ping", HttpStatusCode.OK));
        Console.WriteLine("LOAD_RIG_READY");
        await Task.Delay(TimeSpan.FromMinutes(4));
        return 0;
    }
    Configure("WeightedRandom", 80, 20);
    var backendA = Start(backDll, "backend-A", "18081", "A");
    _ = Start(backDll, "backend-B", "18082", "B");
    await WaitFor("backend A", () => IsStatus(aUrl + "/health/ready", HttpStatusCode.OK));
    await WaitFor("backend B", () => IsStatus(bUrl + "/health/ready", HttpStatusCode.OK));
    _ = Start(gateDll, "gateway");
    await WaitFor("gateway", () => IsStatus(proxy + "/lab/ping", HttpStatusCode.OK));
    await Task.Delay(2500);

    var weighted = await Sample(4000);
    Require(weighted.Success == 4000, "4,000 weighted HTTP requests succeeded");
    var aPercent = 100.0 * weighted.Nodes.GetValueOrDefault("A") / 4000;
    Require(aPercent is >= 75 and <= 85, $"80:20 ratio in tolerance: A={aPercent:F2}%");
    Record("weighted-80-20", new { aPercent, weighted });

    Configure("WeightedRandom", 80, 20, drainA: true);
    await Task.Delay(1600);
    var drained = await Sample(300);
    Require(drained.Success == 300 && drained.Nodes.GetValueOrDefault("B") == 300,
        "drained A receives no NEW requests");
    Record("drain-new-requests", drained);
    Configure("WeightedRandom", 80, 20);
    await Task.Delay(1600);
    var backFromDrain = await Sample(400);
    Require(backFromDrain.Success == 400 && backFromDrain.Nodes.ContainsKey("A"), "un-drained A re-enters pool");
    Record("drain-restore", backFromDrain);

    var longRequest = client.GetAsync(proxy + "/kill/slow");
    await WaitFor("in-flight request begins on A", async () => await InFlight(aUrl) > 0);
    Configure("WeightedRandom", 80, 20, drainKillA: true);
    await Task.Delay(1700);
    using (var refused = await client.GetAsync(proxy + "/kill/slow"))
        Require(refused.StatusCode == HttpStatusCode.ServiceUnavailable,
            "draining blocks NEW requests even while an existing one remains in flight");
    using (var completed = await longRequest)
        Require(completed.IsSuccessStatusCode, "previously forwarded request completes during drain");
    Record("inflight-preserved-during-drain", new { completed = true, newTraffic = 503 });
    Configure("WeightedRandom", 80, 20);
    await Task.Delay(1600);
    Configure("WeightedRandom", 80, 20, slowStartA: 10);
    await Task.Delay(1500);
    var early = await Sample(500);
    Require(early.Success == 500 && early.Nodes.GetValueOrDefault("A") < 350,
        "slow-start limits fresh A during warmup");
    await Task.Delay(10500);
    var late = await Sample(1000);
    var lateAPercent = 100.0 * late.Nodes.GetValueOrDefault("A") / 1000;
    Require(late.Success == 1000 && lateAPercent is >= 72 and <= 88,
        $"slow-start returns to 80 percent A: {lateAPercent:F2}%");
    Record("slow-start", new { early, lateAPercent });


    Configure("SourceIpHash", 80, 20);
    await Task.Delay(2500);
    var sticky = await Sample(300);
    Require(sticky.Success == 300 && sticky.Nodes.Count == 1,
        "same TCP client IP remains on one backend for 300 requests");
    Record("source-ip-affinity", sticky);
    CheckRendezvous();

    Configure("WeightedRandom", 80, 20);
    await Task.Delay(2500);
    var ongoing = Sample(5000, concurrency: 12, pacingMs: 12);
    await Task.Delay(1100);
    Configure("WeightedRandom", 20, 80);
    var during = await ongoing;
    Require(during.Success == 5000, "5,000 requests succeeded during config hot reload");
    Record("hot-reload-under-load", during);
    await Task.Delay(2500);
    var reversed = await Sample(3000);
    Require(reversed.Success == 3000, "3,000 requests succeeded after weight change");
    var bPercent = 100.0 * reversed.Nodes.GetValueOrDefault("B") / 3000;
    Require(bPercent is >= 75 and <= 85, $"20:80 ratio in tolerance: B={bPercent:F2}%");
    Record("weighted-20-80", new { bPercent, reversed });

    await SetReady(aUrl, false);
    await WaitFor("A becomes unhealthy", () => RoutesOnly("B"));
    var failedOver = await Sample(150);
    Require(failedOver.Success == 150 && failedOver.Nodes.GetValueOrDefault("B") == 150,
        "unhealthy A removed from traffic selection");
    Record("health-failover", failedOver);
    await SetReady(aUrl, true);
    await WaitFor("A recovery", async () => (await Sample(100)).Nodes.ContainsKey("A"));
    Record("health-recovery", new { recovered = true });

    await SetReady(aUrl, false);
    await SetReady(bUrl, false);
    await WaitFor("both unavailable -> 503", () => IsStatus(proxy + "/api/identity", HttpStatusCode.ServiceUnavailable));
    Record("all-backends-down", new { status = 503 });
    await SetReady(aUrl, true);
    await SetReady(bUrl, true);
    await WaitFor("both recovered", async () => (await Sample(100)).Nodes.Count == 2);

    var slow = client.GetAsync(proxy + "/kill/slow");
    await WaitFor("slow request started", async () => await InFlight(aUrl) > 0, 10);
    backendA.Kill(entireProcessTree: true);
    await backendA.WaitForExitAsync();
    var falselySucceeded = false;
    try { using var r = await slow; falselySucceeded = r.IsSuccessStatusCode; }
    catch (Exception e) when (e is HttpRequestException or TaskCanceledException or IOException) { }
    Require(!falselySucceeded, "interrupted mid-request transaction did not report success");
    await WaitFor("backend B serves after process loss", () => RoutesOnly("B"));
    Record("mid-request-backend-death", new { interrupted = true });
    _ = Start(backDll, "backend-A-restarted", "18081", "A");
    await WaitFor("A restarted", () => IsStatus(aUrl + "/health/ready", HttpStatusCode.OK));
    await WaitFor("A returned to YARP pool", async () => (await Sample(100)).Nodes.ContainsKey("A"));
    Record("backend-process-recovery", new { recovered = true });
    passed = true;
    Console.WriteLine("ALL L7 ACCEPTANCE TESTS PASSED");
}
catch (Exception error)
{
    Console.Error.WriteLine("L7 ACCEPTANCE FAILED: " + error);
    stages.Add(new { name = "failure", error = error.ToString(), utc = DateTimeOffset.UtcNow });
}
finally
{
    foreach (var p in processes.AsEnumerable().Reverse())
    {
        try { if (!p.HasExited) p.Kill(entireProcessTree: true); p.WaitForExit(6000); }
        catch (Exception e) { Console.Error.WriteLine("Cleanup warning: " + e.Message); }
    }
    try { await Task.WhenAll(logs); } catch {}
    File.WriteAllText(Path.Combine(output, "lab-results.json"),
        JsonSerializer.Serialize(new { passed, stages, completedAt = DateTimeOffset.UtcNow }, options));
}
return passed ? 0 : 1;

record SampleResult(int Requested, Dictionary<string, int> Nodes, Dictionary<int, int> HttpCodes)
{
    [JsonIgnore] public int Success => Nodes.Values.Sum();
}
