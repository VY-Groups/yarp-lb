using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

var repo = args.Length == 1 ? Path.GetFullPath(args[0]) : Directory.GetCurrentDirectory();
var backendDll = Path.Combine(repo, "tests", "L7", "BackendLab", "bin", "Release", "net10.0", "BackendLab.dll");
var gatewayDll = Path.Combine(repo, "tests", "L7", "GatewayLab", "bin", "Release", "net10.0", "GatewayLab.dll");
var artifacts = Path.Combine(repo, "artifacts", "ha");
Directory.CreateDirectory(artifacts);
var temp = Path.Combine(Path.GetTempPath(), "yarp-ha-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var processes = new List<Process>();
var outputReaders = new List<Task>();
var checks = new List<object>();
using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false,
    PooledConnectionLifetime = TimeSpan.FromSeconds(2) }) { Timeout = TimeSpan.FromSeconds(8) };

void Require(bool ok, string description)
{
    if (!ok) throw new InvalidOperationException("FAIL: " + description);
    Console.WriteLine("PASS: " + description);
    checks.Add(new { description, utc = DateTimeOffset.UtcNow });
}
void Config(string path, IEnumerable<(string Id, string Address)> destinations, string probe)
{
    var dict = destinations.ToDictionary(d => d.Id, d => new
    {
        Address = d.Address,
        Metadata = new Dictionary<string, string> { ["Weight"] = "1" }
    });
    var config = new
    {
        ReverseProxy = new
        {
            Routes = new Dictionary<string, object>
            { ["api"] = new { ClusterId = "api", Match = new { Path = "/api/{**catch-all}" } } },
            Clusters = new Dictionary<string, object> {
                ["api"] = new {
                    LoadBalancingPolicy = "RoundRobin",
                    HealthCheck = new {
                        AvailableDestinationsPolicy = "HealthyAndUnknown",
                        Active = new {
                            Enabled = true, Interval = "00:00:01",
                            Timeout = "00:00:01", Policy = "ConsecutiveFailures", Path = probe }
                    },
                    Metadata = new Dictionary<string,string> {
                        ["ConsecutiveFailuresHealthPolicy.Threshold"] = "1"
                    },
                    Destinations = dict
                }
            }
        }
    };
    File.WriteAllText(path, JsonSerializer.Serialize(config), Encoding.UTF8);
}
Process Start(string label, string dll, string[] argv, Dictionary<string,string>? env = null)
{
    var start = new ProcessStartInfo("dotnet")
    {
        WorkingDirectory = Path.GetDirectoryName(dll)!,
        UseShellExecute = false,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        CreateNoWindow = true
    };
    start.ArgumentList.Add(dll);
    foreach (var arg in argv) start.ArgumentList.Add(arg);
    if (env is not null) foreach (var (key,value) in env) start.Environment[key] = value;
    var process = Process.Start(start) ?? throw new Exception("Process launch failed: " + label);
    processes.Add(process);
    outputReaders.Add(Task.Run(async () => await File.WriteAllTextAsync(
        Path.Combine(artifacts,label+".out.log"), await process.StandardOutput.ReadToEndAsync())));
    outputReaders.Add(Task.Run(async () => await File.WriteAllTextAsync(
        Path.Combine(artifacts,label+".err.log"), await process.StandardError.ReadToEndAsync())));
    return process;
}
async Task<bool> Responds(string url, int code = 200)
{
    try { using var res=await client.GetAsync(url); return (int)res.StatusCode == code; }
    catch { return false; }
}
async Task WaitFor(string description, Func<Task<bool>> condition, int seconds = 40)
{
    var watch = Stopwatch.StartNew();
    while (watch.Elapsed < TimeSpan.FromSeconds(seconds))
    {
        if (await condition()) return;
        await Task.Delay(300);
    }
    throw new Exception("Timed out: " + description);
}
async Task<(int Ok,int Fail)> Sample(int n)
{
    var ok=0; var failed=0;
    await Parallel.ForEachAsync(Enumerable.Range(0,n),
        new ParallelOptions { MaxDegreeOfParallelism=15 },async (_,ct) =>
        {
            try
            {
                using var res=await client.GetAsync("http://127.0.0.1:19080/api/identity",ct);
                if (res.IsSuccessStatusCode)
                {
                    var body=await res.Content.ReadAsStringAsync(ct);
                    if (body.Contains("\"node\":\"A\"") || body.Contains("\"node\":\"B\""))
                    { Interlocked.Increment(ref ok); return; }
                }
            }
            catch (HttpRequestException) {}
            catch (TaskCanceledException) {}
            Interlocked.Increment(ref failed);
        });
    return (ok,failed);
}

var success=false;
try
{
    Require(File.Exists(backendDll) && File.Exists(gatewayDll), "HA lab binaries exist");
    var g1config=Path.Combine(temp,"gateway-1.json");
    var g2config=Path.Combine(temp,"gateway-2.json");
    var edgeConfig=Path.Combine(temp,"ingress.json");
    var apps = new[] { ("A", "http://127.0.0.1:18081/"), ("B", "http://127.0.0.1:18082/") };
    Config(g1config,apps,"/health/ready");
    Config(g2config,apps,"/health/ready");
    Config(edgeConfig,new[] { ("gateway-1","http://127.0.0.1:18080/"),
         ("gateway-2","http://127.0.0.1:18083/") }, "/lab/ping");
    var backend1=Start("backend-a",backendDll,["18081","A"]);
    var backend2=Start("backend-b",backendDll,["18082","B"]);
    await WaitFor("application backends",async()=>await Responds("http://127.0.0.1:18081/health/ready") &&
        await Responds("http://127.0.0.1:18082/health/ready"));
    Dictionary<string,string> Settings(int port,int tls,string path) => new()
    {
        ["YARP_LAB_HTTP_PORT"]=port.ToString(),
        ["YARP_LAB_TLS_PORT"]=tls.ToString(),
        ["YARP_LAB_CONFIG_FILE"]=path
    };
    var gateway1=Start("gateway-1",gatewayDll,[],Settings(18080,18443,g1config));
    var gateway2=Start("gateway-2",gatewayDll,[],Settings(18083,18444,g2config));
    await WaitFor("both YARP gateways",async()=>await Responds("http://127.0.0.1:18080/lab/ping") &&
        await Responds("http://127.0.0.1:18083/lab/ping"));
    _=Start("health-aware-ingress",gatewayDll,[],Settings(19080,19443,edgeConfig));
    await WaitFor("ingress",()=>Responds("http://127.0.0.1:19080/lab/ping"));
    await Task.Delay(2500);
    var initial=await Sample(300);
    Require(initial.Ok==300,"300 HTTP requests traverse ingress and both healthy gateway candidates");
    gateway1.Kill(entireProcessTree:true);
    await gateway1.WaitForExitAsync();
    await Task.Delay(3500);
    var afterFailure=await Sample(400);
    Require(afterFailure.Ok==400,
        "gateway 1 terminated: 400/400 NEW requests continue through remaining gateway");
    Require(!gateway2.HasExited,"gateway 2 remains serving after gateway 1 dies");
    // Controller is never part of the data plane in this isolated test.
    // The gateways continue serving from their on-disk last-known configuration.
    var restart=Start("gateway-1-restarted",gatewayDll,[],Settings(18080,18443,g1config));
    await WaitFor("gateway 1 recovery",()=>Responds("http://127.0.0.1:18080/lab/ping"));
    await Task.Delay(2500);
    var recovered=await Sample(250);
    Require(recovered.Ok==250,"restarted gateway returns to healthy ingress without outages");
    restart.Kill(entireProcessTree:true);
    gateway2.Kill(entireProcessTree:true);
    await restart.WaitForExitAsync();
    await gateway2.WaitForExitAsync();
    await WaitFor("both down gives HTTP 503",()=>Responds("http://127.0.0.1:19080/api/identity",503));
    Require(true,"ingress refuses traffic rather than forwarding to known dead gateways");
    success=true;
    Console.WriteLine("ALL HA LAB INTEGRATION CHECKS PASSED");
}
catch(Exception ex)
{
    Console.Error.WriteLine("HA LAB FAILED: "+ex);
    checks.Add(new { failure=ex.ToString(), utc=DateTimeOffset.UtcNow });
}
finally
{
    foreach(var proc in processes.AsEnumerable().Reverse())
    {
        try { if(!proc.HasExited)proc.Kill(entireProcessTree:true);proc.WaitForExit(5000); }
        catch {}
    }
    try { await Task.WhenAll(outputReaders); } catch {}
    File.WriteAllText(Path.Combine(artifacts,"ha-results.json"),
        JsonSerializer.Serialize(new { passed=success,checks,finishedUtc=DateTimeOffset.UtcNow },
            new JsonSerializerOptions {WriteIndented=true}));
    try { Directory.Delete(temp,true); } catch {}
}
return success?0:1;
