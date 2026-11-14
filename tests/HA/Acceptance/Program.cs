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
void Config(string path, IEnumerable<(string Id, string Address)> destinations,
    string probe, bool explicitPanic = false)
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
                        AvailableDestinationsPolicy = explicitPanic ? "HealthyOrPanic" : "HealthyAndUnknown", // never implicit panic,
                        Active = new {
                            Enabled = true, Interval = probe == "/lab/ping" ? "00:00:00.500" : "00:00:01",
                            Timeout = probe == "/lab/ping" ? "00:00:00.500" : "00:00:01",
                            Policy = "ConsecutiveFailures", Path = probe },
                        Passive = new {
                            Enabled = probe == "/lab/ping",
                            Policy = "BoundedTransportFailure",
                            ReactivationPeriod = "00:00:15"
                        }
                    },
                    Metadata = new Dictionary<string,string> {
                        ["ConsecutiveFailuresHealthPolicy.Threshold"] = "1",
                        ["BoundedTransportFailure.MaxEjectedPercent"] = "50",
                        ["BoundedTransportFailure.MinHealthyRemaining"] = "1"
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
    Dictionary<string,string> Settings(int port,int tls,string path, string nodeName) => new()
    {
        ["YARP_LAB_HTTP_PORT"]=port.ToString(),
        ["YARP_LAB_TLS_PORT"]=tls.ToString(),
        ["YARP_LAB_CONFIG_FILE"]=path,
        ["YARP_LAB_GATEWAY_ID"]=nodeName
    };
    var gateway1=Start("gateway-1",gatewayDll,[],Settings(18080,18443,g1config,"gateway-1"));
    var gateway2=Start("gateway-2",gatewayDll,[],Settings(18083,18444,g2config,"gateway-2"));
    await WaitFor("both YARP gateways",async()=>await Responds("http://127.0.0.1:18080/lab/ping") &&
        await Responds("http://127.0.0.1:18083/lab/ping"));
    _=Start("health-aware-ingress",gatewayDll,[],Settings(19080,19443,edgeConfig,""));
    await WaitFor("ingress",()=>Responds("http://127.0.0.1:19080/lab/ping"));
    await Task.Delay(2500);
    var initial=await Sample(300);
    checks.Add(new {description="initial-ingress-warmup",successful=initial.Ok,
        failed=initial.Fail,utc=DateTimeOffset.UtcNow});
    // A gateway may report /lab/ping before active health's very first probe
    // marks both destinations eligible (particularly on loaded Windows CI).
    // We allow a bounded warmup but NEVER discard the initial failure evidence.
    if(initial.Ok!=300)
    {
        await WaitFor("two complete post-warmup ingress samples",async () =>
        {
            var first=await Sample(300);
            if(first.Ok!=300) return false;
            var second=await Sample(300);
            return second.Ok==300;
        },20);
        initial=await Sample(300);
    }
    Require(initial.Ok==300,
        $"300 HTTP requests traverse ingress after bounded health warmup, ok={initial.Ok} fail={initial.Fail}");
    using(var slow=await client.GetAsync("http://127.0.0.1:19080/api/slow"))
        Require(slow.StatusCode==HttpStatusCode.OK,
            "700ms slow but healthy upstream response is not misclassified as failed");
    Require((await Sample(100)).Ok==100,
        "healthy edge remains routable after slow upstream response");

    // A production-like MAINTENANCE stop is a two-step sequence: mark gateway
    // unready -> wait until ingress routes solely to the survivor -> gracefully
    // shut down Kestrel. SIGTERM on Linux enters the same host-stop lifecycle.
    // A plain SIGTERM with no prior drain is NOT asserted zero loss.
    var gracefulStatuses = new ConcurrentQueue<(double AtMs,int Status,string Gateway)>();
    using var gracefulCancel = new CancellationTokenSource();
    var gracefulOrigin = Stopwatch.GetTimestamp();
    var gracefulWorkers = Enumerable.Range(0,16).Select(async _ =>
    {
        while (!gracefulCancel.IsCancellationRequested)
        {
            int status=0; string selected="?";
            try
            {
                using var response=await client.GetAsync("http://127.0.0.1:19080/api/identity",gracefulCancel.Token);
                status=(int)response.StatusCode;
                selected=response.Headers.TryGetValues("X-Lab-Gateway",out var headers)
                    ? headers.FirstOrDefault() ?? "?" : "?";
            }
            catch(OperationCanceledException) when (gracefulCancel.IsCancellationRequested) { break; }
            catch(Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { }
            gracefulStatuses.Enqueue((Stopwatch.GetElapsedTime(gracefulOrigin).TotalMilliseconds,status,selected));
            try { await Task.Delay(20,gracefulCancel.Token); }
            catch(OperationCanceledException) { break; }
        }
    }).ToArray();
    await Task.Delay(1250);
    var gracefulDrainStart=Stopwatch.GetElapsedTime(gracefulOrigin).TotalMilliseconds;
    using (var drainReply=await client.PostAsync("http://127.0.0.1:18080/lab/drain",null))
        drainReply.EnsureSuccessStatusCode();
    await WaitFor("gateway 1 readiness drops",()=>Responds("http://127.0.0.1:18080/lab/ping",503));
    // Ensure ingress has converged, not merely that gateway 1 self-declares drain.
    await WaitFor("ingress routes to gateway 2 only",async () =>
    {
        for (var i=0;i<25;i++)
        {
            using var res=await client.GetAsync("http://127.0.0.1:19080/api/identity");
            if (!res.IsSuccessStatusCode || !res.Headers.TryGetValues("X-Lab-Gateway",out var values) ||
                values.FirstOrDefault()!="gateway-2") return false;
        }
        return true;
    },20);
    var gracefulReadyMs=Stopwatch.GetElapsedTime(gracefulOrigin).TotalMilliseconds;
    var gracefulStopKind = "readiness-withdrawal-and-host-stop";
    if (OperatingSystem.IsLinux())
    {
        // On Linux use the real OS signal; do not confuse an internal
        // StopApplication API call with proof of SIGTERM handling.
        var signal = new ProcessStartInfo("/usr/bin/kill")
        {
            UseShellExecute = false,
            RedirectStandardError = true
        };
        signal.ArgumentList.Add("-TERM");
        signal.ArgumentList.Add(gateway1.Id.ToString(System.Globalization.CultureInfo.InvariantCulture));
        using var sent = Process.Start(signal)
            ?? throw new InvalidOperationException("Could not dispatch SIGTERM");
        await sent.WaitForExitAsync();
        Require(sent.ExitCode == 0, "actual Linux SIGTERM successfully delivered");
        gracefulStopKind = "readiness-withdrawal-and-linux-SIGTERM";
    }
    else
    {
        // Windows CI cannot send Unix SIGTERM; use Kestrel's graceful
        // application lifetime stop, without claiming it is an OS signal.
        using var gracefulStop=await client.PostAsync(
            "http://127.0.0.1:18080/lab/graceful-stop",null);
        gracefulStop.EnsureSuccessStatusCode();
    }
    using(var graceTimeout=new CancellationTokenSource(TimeSpan.FromSeconds(20)))
        await gateway1.WaitForExitAsync(graceTimeout.Token);
    await Task.Delay(1500);
    gracefulCancel.Cancel();
    await Task.WhenAll(gracefulWorkers);
    var gracefulArray=gracefulStatuses.ToArray();
    var gracefulFailures=gracefulArray.Where(x=>x.Status!=200).ToArray();
    Require(gracefulArray.Length>=100,"graceful lifecycle measured >=100 requests");
    Require(gracefulFailures.Length==0,
        $"pre-drained graceful host stop caused zero HTTP errors: observed {gracefulFailures.Length}");
    checks.Add(new {description="graceful-drain-under-load",
        evidence=new { method=gracefulStopKind,
          measuredRequests=gracefulArray.Length,failedRequests=gracefulFailures.Length,
          readinessConvergenceMs=Math.Round(gracefulReadyMs-gracefulDrainStart,1),
          gateway2Observed=gracefulArray.Count(x=>x.Gateway=="gateway-2") }});
    // Restore gateway 1 to run the independent sudden-crash (SIGKILL) scenario.
    gateway1=Start("gateway-1-after-graceful",gatewayDll,[],Settings(18080,18443,g1config,"gateway-1"));
    await WaitFor("gateway 1 restored after graceful stop",()=>Responds("http://127.0.0.1:18080/lab/ping"));
    await Task.Delay(2500);
    Require((await Sample(150)).Ok==150,"both gateways functional before SIGKILL test");

    // Continuous in-flight HTTP traffic spans the exact moment the gateway dies.
    // Every attempted request is counted, including exceptions and status >= 500.
    var timeline = new ConcurrentQueue<(double StartMs, double CompletedMs, int Status, double LatencyMs)>();
    using var trafficStop = new CancellationTokenSource();
    var epoch = Stopwatch.GetTimestamp();
    var trafficWorkers = Enumerable.Range(0,24).Select(async _ =>
    {
        while (!trafficStop.IsCancellationRequested)
        {
            var started = Stopwatch.GetTimestamp();
            var status = 0;
            try
            {
                using var response = await client.GetAsync(
                    "http://127.0.0.1:19080/api/identity", trafficStop.Token);
                status = (int)response.StatusCode;
            }
            catch (OperationCanceledException) when (trafficStop.IsCancellationRequested) { break; }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or IOException) { }
            timeline.Enqueue((Stopwatch.GetElapsedTime(epoch,started).TotalMilliseconds,
                Stopwatch.GetElapsedTime(epoch).TotalMilliseconds,
                status, Stopwatch.GetElapsedTime(started).TotalMilliseconds));
            try { await Task.Delay(15,trafficStop.Token); }
            catch (OperationCanceledException) { break; }
        }
    }).ToArray();
    await Task.Delay(1500);
    var killRequestedAtMs = Stopwatch.GetElapsedTime(epoch).TotalMilliseconds;
    // The gateway lab is a single dotnet host with NO child processes.
    // On Windows Kill(entireProcessTree:true) can spend substantial time
    // enumerating descendants before stopping the target process. Use the
    // actual single-process abrupt termination; never include test-harness
    // descendant traversal time in a YARP failover measurement.
    gateway1.Kill();
    await gateway1.WaitForExitAsync();
    var killAtMs = Stopwatch.GetElapsedTime(epoch).TotalMilliseconds;
    checks.Add(new {description="fault-timing",
        evidence=new {requestedAtMs=Math.Round(killRequestedAtMs,1),
            exitedAtMs=Math.Round(killAtMs,1),
            processTerminationDelayMs=Math.Round(killAtMs-killRequestedAtMs,1)}});
    Require(killAtMs - killRequestedAtMs <= 2000,
        "single-process abrupt-kill operation itself completes within 2s");
    await Task.Delay(6000);
    trafficStop.Cancel();
    await Task.WhenAll(trafficWorkers);
    var measured = timeline.ToArray();
    // Use COMPLETION time so in-flight requests started before the kill but
    // aborted after it still count as post-fault failures.
    var preKill = measured.Where(x => x.CompletedMs < killAtMs).ToArray();
    var postKill = measured.Where(x => x.CompletedMs >= killAtMs).ToArray();
    var steadyState = measured.Where(x => x.CompletedMs > killAtMs + 4500).ToArray();
    Console.WriteLine($"FAULT SAMPLE COUNTS pre={preKill.Length}, post={postKill.Length}, steady={steadyState.Length}");
    // This is a correctness/failure-injection test, not a VU throughput SLO.
    // A busy shared Windows hosted runner may complete fewer HTTP calls.
    Require(preKill.Length >= 24 && postKill.Length >= 24,
        $"continuous load present before/after gateway death (pre={preKill.Length}, post={postKill.Length})");
    Require(steadyState.Length >= 16 && steadyState.All(x => x.Status == 200),
        $"survivor must serve final observation window without errors (steady={steadyState.Length})");
    var failuresAfter = postKill.Where(x => x.Status != 200).ToArray();
    var latencies = measured.Select(x => x.LatencyMs).OrderBy(x=>x).ToArray();
    static double Percentile(double[] sorted, double p) =>
        sorted[Math.Clamp((int)Math.Ceiling(p * sorted.Length) - 1, 0, sorted.Length - 1)];
    var failoverEvidence = new
    {
        faultType = "gateway-process-kill",
        activeClients = trafficWorkers.Length,
        sampleTimeMs = 7500,
        beforeRequests = preKill.Length,
        beforeFailures = preKill.Count(x => x.Status != 200),
        afterRequests = postKill.Length,
        afterFailures = failuresAfter.Length,
        failuresByStatus = failuresAfter.GroupBy(x => x.Status)
            .ToDictionary(x => x.Key.ToString(),x=>x.Count()),
        firstObservedFailureOffsetMs = failuresAfter.Length == 0 ? (double?)null :
            Math.Round(failuresAfter.Min(x => x.CompletedMs - killAtMs),1),
        lastObservedFailureOffsetMs = failuresAfter.Length == 0 ? (double?)null :
            Math.Round(failuresAfter.Max(x => x.CompletedMs - killAtMs),1),
        observedFailureWindowMs = failuresAfter.Length == 0 ? 0 :
            Math.Round(failuresAfter.Max(x => x.CompletedMs) - failuresAfter.Min(x => x.CompletedMs),1),
        lastFailureAfterKillUnder2s = failuresAfter.Length == 0 ||
            failuresAfter.Max(x=>x.CompletedMs - killAtMs) <= 2000,
        p95LatencyMs = Math.Round(Percentile(latencies,0.95),2),
        p99LatencyMs = Math.Round(Percentile(latencies,0.99),2),
        caveat = "Last observed failure offset is NOT a YARP health-detection timestamp; in-flight retries are not assumed."
    };
    checks.Add(new { description="continuous-load-failover", evidence=failoverEvidence });
    Require(failoverEvidence.lastFailureAfterKillUnder2s,
        "Windows/Ubuntu last observed gateway-kill failure ends within 2s of fault");
    Console.WriteLine("FAILOVER UNDER LOAD: "+JsonSerializer.Serialize(failoverEvidence));
    // Non-idempotent requests have a strict ZERO automatic replay budget.
    // A lost HTTP response may hide an applied operation, therefore count
    // backend side effects rather than using status alone as an oracle.
    var txStatuses=new List<int>();
    var maxApplications=0;
    for(var i=0;i<24;i++)
    {
        var txId="neverretry"+i.ToString("D6");
        int status;
        try
        {
            using var response=await client.PostAsync(
                "http://127.0.0.1:19080/api/transaction/"+txId,
                new StringContent("one-commit"));
            status=(int)response.StatusCode;
        }
        catch(HttpRequestException) {status=0;}
        txStatuses.Add(status);
        async Task<int> Count(string host)
        {
            using var reply=await client.GetAsync(host+"/lab/transaction-count/"+txId);
            reply.EnsureSuccessStatusCode();
            using var doc=JsonDocument.Parse(await reply.Content.ReadAsStringAsync());
            return doc.RootElement.GetProperty("count").GetInt32();
        }
        var applied=await Count("http://127.0.0.1:18081")+await Count("http://127.0.0.1:18082");
        maxApplications=Math.Max(maxApplications,applied);
        Require(applied<=1,
            $"transaction {txId} delivered at most once after failover, applied={applied}");
        if(status==200) Require(applied==1,
            $"HTTP 200 transaction {txId} committed exactly once");
    }
    checks.Add(new {description="non-idempotent-post-no-replay",
        evidence=new {attempts=txStatuses.Count,maxApplications,
            successful=txStatuses.Count(x=>x==200),failed=txStatuses.Count(x=>x!=200),
            retryBudget=0}});
    var afterFailure=await Sample(400);
    Require(afterFailure.Ok==400,
        "gateway 1 terminated: 400/400 NEW requests continue through remaining gateway");
    Require(!gateway2.HasExited,"gateway 2 remains serving after gateway 1 dies");
    // Controller is never part of the data plane in this isolated test.
    // The gateways continue serving from their on-disk last-known configuration.
    var restart=Start("gateway-1-restarted",gatewayDll,[],Settings(18080,18443,g1config,"gateway-1"));
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
    // Opt-in panic is an explicitly different availability contract: on TOTAL
    // loss YARP retries known dead candidate destinations once as NEW requests
    // (not a replay of a previously forwarded non-idempotent operation).
    // Never enable this for CA/RA signing or enrollment without risk approval.
    Config(edgeConfig,new[] {("gateway-1","http://127.0.0.1:18080/"),
        ("gateway-2","http://127.0.0.1:18083/")}, "/lab/ping", explicitPanic:true);
    await WaitFor("explicit panic tries all-down destinations",async () =>
    {
        try
        {
            using var response=await client.GetAsync("http://127.0.0.1:19080/api/identity");
            return (int)response.StatusCode==502;
        }
        catch {return false;}
    },20);
    checks.Add(new {description="all-down-explicit-panic",
        evidence="opt-in YARP HealthyOrPanic attempts dead backends; default 503 remains safer"});
    Config(edgeConfig,new[] {("gateway-1","http://127.0.0.1:18080/"),
        ("gateway-2","http://127.0.0.1:18083/")}, "/lab/ping", explicitPanic:false);
    await WaitFor("reverted all-down policy fails closed with HTTP 503",
        ()=>Responds("http://127.0.0.1:19080/api/identity",503),20);
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
