using System.Diagnostics;
using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

// Disposable loopback software acceptance, not a product authentication
// endpoint or a claim of physical load-balancer or distributed writer acceptance.
internal static class HttpRollingAcceptance
{
    internal const string Application = "GatewayCore.FleetHttpRotation.CI.v1";
    private const string Scheme = "FleetProbe";
    private const string CookieName = "GatewayCore.FleetProbe";

    internal static int RunNode(string state, string appName)
    {
        if (!OperatingSystem.IsLinux() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS") != "true" ||
            Environment.GetEnvironmentVariable("RUNNER_OS") != "Linux" ||
            appName != Application)
            return 2;
        LinuxKeyProtection.InitializeStateDirectory();
        var builder = WebApplication.CreateSlimBuilder(
            new WebApplicationOptions { Args = Array.Empty<string>() });
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        var dp = builder.Services.AddDataProtection().SetApplicationName(appName)
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(state,"data-protection-keys")));
        LinuxKeyProtection.Configure(dp,state);
        builder.Services.AddAuthentication(Scheme).AddCookie(Scheme, o =>
        {
            o.Cookie.Name = CookieName;
            o.SlidingExpiration = false;
            o.Events.OnRedirectToLogin = c =>
            {
                c.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
        });
        builder.Services.AddAuthorization();
        var app = builder.Build();
        app.Use(async (ctx,next) =>
        {
            ctx.Response.Headers["X-Fleet-Fixture-Node"]=Path.GetFileName(state);
            await next();
        });
        app.UseAuthentication();
        app.UseAuthorization();
        app.MapPost("/mint", async (HttpContext ctx) =>
        {
            var identity = new ClaimsIdentity(
                new[] {new Claim(ClaimTypes.Name,"disposable-fleet-user")}, Scheme);
            await ctx.SignInAsync(Scheme,new ClaimsPrincipal(identity));
            return Results.Ok();
        });
        app.MapGet("/probe", (ClaimsPrincipal user) =>
            Results.Text(user.Identity?.Name ?? "")).RequireAuthorization();
        app.StartAsync().GetAwaiter().GetResult();
        var address = app.Services.GetRequiredService<IServer>().Features
            .Get<IServerAddressesFeature>()?.Addresses.Single()
            ?? throw new InvalidOperationException("Missing fixture listener");
        Console.WriteLine(address);
        Console.Out.Flush();
        app.WaitForShutdownAsync().GetAwaiter().GetResult();
        return 0;
    }

    private sealed class Node : IDisposable
    {
        private readonly Process process;
        private readonly Task<string> stderr;
        public string Address { get; private set; } = "";
        public string Name { get; private set; } = "";
        private Node(Process p)
        {
            process = p;
            stderr = p.StandardError.ReadToEndAsync();
        }
        public static async Task<Node> Start(string state,
            (string Pfx,string Password) current, (string Pfx,string Password)? previous)
        {
            var start = new ProcessStartInfo("dotnet")
            {
                UseShellExecute = false, RedirectStandardOutput = true,
                RedirectStandardError = true, RedirectStandardInput = true
            };
            foreach (var value in new[] {
                System.Reflection.Assembly.GetExecutingAssembly().Location,
                "child", "http", state, current.Pfx, current.Password, Application,
                previous?.Pfx ?? "-", previous?.Password ?? "-" })
                start.ArgumentList.Add(value);
            var node = new Node(Process.Start(start) ??
                throw new InvalidOperationException("Cannot start HTTP fleet fixture"));
            try
            {
                var ready = await node.process.StandardOutput.ReadLineAsync()
                    .WaitAsync(TimeSpan.FromSeconds(30));
                if (!Uri.TryCreate(ready,UriKind.Absolute,out var address) ||
                    address.Scheme != "http" || address.Host != "127.0.0.1" ||
                    address.Port <= 0)
                    throw new InvalidOperationException("HTTP fleet fixture failed readiness");
                node.Address = address.GetLeftPart(UriPartial.Authority);
                node.Name = Path.GetFileName(state);
                return node;
            }
            catch { node.Dispose(); throw; }
        }
        public void Dispose()
        {
            try
            {
                if (!process.HasExited) process.Kill(entireProcessTree:true);
                if (!process.WaitForExit(5000))
                    throw new InvalidOperationException("HTTP fleet fixture did not stop");
                _ = stderr.Wait(TimeSpan.FromSeconds(3));
            }
            finally { process.Dispose(); }
        }
    }

    private static Task<string> Mint(HttpClient http, Node node) => MintAt(http,node.Address);
    private static async Task<string> MintAt(HttpClient http, string address)
    {
        using var response = await http.PostAsync(address+"/mint",null);
        response.EnsureSuccessStatusCode();
        var cookie = response.Headers.GetValues("Set-Cookie").Single(
            x=>x.StartsWith(CookieName+"=",StringComparison.Ordinal));
        return cookie.Split(';',2)[0];
    }
    private static Task<string> Probe(HttpClient http, Node node, string cookie) =>
        ProbeAt(http,node.Address,cookie);
    private static async Task<string> ProbeAt(HttpClient http, string address, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,address+"/probe");
        request.Headers.TryAddWithoutValidation("Cookie",cookie);
        using var response = await http.SendAsync(request);
        if (response.StatusCode != HttpStatusCode.OK ||
            await response.Content.ReadAsStringAsync() != "disposable-fleet-user")
            throw new InvalidOperationException("Live authenticated fleet request failed");
        return response.Headers.GetValues("X-Fleet-Fixture-Node").Single();
    }
    private static bool DifferentKeys(string oldCookie,string newCookie)
    {
        var oldBytes=WebEncoders.Base64UrlDecode(oldCookie[(CookieName.Length+1)..]);
        var newBytes=WebEncoders.Base64UrlDecode(newCookie[(CookieName.Length+1)..]);
        return oldBytes.Length>=20 && newBytes.Length>=20 &&
            !oldBytes.AsSpan(4,16).SequenceEqual(newBytes.AsSpan(4,16));
    }

    // Actual shipping GatewayCore handles every workload request. Config
    // reload and observed destination drain precede each process restart.
    // No failed request is retried or excluded from the acceptance gate.
    internal static async Task RunAsync(string stateA,string stateB,
        (string Pfx,string Password) oldA,(string Pfx,string Password) nextA,
        (string Pfx,string Password) oldB,(string Pfx,string Password) nextB,
        Action<string,string> replicate,Func<string,int> rotate)
    {
        using var http=new HttpClient(new HttpClientHandler {
            UseCookies=false, AllowAutoRedirect=false }) {
            Timeout=TimeSpan.FromSeconds(5) };
        using var gate=new SemaphoreSlim(1,1);
        using var stop=new CancellationTokenSource();
        Node? a=null,b=null;
        Task? traffic=null;
        ProductFleetProxy? gateway=null;
        string? oldCookie=null;
        string? routed=null;
        var observedCookies=new Queue<string>();
        int success=0;
        async Task Admit(params Node[] nodes)
        {
            if(gateway is null||routed is null||oldCookie is null||nodes.Length==0)
                throw new InvalidOperationException("Product cutover fixture not initialized");
            var active=nodes.Select(x=>x.Name).ToHashSet(StringComparer.Ordinal);
            var current=new[]{a,b}.Where(x=>x is not null).Select(x=>x!).ToArray();
            gateway.Apply(current.ToDictionary(x=>x.Name,x=>(x.Address,!active.Contains(x.Name))));
            using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var seen=new HashSet<string>(StringComparer.Ordinal);
            var consecutive=0;
            while(consecutive<8||!seen.SetEquals(active))
            {
                limit.Token.ThrowIfCancellationRequested();
                if(traffic?.IsCompleted==true)await traffic;
                var actual=await ProbeAt(http,routed,oldCookie);
                if(active.Contains(actual)){seen.Add(actual);consecutive++;}
                else {seen.Clear();consecutive=0;}
                await Task.Delay(30,limit.Token);
            }
            // The continuous workload has at most one pair in flight.
            // Wait for it before stopping a drained process.
            await gate.WaitAsync(limit.Token);gate.Release();
        }
        async Task Progress(int before)
        {
            using var limit=new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (Volatile.Read(ref success)<before+3)
            {
                if (traffic?.IsCompleted==true) await traffic;
                await Task.Delay(20,limit.Token);
            }
        }

        try
        {
            a=await Node.Start(stateA,oldA,null);
            oldCookie=await Mint(http,a);
            replicate(stateA,stateB);
            b=await Node.Start(stateB,nextB,oldB);
            await Probe(http,b,oldCookie);
            gateway=await ProductFleetProxy.Start(
                Path.Combine(Path.GetDirectoryName(stateA)!,"http-gateway"),
                oldA,http,new Dictionary<string,(string Address,bool Draining)> {
                    [a.Name]=(a.Address,false),[b.Name]=(b.Address,false)});
            routed=gateway.Address+"/fleet";
            await Admit(a,b);
            traffic=Task.Run(async () =>
            {
                while (!stop.IsCancellationRequested)
                {
                    await gate.WaitAsync();
                    try
                    {
                        await ProbeAt(http,routed!,oldCookie!);
                        var minted=await MintAt(http,routed!);
                        await ProbeAt(http,routed!,minted);
                        observedCookies.Enqueue(minted);
                        if(observedCookies.Count>128)observedCookies.Dequeue();
                        Interlocked.Increment(ref success);
                    }
                    finally { gate.Release(); }
                    await Task.Delay(20);
                }
            });
            await Progress(0);
            // Drain A and rotate offline while B continues accepting the old
            // cookie. Admit A only after its actual HTTP/auth probe succeeds.
            await Admit(b);
            var before=Volatile.Read(ref success);
            a.Dispose(); a=null;
            if (rotate(stateA)!=0) throw new InvalidOperationException("Offline rotation failed");
            await Task.Delay(2000);
            a=await Node.Start(stateA,nextA,oldA);
            await Probe(http,a,oldCookie);
            await Progress(before);
            await Admit(a);
            var stageCookie=await MintAt(http,routed);
            if(!DifferentKeys(oldCookie,stageCookie))
                throw new InvalidOperationException("Product cutover did not select a newly rotated key");
            await ProbeAt(http,routed,stageCookie);
            before=Volatile.Read(ref success);
            // B is offline before copying newly wrapped XML; the actual
            // proxy keeps routing old-cookie and new-login traffic to A.
            b.Dispose(); b=null;
            replicate(stateA,stateB);
            b=await Node.Start(stateB,nextB,oldB);
            await Probe(http,b,oldCookie);
            await Probe(http,b,stageCookie);
            await Progress(before);
            await Admit(a,b);
            var newCookie=await MintAt(http,routed);
            if (!DifferentKeys(oldCookie,newCookie))
                throw new InvalidOperationException("HTTP rotation did not select new key");
            foreach(var node in new[]{a,b})
            {
                await Probe(http,node,oldCookie);
                await Probe(http,node,newCookie);
            }
            await Progress(Volatile.Read(ref success));
            stop.Cancel();
            await traffic;
            foreach(var cookie in observedCookies.Append(stageCookie))
                foreach(var node in new[]{a,b})await Probe(http,node,cookie);
            Console.WriteLine("PASS: shipping GatewayCore proxy drain and rolling restart with continuous old-cookie and new-login HTTP traffic; both key generations accepted");
        }
        finally
        {
            stop.Cancel();
            try { if (traffic!=null) await traffic; }
            finally { try { gateway?.Dispose(); } finally { try { a?.Dispose(); } finally { b?.Dispose(); } } }
        }
    }
}
