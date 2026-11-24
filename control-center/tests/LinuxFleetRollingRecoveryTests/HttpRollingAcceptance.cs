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

    private static async Task<string> Mint(HttpClient http, Node node)
    {
        using var response = await http.PostAsync(node.Address+"/mint",null);
        response.EnsureSuccessStatusCode();
        var cookie = response.Headers.GetValues("Set-Cookie").Single(
            x=>x.StartsWith(CookieName+"=",StringComparison.Ordinal));
        return cookie.Split(';',2)[0];
    }
    private static async Task Probe(HttpClient http, Node node, string cookie)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get,node.Address+"/probe");
        request.Headers.TryAddWithoutValidation("Cookie",cookie);
        using var response = await http.SendAsync(request);
        if (response.StatusCode != HttpStatusCode.OK ||
            await response.Content.ReadAsStringAsync() != "disposable-fleet-user")
            throw new InvalidOperationException("Live authenticated fleet request failed");
    }
    private static bool DifferentKeys(string oldCookie,string newCookie)
    {
        var oldBytes=WebEncoders.Base64UrlDecode(oldCookie[(CookieName.Length+1)..]);
        var newBytes=WebEncoders.Base64UrlDecode(newCookie[(CookieName.Length+1)..]);
        return oldBytes.Length>=20 && newBytes.Length>=20 &&
            !oldBytes.AsSpan(4,16).SequenceEqual(newBytes.AsSpan(4,16));
    }

    // Serial admission/drain fixture: each admission update waits for the
    // current request to finish. No retry, redirect, or failed request is
    // hidden. This measures cookie traffic while one live node is restarted.
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
        Node[] admitted=Array.Empty<Node>();
        int success=0;
        async Task Admit(params Node[] nodes)
        {
            await gate.WaitAsync();
            try { admitted=nodes; }
            finally { gate.Release(); }
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
            var oldCookie=await Mint(http,a);
            replicate(stateA,stateB);
            b=await Node.Start(stateB,nextB,oldB);
            await Probe(http,b,oldCookie);
            await Admit(a,b);
            traffic=Task.Run(async () =>
            {
                var index=0;
                while (!stop.IsCancellationRequested)
                {
                    await gate.WaitAsync();
                    try
                    {
                        if (admitted.Length==0)
                            throw new InvalidOperationException("No admitted fleet node");
                        await Probe(http,admitted[index++%admitted.Length],oldCookie);
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
            before=Volatile.Read(ref success);
            // B is offline before copying newly wrapped XML; no live partial
            // file import. New cookie issuance is tested only after both
            // nodes have the same new ring, not during the staging interval.
            b.Dispose(); b=null;
            replicate(stateA,stateB);
            b=await Node.Start(stateB,nextB,oldB);
            await Probe(http,b,oldCookie);
            await Progress(before);
            await Admit(a,b);
            var newCookie=await Mint(http,a);
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
            Console.WriteLine("PASS: continuous old-cookie HTTP probes during two-node rolling restart; both cookie generations accepted after coordinated staging");
        }
        finally
        {
            stop.Cancel();
            try { if (traffic!=null) await traffic; }
            finally { try { a?.Dispose(); } finally { b?.Dispose(); } }
        }
    }
}
