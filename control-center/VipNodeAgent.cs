using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Globalization;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// Separate privileged local process, reachable only by the independent provider.
internal static class VipNodeAgent
{
    private sealed record Settings(string Scope,string NodePin,string OtherPin,string ReaderConfig,
        string SupervisorConfig,VipMachineTransport.ServerSettings Server);
    internal static async Task<int> Run(string[] args)
    {
        try
        {
            if(args.Length!=2)throw new InvalidDataException("Usage: --vip-node-agent <private-config>");
            var s=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FleetQuorum.FilePath(args[1],16384,true)),VipMachineTransport.Json)
                ??throw new InvalidDataException("Missing node agent settings.");
            VipFenceProvider.ValidatePair(s.Scope,s.NodePin,s.OtherPin);
            var t=s.Server;
            if(!IPAddress.TryParse(t.ListenIp,out var ip)||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)||
                ip.IsIPv4MappedToIPv6||ip.IsIPv6Multicast||t.Port is <1024 or >65535||
                !VipFenceProvider.Pin(t.ClientPin)||t.ClientPin==s.NodePin||t.ClientPin==s.OtherPin)
                throw new InvalidDataException("Require isolated node agent and independent provider certificate.");
            using var authority=FleetQuorum.OpenVip(s.ReaderConfig,s.Scope);
            if(authority.VipReaderPin!=s.NodePin)throw new InvalidDataException("Node identity mismatch.");
            _=FleetQuorum.FilePath(s.SupervisorConfig,16384,true);
            using var ca=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(t.ClientCaFile,65536));
            using var cert=X509CertificateLoader.LoadPkcs12FromFile(FleetQuorum.FilePath(t.Pfx,65536,true),
                File.ReadAllText(FleetQuorum.FilePath(t.PasswordFile,4096,true)).TrimEnd('\r','\n'),
                OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
            bool Allowed(X509Certificate2? leaf)=>VipMachineTransport.Pinned(leaf,ca,t.ClientPin,"1.3.6.1.5.5.7.3.2");
            var builder=WebApplication.CreateSlimBuilder(Array.Empty<string>());
            builder.Configuration.Sources.Clear();builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(o=>
            {
                o.Limits.MaxRequestBodySize=4096;o.Limits.MaxConcurrentConnections=8;
                o.Limits.RequestHeadersTimeout=TimeSpan.FromSeconds(5);
                o.Listen(ip,t.Port,l=>l.UseHttps(new HttpsConnectionAdapterOptions
                {ServerCertificate=cert,ClientCertificateMode=ClientCertificateMode.RequireCertificate,ClientCertificateValidation=(leaf,_,_)=>Allowed(leaf)}));
            });
            await using var app=builder.Build();
            using var gate=new SemaphoreSlim(1,1);
            async Task<IResult> Handle(HttpContext ctx,bool activate)
            {
                if(!Allowed(ctx.Connection.ClientCertificate))return Results.StatusCode(403);
                if(!await gate.WaitAsync(0,ctx.RequestAborted))return Results.Conflict();
                try
                {
                    var r=await ctx.Request.ReadFromJsonAsync<VipRemoteNode.Request>(VipMachineTransport.Json,ctx.RequestAborted)
                        ??throw new InvalidDataException("Missing request.");
                    VipRemoteNode.Validate(r,s.Scope,s.NodePin);
                    if((r.OwnerPin==s.NodePin?r.OtherPin:r.OwnerPin)!=s.OtherPin)return Results.BadRequest();
                    using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    deadline.CancelAfter(TimeSpan.FromSeconds(100));
                    var expected=new FleetQuorum.Fence("vip_"+r.OwnerPin,r.Epoch);
                    if(await authority.ReadVipState(deadline.Token)!=expected)return Results.Conflict();
                    bool own=r.OwnerPin==s.NodePin;
                    if(activate&&!own)return Results.StatusCode(403);
                    var mode=activate?"activate":own?"owner-check":"standby-check";
                    int code=await VipNodeSupervisor.Run(["--vip-node",s.SupervisorConfig,mode,r.Epoch.ToString(CultureInfo.InvariantCulture)],
                        s.Scope,s.NodePin,r.OwnerPin,deadline.Token);
                    if(await authority.ReadVipState(deadline.Token)!=expected)return Results.Conflict();
                    // Only explicitly observed negative application readiness is
                    // a health failure. Invalid config or unknown state is 503.
                    if(code!=0&&(activate||code!=1))return Results.StatusCode(503);
                    return Results.Json(new VipRemoteNode.Evidence(r.Scope,r.OwnerPin,r.Epoch,r.OtherPin,r.Nonce,s.NodePin,own&&code==0,!own&&code==0),VipMachineTransport.Json);
                }
                catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or
                    HttpRequestException or OperationCanceledException or JsonException or CryptographicException or UnauthorizedAccessException or ArgumentException)
                {return Results.StatusCode(503);}
                finally{gate.Release();}
            }
            app.MapPost("/v1/vip-node/status",(Delegate)(Func<HttpContext,Task<IResult>>)(ctx=>Handle(ctx,false)));
            app.MapPost("/v1/vip-node/activate",(Delegate)(Func<HttpContext,Task<IResult>>)(ctx=>Handle(ctx,true)));
            await app.RunAsync();return 0;
        }
        catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or
            HttpRequestException or OperationCanceledException or JsonException or CryptographicException or UnauthorizedAccessException or ArgumentException)
        {Console.Error.WriteLine("VIP node agent refused: "+e.GetType().Name);return 78;}
    }
}
