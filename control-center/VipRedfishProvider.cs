using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// Run on an independently administered, private fencing host. It cannot
// mutate Raft ownership, cannot power a node on, and never accepts target URLs
// or credentials from the network. BMC access is limited to configured nodes.
internal static class VipRedfishProvider
{
    private sealed record Node(string Pin,VipRedfishFence.Settings Bmc);
    private sealed record Settings(string ListenIp,int Port,string Scope,string ReaderConfig,
        string ServerPfx,string ServerPasswordFile,string WriterCaFile,string WriterPin,
        string SigningKeyFile,Node[] Nodes);
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web)
        {UnmappedMemberHandling=JsonUnmappedMemberHandling.Disallow};
    internal static async Task<int> Run(string[] args)
    {
        try
        {
            if(args.Length!=2)throw new InvalidDataException("Usage: --vip-redfish-provider <private-config>");
            var s=JsonSerializer.Deserialize<Settings>(File.ReadAllBytes(FleetQuorum.FilePath(args[1],32768,true)),Json)
                ??throw new InvalidDataException("Missing provider configuration.");
            if(!IPAddress.TryParse(s.ListenIp,out var ip)||ip.Equals(IPAddress.Any)||ip.Equals(IPAddress.IPv6Any)||
                ip.IsIPv4MappedToIPv6||ip.IsIPv6Multicast||s.Port is <1024 or >65535||s.Nodes is not {Length:2}||
                s.Nodes.Any(n=>n is null||n.Bmc is null)||!VipFenceProvider.Pin(s.WriterPin))
                throw new InvalidDataException("Require isolated provider listener and exact pair.");
            VipFenceProvider.ValidatePair(s.Scope,s.Nodes[0].Pin,s.Nodes[1].Pin);
            if(s.Nodes.Any(n=>n.Pin==s.WriterPin)||s.Nodes[0].Bmc.Origin==s.Nodes[1].Bmc.Origin||
                string.Equals(s.Nodes[0].Bmc.SystemUuid,s.Nodes[1].Bmc.SystemUuid,StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Independent writer and distinct BMC identities required.");
            using var reader=FleetQuorum.OpenVip(s.ReaderConfig,s.Scope);
            if(reader.VipReaderPin==s.WriterPin||s.Nodes.Any(n=>n.Pin==reader.VipReaderPin))
                throw new InvalidDataException("Provider requires an independent read-only Raft identity.");
            using var first=VipRedfishFence.Open(s.Nodes[0].Bmc);
            using var second=VipRedfishFence.Open(s.Nodes[1].Bmc);
            using var signer=ECDsa.Create();
            signer.ImportFromPem(File.ReadAllText(FleetQuorum.FilePath(s.SigningKeyFile,8192,true)));
            if(signer.KeySize!=256||signer.ExportParameters(true).D is not {Length:32})
                throw new InvalidDataException("Independent P-256 signing key required.");
            using var writerCa=X509CertificateLoader.LoadCertificateFromFile(FleetQuorum.FilePath(s.WriterCaFile,65536));
            var password=File.ReadAllText(FleetQuorum.FilePath(s.ServerPasswordFile,4096,true)).TrimEnd('\r','\n');
            using var server=X509CertificateLoader.LoadPkcs12FromFile(FleetQuorum.FilePath(s.ServerPfx,65536,true),password,
                OperatingSystem.IsWindows()?X509KeyStorageFlags.UserKeySet:X509KeyStorageFlags.EphemeralKeySet);
            if(!server.HasPrivateKey||server.NotAfter.ToUniversalTime()<=DateTime.UtcNow||
                server.NotBefore.ToUniversalTime()>DateTime.UtcNow)
                throw new InvalidDataException("Provider server certificate unavailable.");
            bool WriterAllowed(X509Certificate2? cert)
            {
                if(cert is null||!CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData),Convert.FromHexString(s.WriterPin)))return false;
                using var chain=new X509Chain();
                chain.ChainPolicy.TrustMode=X509ChainTrustMode.CustomRootTrust;
                chain.ChainPolicy.CustomTrustStore.Add(writerCa);
                chain.ChainPolicy.RevocationMode=X509RevocationMode.NoCheck;
                chain.ChainPolicy.DisableCertificateDownloads=true;
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                return chain.Build(cert);
            }
            var builder=WebApplication.CreateSlimBuilder(Array.Empty<string>());
            builder.Configuration.Sources.Clear();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options=>
            {
                options.Limits.MaxRequestBodySize=4096;
                options.Limits.MaxConcurrentConnections=16;
                options.Limits.RequestHeadersTimeout=TimeSpan.FromSeconds(5);
                options.Listen(ip,s.Port,listen=>listen.UseHttps(new HttpsConnectionAdapterOptions
                {
                    ServerCertificate=server,ClientCertificateMode=ClientCertificateMode.RequireCertificate,
                    ClientCertificateValidation=(cert,_,_)=>WriterAllowed(cert)
                }));
            });
            await using var app=builder.Build();
            using var gate=new SemaphoreSlim(1,1);
            async Task<IResult> Fence(HttpContext ctx)
            {
                if(!WriterAllowed(ctx.Connection.ClientCertificate))return Results.StatusCode(403);
                if(!await gate.WaitAsync(0,ctx.RequestAborted))return Results.Conflict();
                try
                {
                    var request=await ctx.Request.ReadFromJsonAsync<VipFenceProvider.Request>(Json,ctx.RequestAborted)
                        ??throw new InvalidDataException("Missing exact fence request.");
                    VipFenceProvider.ValidatePair(request.Scope,request.OldPin,request.NewPin);
                    if(request.Scope!=s.Scope||request.RevokedEpoch<1||
                        !s.Nodes.Any(n=>n.Pin==request.OldPin)||!s.Nodes.Any(n=>n.Pin==request.NewPin))
                        return Results.BadRequest();
                    using var deadline=CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    deadline.CancelAfter(TimeSpan.FromSeconds(40));
                    async Task AssertRevoked(CancellationToken token)
                    {
                        if(await reader.ReadVipState(token)!=new FleetQuorum.Fence("vip_revoked_"+request.OldPin,request.RevokedEpoch))
                            throw new InvalidDataException("Exact revoked authority not confirmed.");
                    }
                    await (request.OldPin==s.Nodes[0].Pin?first:second).ConfirmOff(AssertRevoked,deadline.Token);
                    await AssertRevoked(deadline.Token);
                    long expires=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+60;
                    var message=Encoding.UTF8.GetBytes(string.Join("\n","GatewayCore.VIP.HardFence.v1",s.Scope,
                        request.OldPin,request.RevokedEpoch.ToString(CultureInfo.InvariantCulture),request.NewPin,
                        expires.ToString(CultureInfo.InvariantCulture)));
                    var signature=signer.SignData(message,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence);
                    return Results.Json(new VipFenceProvider.Permit(s.Scope,request.OldPin,request.RevokedEpoch,request.NewPin,
                        expires,Convert.ToBase64String(signature)),Json);
                }
                catch(Exception error) when(error is IOException or InvalidDataException or InvalidOperationException or
                    UnauthorizedAccessException or HttpRequestException or OperationCanceledException or JsonException or
                    CryptographicException or KeyNotFoundException or FormatException or ArgumentException)
                {return Results.Json(new{error="Hard fencing not independently confirmed."},statusCode:503);}
                finally{gate.Release();}
            }
            app.MapPost("/v1/vip/hard-fence",(Delegate)(Func<HttpContext,Task<IResult>>)Fence);
            await app.RunAsync();
            return 0;
        }
        catch(Exception error) when(error is IOException or InvalidDataException or InvalidOperationException or
            UnauthorizedAccessException or HttpRequestException or OperationCanceledException or JsonException or
            CryptographicException or KeyNotFoundException or FormatException or ArgumentException)
        {Console.Error.WriteLine("Independent Redfish provider refused: "+error.GetType().Name);return 78;}
    }
}
