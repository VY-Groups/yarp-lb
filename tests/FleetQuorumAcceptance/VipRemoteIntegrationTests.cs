using System.Net;
using System.Net.Security;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

internal static class VipRemoteIntegrationTests
{
    private static void Must(bool ok,string name){if(!ok)throw new Exception(name);Console.WriteLine("PASS: "+name);}
    private static string Pin(X509Certificate2 c)=>Convert.ToHexString(SHA256.HashData(c.RawData));
    private static async Task Refused(Func<Task> action)
    {
        try{await action();}catch(Exception e) when(e is InvalidDataException or InvalidOperationException or HttpRequestException){return;}
        throw new Exception("Expected fail-closed refusal.");
    }
    internal static async Task Run()
    {
        string scope=new('A',64),a=new('B',64),b=new('C',64);
        var dir=Directory.CreateTempSubdirectory("vip-remote-fixture-");
        if(OperatingSystem.IsLinux())File.SetUnixFileMode(dir.FullName,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
        try
        {
            using var caKey=RSA.Create(2048);
            var caReq=new CertificateRequest("CN=Disposable VIP CI CA",caKey,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
            caReq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
            using var ca=caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),DateTimeOffset.UtcNow.AddDays(1));
            using var serverKey=RSA.Create(2048);
            using var clientKey=RSA.Create(2048);
            using var otherKey=RSA.Create(2048);
            X509Certificate2 Issue(RSA key,string name,string eku,bool server)
            {
                var r=new CertificateRequest("CN="+name,key,HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
                r.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
                r.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature|X509KeyUsageFlags.KeyEncipherment,true));
                var usages=new OidCollection();usages.Add(new Oid(eku));
                r.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(usages,true));
                if(server){var san=new SubjectAlternativeNameBuilder();san.AddIpAddress(IPAddress.Loopback);r.CertificateExtensions.Add(san.Build());}
                using var leaf=r.Create(ca,DateTimeOffset.UtcNow.AddMinutes(-2),DateTimeOffset.UtcNow.AddHours(2),RandomNumberGenerator.GetBytes(16));
                return leaf.CopyWithPrivateKey(key);
            }
            using var server=Issue(serverKey,"127.0.0.1","1.3.6.1.5.5.7.3.1",true);
            using var client=Issue(clientKey,"disposable writer","1.3.6.1.5.5.7.3.2",false);
            using var wrong=Issue(otherKey,"wrong writer","1.3.6.1.5.5.7.3.2",false);
            string Write(string name,string content)
            {
                string path=Path.Combine(dir.FullName,name);
                File.WriteAllText(path,content);
                if(OperatingSystem.IsLinux())File.SetUnixFileMode(path,UnixFileMode.UserRead|UnixFileMode.UserWrite);
                return path;
            }
            var caPath=Write("ca.pem",ca.ExportCertificatePem());
            var certPath=Write("client.pem",client.ExportCertificatePem());
            var keyPath=Write("client.key",clientKey.ExportPkcs8PrivateKeyPem());
            var wrongPath=Write("wrong.pem",wrong.ExportCertificatePem());
            var wrongKey=Write("wrong.key",otherKey.ExportPkcs8PrivateKeyPem());
            var json=VipMachineTransport.Json;
            var state=new FleetQuorum.Fence("vip_"+a,10);
            var powered=new Dictionary<string,bool>{{a,true},{b,true}};
            var serving=new Dictionary<string,bool>{{a,false},{b,false}};
            var manual=new Dictionary<string,bool>{{a,false},{b,false}};
            var drained=new Dictionary<string,bool>{{a,false},{b,false}};
            int inflight=0,drainSamples=0,revokes=0,activations=0;
            bool loseFence=false,loseActivation=false;
            Task<FleetQuorum.Fence?> Observe(CancellationToken t)=>Task.FromResult<FleetQuorum.Fence?>(state);
            Task<FleetQuorum.Fence> Revoke(string pin,long epoch,CancellationToken t)
            {
                if(state!=new FleetQuorum.Fence("vip_"+pin,epoch))throw new InvalidDataException("CAS mismatch");
                if(drained[pin]&&inflight!=0)throw new Exception("Revoked before drain completed");
                revokes++;state=new("vip_revoked_"+pin,epoch+1);return Task.FromResult(state);
            }
            using var signer=ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] Message(string oldPin,long epoch,string newPin,long expires)=>
                System.Text.Encoding.UTF8.GetBytes(string.Join("\n",scope,oldPin,epoch.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    newPin,expires.ToString(System.Globalization.CultureInfo.InvariantCulture)));
            Task<FleetQuorum.Fence> Activate(string pin,long epoch,string next,long expires,byte[] sig,CancellationToken t)
            {
                if(state!=new FleetQuorum.Fence("vip_revoked_"+pin,epoch)||powered[pin]||
                    !signer.VerifyData(Message(pin,epoch,next,expires),sig,HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence))
                    throw new InvalidDataException("Isolation or signed permit not verified.");
                state=new("vip_"+next,epoch+1);return Task.FromResult(state);
            }
            var builder=WebApplication.CreateSlimBuilder(Array.Empty<string>());
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(o=>o.Listen(IPAddress.Loopback,0,l=>l.UseHttps(new HttpsConnectionAdapterOptions
            {
                ServerCertificate=server,ClientCertificateMode=ClientCertificateMode.RequireCertificate,
                ClientCertificateValidation=(leaf,_,_)=>VipMachineTransport.Pinned(leaf,ca,Pin(client),"1.3.6.1.5.5.7.3.2")
            })));
            await using var app=builder.Build();
            VipMachineTransport? remoteClient=null;
            async Task<IResult> Agent(HttpContext ctx,bool activate)
            {
                var r=await ctx.Request.ReadFromJsonAsync<VipRemoteNode.Request>(json,ctx.RequestAborted);
                if(r is null||r.Scope!=scope||state!=new FleetQuorum.Fence("vip_"+r.OwnerPin,r.Epoch)||
                    !VipFenceProvider.Pin(r.Nonce)||!powered.ContainsKey(r.OwnerPin)||!powered.ContainsKey(r.OtherPin)||
                    r.OwnerPin==r.OtherPin)return Results.StatusCode(503);
                // The fixture uses a node identity header ONLY inside this
                // disposable test listener; the product pins two fixed origins.
                string pin=ctx.Request.Path=="/v1/vip-node/activate"?r.OwnerPin:
                    r.Nonce.StartsWith("0",StringComparison.Ordinal)?r.OwnerPin:r.OtherPin;
                if(activate)
                {
                    if(loseActivation||powered[r.OtherPin]||!powered[pin])return Results.StatusCode(503);
                    activations++;drained[pin]=false;serving[pin]=true;
                }
                return Results.Json(new VipRemoteNode.Evidence(scope,r.OwnerPin,r.Epoch,r.OtherPin,r.Nonce,pin,
                    pin==r.OwnerPin&&powered[pin]&&serving[pin],pin==r.OtherPin&&powered[pin]&&!serving[pin]),json);
            }
            async Task<IResult> DrainEndpoint(HttpContext ctx)
            {
                var r=await ctx.Request.ReadFromJsonAsync<VipRemoteNode.DrainRequest>(json,ctx.RequestAborted);
                if(r is null||r.Scope!=scope||state.Epoch!=r.Epoch||!state.Transaction.StartsWith("vip_",StringComparison.Ordinal)||
                    !VipFenceProvider.Pin(r.Nonce))return Results.StatusCode(503);
                string owner=state.Transaction[4..];
                if(!powered.ContainsKey(owner)||!powered[owner])return Results.StatusCode(503);
                if(r.Drain){drained[owner]=true;serving[owner]=false;drainSamples++;}
                else if(drained[owner]&&inflight>0){inflight--;drainSamples++;}
                return Results.Json(new VipRemoteNode.DrainEvidence(scope,r.Epoch,r.Nonce,drained[owner],manual[owner],inflight),json);
            }
            app.MapPost("/v1/vip-node/status",(Delegate)(Func<HttpContext,Task<IResult>>)(ctx=>Agent(ctx,false)));
            app.MapPost("/v1/vip-node/activate",(Delegate)(Func<HttpContext,Task<IResult>>)(ctx=>Agent(ctx,true)));
            app.MapPost("/admin/vip-machine/drain",(Delegate)(Func<HttpContext,Task<IResult>>)DrainEndpoint);
            async Task<IResult> Node(HttpContext ctx,string action)
            {
                try
                {
                    var r=await ctx.Request.ReadFromJsonAsync<VipFenceProvider.NodeRequest>(json,ctx.RequestAborted)
                        ??throw new InvalidDataException("Missing request");
                    Task Assert()
                    {
                        if(state!=new FleetQuorum.Fence("vip_"+r.OwnerPin,r.Epoch))throw new InvalidDataException("Wrong owner");
                        return Task.CompletedTask;
                    }
                    async Task<VipRemoteNode.Evidence> NodeStatus(string pin,bool activate,CancellationToken t)
                    {
                        var request=new VipRemoteNode.Request(scope,r.OwnerPin,r.Epoch,r.OtherPin,
                            (pin==r.OwnerPin?"0":"1")+Convert.ToHexString(RandomNumberGenerator.GetBytes(32))[1..]);
                        return VipRemoteNode.Match(request,pin,await remoteClient!.Post<VipRemoteNode.Evidence>(
                            activate?"/v1/vip-node/activate":"/v1/vip-node/status",request,t));
                    }
                    async Task<VipRemoteNode.DrainEvidence> Drain(bool mutate,CancellationToken t)
                    {
                        var request=new VipRemoteNode.DrainRequest(scope,r.Epoch,Convert.ToHexString(RandomNumberGenerator.GetBytes(32)),mutate);
                        return VipRemoteNode.Match(request,await remoteClient!.Post<VipRemoteNode.DrainEvidence>("/admin/vip-machine/drain",request,t));
                    }
                    var evidence=await VipProviderActions.Run(action,r,Assert,
                        _=>Task.FromResult(!powered[r.OwnerPin]),_=>Task.FromResult(!powered[r.OtherPin]),NodeStatus,Drain,ctx.RequestAborted);
                    return Results.Json(evidence,json);
                }
                catch(Exception e) when(e is InvalidDataException or InvalidOperationException){return Results.StatusCode(503);}
            }
            foreach(var action in new[]{"node-status","drain-node","activate-node"})
            {
                var selected=action;
                app.MapPost("/v1/vip/"+selected,(Delegate)(Func<HttpContext,Task<IResult>>)(ctx=>Node(ctx,selected)));
            }
            async Task<IResult> HardFence(HttpContext ctx)
            {
                var r=await ctx.Request.ReadFromJsonAsync<VipFenceProvider.Request>(json,ctx.RequestAborted);
                if(r is null||r.Scope!=scope||state!=new FleetQuorum.Fence("vip_revoked_"+r.OldPin,r.RevokedEpoch)||loseFence)
                    return Results.StatusCode(503);
                powered[r.OldPin]=false;serving[r.OldPin]=false;
                long expiry=DateTimeOffset.UtcNow.ToUnixTimeSeconds()+60;
                var sig=signer.SignData(Message(r.OldPin,r.RevokedEpoch,r.NewPin,expiry),HashAlgorithmName.SHA256,DSASignatureFormat.Rfc3279DerSequence);
                return Results.Json(new VipFenceProvider.Permit(scope,r.OldPin,r.RevokedEpoch,r.NewPin,expiry,Convert.ToBase64String(sig)),json);
            }
            app.MapPost("/v1/vip/hard-fence",(Delegate)(Func<HttpContext,Task<IResult>>)HardFence);
            await app.StartAsync();
            string origin=app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            string Config(string cert,string key,string pin,string name)=>Write(name,JsonSerializer.Serialize(
                new VipFenceProvider.Settings(origin,pin,caPath,cert,key,scope,[a,b]),json));
            using var agentTransport=VipMachineTransport.Open(new(origin,Pin(server),caPath,certPath,keyPath));
            remoteClient=agentTransport;
            using var provider=VipFenceProvider.Open(Config(certPath,keyPath,Pin(server),"writer.json"),scope,a,b);
            using var wrongClient=VipFenceProvider.Open(Config(wrongPath,wrongKey,Pin(server),"wrong.json"),scope,a,b);
            await Refused(()=>wrongClient.NodeAction("node-status",scope,a,10,b,default));
            using var wrongServer=VipFenceProvider.Open(Config(certPath,keyPath,new string('D',64),"wrong-server.json"),scope,a,b);
            await Refused(()=>wrongServer.NodeAction("node-status",scope,a,10,b,default));
            var ready=await provider.NodeAction("node-status",scope,a,10,b,default);
            Must(!ready.OwnerServing&&ready.OtherEligible&&ready.Quiescent,"real pinned mTLS observes failed owner and eligible standby");
            await Refused(()=>provider.NodeAction("node-status",scope,a,9,b,default));
            var journalPath=Path.Combine(dir.FullName,"transitions");
            using(var journal=new VipAutomaticJournal(journalPath,scope,a,b))
            {
                var intent=new VipAutomaticJournal.Transition(scope,a,10,b,"failover");journal.Begin(intent);
                loseFence=true;
                await Refused(()=>VipAutomaticController.ExecuteTransition(scope,intent,journal,Observe,Revoke,provider.Fence,Activate,provider.NodeAction,default));
                Must(state.Transaction=="vip_revoked_"+a&&journal.Pending==intent&&activations==0,"provider failure leaves revoked state and durable intent");
            }
            using(var journal=new VipAutomaticJournal(journalPath,scope,a,b))
            {
                loseFence=false;loseActivation=true;
                var intent=journal.Pending!;
                await Refused(()=>VipAutomaticController.ExecuteTransition(scope,intent,journal,Observe,Revoke,provider.Fence,Activate,provider.NodeAction,default));
                Must(state.Transaction=="vip_"+b&&!powered[a]&&!serving[b]&&journal.Pending==intent,"failed successor startup retains pending recovery");
                loseActivation=false;
                await VipAutomaticController.ExecuteTransition(scope,intent,journal,Observe,Revoke,provider.Fence,Activate,provider.NodeAction,default);
                Must(state.Epoch==12&&serving[b]&&!powered[a]&&journal.Pending is null&&revokes==1,"exact recovery activates successor without another ownership transfer");
                powered[a]=true; // fixture simulates independently approved standby rearm, not production power-on
                manual[b]=true;inflight=5;
                var back=new VipAutomaticJournal.Transition(scope,b,12,a,"failback");journal.Begin(back);
                await Refused(()=>VipAutomaticController.ExecuteTransition(scope,back,journal,Observe,Revoke,provider.Fence,Activate,provider.NodeAction,default));
                Must(state.Epoch==12&&inflight==5,"manual maintenance prevents automatic failback");
                manual[b]=false;drained[b]=true;serving[b]=false;
                await VipAutomaticController.ExecuteTransition(scope,back,journal,Observe,Revoke,provider.Fence,Activate,provider.NodeAction,default);
                Must(state.Transaction=="vip_"+a&&state.Epoch==14&&serving[a]&&!powered[b]&&inflight==0&&drainSamples>=2&&journal.Pending is null,
                    "recovered failback waits for zero active requests, fences predecessor and activates preferred owner");
            }
            await app.StopAsync();
            Console.WriteLine("PASS: actual controller-to-provider and provider-to-node loopback mTLS transport and production transition/provider decision code; fixture Raft and BMC state only, not physical acceptance.");
        }
        finally{dir.Delete(true);}
    }
}
