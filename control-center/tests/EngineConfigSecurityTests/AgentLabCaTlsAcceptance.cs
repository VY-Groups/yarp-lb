using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

/// <summary>
/// Real Kestrel mTLS test using fresh self-signed CA and CA-issued clients.
/// All keys/certificates live in a throwaway CI directory; never published.
/// </summary>
public static class AgentLabCaTlsAcceptance
{
    public static async Task RunAsync()
    {
        var dll=Path.Combine(Directory.GetCurrentDirectory(),"GatewayAgent","bin",
            "Release","net10.0","GatewayCoreGatewayAgent.dll");
        if (!File.Exists(dll)) throw new FileNotFoundException("Build real agent first",dll);
        var dir=Path.Combine(Path.GetTempPath(),"agent-ephemeral-pki-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        using var caKey=RSA.Create(2048);
        var rootReq=new CertificateRequest("CN=ephemeral-agent-ca",caKey,
            HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        rootReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true,false,0,true));
        rootReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign|X509KeyUsageFlags.CrlSign,true));
        using var ca=rootReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-30),
            DateTimeOffset.UtcNow.AddDays(7));
        var caPem=Path.Combine(dir,"ci-root.pem");
        File.WriteAllText(caPem,ca.ExportCertificatePem());
        var old=Issue(ca,"old-controller",DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var newer=Issue(ca,"new-controller",DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var wrong=Issue(ca,"valid-ca-but-unpinned",DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(1));
        var expired=Issue(ca,"expired-controller",DateTimeOffset.UtcNow.AddDays(-10),
            DateTimeOffset.UtcNow.AddDays(-1));
        using(old) using(newer) using(wrong) using(expired)
        {
            using var serverKey=RSA.Create(2048);
            var serverRequest=new CertificateRequest("CN=localhost",serverKey,
                HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
            var san=new SubjectAlternativeNameBuilder();
            san.AddDnsName("localhost");san.AddIpAddress(IPAddress.Loopback);
            serverRequest.CertificateExtensions.Add(san.Build());
            serverRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature |
                    X509KeyUsageFlags.KeyEncipherment,true));
            using var server=serverRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddHours(2));
            var pass=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            var pfx=Path.Combine(dir,"listener.pfx");
            File.WriteAllBytes(pfx,server.Export(X509ContentType.Pfx,pass));
            var portSource=new TcpListener(IPAddress.Loopback,0);
            portSource.Start();var port=((IPEndPoint)portSource.LocalEndpoint).Port;portSource.Stop();
            var cfg=Path.Combine(dir,"appsettings.json");
            void SetPins(string[] pins,string[]? revoked=null) =>
                File.WriteAllText(cfg,JsonSerializer.Serialize(new {
                    Agent = new {
                        TrustedClientThumbprints = pins,
                        RevokedClientThumbprints = revoked ?? Array.Empty<string>(),
                        LabOnlyClientCaCertificatePath = caPem,
                        EnableConfigChanges=false,
                        EnableEngineConfigChanges=false,
                        EnableServiceActions=false
                    }
                }));
            SetPins([old.Thumbprint]);
            var info=new ProcessStartInfo("dotnet") {
                WorkingDirectory=dir,UseShellExecute=false,CreateNoWindow=true,
                RedirectStandardOutput=true,RedirectStandardError=true
            };
            info.ArgumentList.Add(dll);
            info.Environment["Kestrel__Endpoints__AgentHttps__Url"]="https://127.0.0.1:"+port;
            info.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Path"]=pfx;
            info.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Password"]=pass;
            using var process=Process.Start(info) ?? throw new Exception("Agent start failed");
            var stdout=process.StandardOutput.ReadToEndAsync();
            var stderr=process.StandardError.ReadToEndAsync();
            try
            {
                var ready=false;
                for(var i=0;i<100;i++)
                {
                    using var tcp=new TcpClient();
                    try { await tcp.ConnectAsync(IPAddress.Loopback,port);ready=true;break; }
                    catch(SocketException){}
                    if (process.HasExited) break;
                    await Task.Delay(100);
                }
                if(!ready)
                {
                    if(!process.HasExited) process.Kill(entireProcessTree:true);
                    await process.WaitForExitAsync();
                    throw new Exception("Lab CA agent listener failed to bind; stdout=" +
                        (await stdout)[..Math.Min(3000,(await stdout).Length)] +
                        " stderr=" + (await stderr)[..Math.Min(7000,(await stderr).Length)]);
                }
                var url="https://127.0.0.1:"+port+"/agent/v1/status";
                using var a=Client(server,old);
                using var b=Client(server,newer);
                using var unpinned=Client(server,wrong);
                using var tooOld=Client(server,expired);
                await RequireStatus(a,url,HttpStatusCode.OK,"valid CA-signed and pinned client succeeds");
                await RequireStatus(unpinned,url,HttpStatusCode.Forbidden,
                    "valid CA-signed but unpinned client denied by real agent middleware");
                // The lab-mode chain policy and the live auth policy both reject expiry.
                await RequireDenied(tooOld,url,"CA-signed expired certificate denied");
                // JSON configuration reload must be sufficient for two-cert overlap,
                // with existing TCP listener PID unchanged.
                SetPins([old.Thumbprint,newer.Thumbprint]);
                await Task.Delay(1800);
                await RequireStatus(a,url,HttpStatusCode.OK,"old pin survives overlap");
                await RequireStatus(b,url,HttpStatusCode.OK,"new pin admitted without listener restart");
                SetPins([newer.Thumbprint]);
                await Task.Delay(1800);
                await RequireStatus(a,url,HttpStatusCode.Forbidden,
                    "removed old pin denied without process restart");
                await RequireStatus(b,url,HttpStatusCode.OK,"new pin survives old pin removal");
                SetPins([newer.Thumbprint],[newer.Thumbprint]);
                await Task.Delay(1800);
                await RequireStatus(b,url,HttpStatusCode.Forbidden,
                    "emergency revoked thumbprint denied on live CA-signed TLS");
                SetPins(Array.Empty<string>());
                await Task.Delay(1800);
                await RequireStatus(b,url,HttpStatusCode.Forbidden,
                    "missing pins fail closed after runtime configuration reload");
                if(process.HasExited) throw new Exception("Agent exited during certificate rotation");
                Console.WriteLine("PASS: real agent local CA, wrong pin, expiry, live rotation, denylist");
            }
            finally
            {
                if(!process.HasExited)process.Kill(entireProcessTree:true);
                await process.WaitForExitAsync();
                _=await stdout;_=await stderr;
                Directory.Delete(dir,true);
            }
        }
    }

    private static X509Certificate2 Issue(X509Certificate2 ca,string cn,
        DateTimeOffset from,DateTimeOffset until)
    {
        using var key=RSA.Create(2048);
        var req=new CertificateRequest("CN="+cn,key,HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature,true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection{new Oid("1.3.6.1.5.5.7.3.2")},true));
        using var issued=req.Create(ca,from,until,RandomNumberGenerator.GetBytes(16));
        using var combined=issued.CopyWithPrivateKey(key);
        var flags=OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.UserKeySet|X509KeyStorageFlags.PersistKeySet|X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.EphemeralKeySet;
        // Isolated, throwaway test only.
        return new X509Certificate2(combined.Export(X509ContentType.Pfx,"test-pfx"),
            "test-pfx",flags);
    }

    private static HttpClient Client(X509Certificate2 server,X509Certificate2 cert)
    {
        var handler=new HttpClientHandler {UseProxy=false,
            ClientCertificateOptions=ClientCertificateOption.Manual};
        handler.ClientCertificates.Add(cert);
        handler.ServerCertificateCustomValidationCallback=(_,peer,_,_) =>
            peer?.Thumbprint==server.Thumbprint;
        return new HttpClient(handler) {Timeout=TimeSpan.FromSeconds(5)};
    }
    private static async Task RequireStatus(HttpClient client,string url,
        HttpStatusCode expected,string name)
    {
        using var result=await client.GetAsync(url);
        if(result.StatusCode!=expected)
            throw new Exception("FAIL: "+name+" expected "+expected+" got "+result.StatusCode);
        Console.WriteLine("PASS: "+name);
    }
    private static async Task RequireDenied(HttpClient client,string url,string name)
    {
        try
        {
            using var result=await client.GetAsync(url);
            if(result.IsSuccessStatusCode) throw new Exception("FAIL: "+name);
            if(result.StatusCode is not (HttpStatusCode.BadRequest or
                HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden))
                throw new Exception("FAIL: unexpected response "+result.StatusCode);
        }
        catch(HttpRequestException){}
        Console.WriteLine("PASS: "+name);
    }
}
