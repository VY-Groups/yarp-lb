using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Disposable loopback TLS negative test against the actual GatewayAgent Kestrel
/// listener. Self-signed certificates exist only in a temporary CI directory.
/// </summary>
public static class AgentTlsNegativeAcceptance
{
    public static async Task RunAsync()
    {
        var agentDll = Path.Combine(Directory.GetCurrentDirectory(), "GatewayAgent", "bin",
            "Release", "net10.0", "SpeedSignGatewayAgent.dll");
        if (!File.Exists(agentDll))
            throw new FileNotFoundException("Build GatewayAgent before TLS acceptance", agentDll);
        var folder = Path.Combine(Path.GetTempPath(), "yarp-agent-tls-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        var portListener = new TcpListener(IPAddress.Loopback, 0);
        portListener.Start();
        var port = ((IPEndPoint)portListener.LocalEndpoint).Port;
        portListener.Stop();
        var secret = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        using var serverKey = RSA.Create(2048);
        var serverRequest = new CertificateRequest("CN=localhost", serverKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false,false,0,true));
        serverRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,true));
        var san = new SubjectAlternativeNameBuilder();
        san.AddDnsName("localhost");
        san.AddIpAddress(IPAddress.Loopback);
        serverRequest.CertificateExtensions.Add(san.Build());
        using var serverCert = serverRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1));
        var pfx = Path.Combine(folder,"server.pfx");
        File.WriteAllBytes(pfx,serverCert.Export(X509ContentType.Pfx,secret));
        // The trusted client pin is deliberately synthetic and cannot be met by
        // any unauthenticated HTTP caller in this test.
        using var signer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trustedRequest = new CertificateRequest("CN=pinned-client",signer,HashAlgorithmName.SHA256);
        using var syntheticPin = trustedRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddHours(1));
        var info = new ProcessStartInfo("dotnet") {
            UseShellExecute=false,CreateNoWindow=true,
            RedirectStandardOutput=true,RedirectStandardError=true
        };
        info.ArgumentList.Add(agentDll);
        info.Environment["Kestrel__Endpoints__AgentHttps__Url"]="https://127.0.0.1:"+port;
        info.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Path"]=pfx;
        info.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Password"]=secret;
        info.Environment["Agent__TrustedClientThumbprints__0"]=syntheticPin.Thumbprint;
        info.Environment["Agent__EnableConfigChanges"]="false";
        info.Environment["Agent__EnableEngineConfigChanges"]="false";
        info.Environment["Agent__EnableServiceActions"]="false";
        using var process = Process.Start(info) ?? throw new Exception("Could not launch GatewayAgent");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        try
        {
            var ready = false;
            for (var i = 0;i<100;i++)
            {
                using var tcp = new TcpClient();
                try { await tcp.ConnectAsync(IPAddress.Loopback,port); ready=true; break; }
                catch (SocketException) { }
                if (process.HasExited) break;
                await Task.Delay(100);
            }
            if (!ready) throw new Exception("GatewayAgent HTTPS listener never became ready");
            using var handler = new HttpClientHandler { UseProxy=false };
            // The server-only test identity is pinned; this does NOT disable
            // or alter server-side client certificate validation.
            handler.ServerCertificateCustomValidationCallback = (_,server,_,_) =>
                server?.Thumbprint == serverCert.Thumbprint;
            using var http = new HttpClient(handler) {Timeout=TimeSpan.FromSeconds(3)};
            var uri = "https://127.0.0.1:"+port;
            await MustDeny(http, new HttpRequestMessage(HttpMethod.Get,uri+"/agent/v1/status"),
                "missing client certificate denied at real HTTPS status endpoint");
            await MustDeny(http, new HttpRequestMessage(HttpMethod.Post,uri+"/agent/v1/engines/l4/config/prepare") {
                Content = new StringContent("{}", System.Text.Encoding.UTF8,"application/json")
            }, "missing client certificate denied at real HTTPS engine-change endpoint");
            Console.WriteLine("PASS: real Kestrel HTTPS refuses unauthenticated agent calls");
        }
        finally
        {
            if (!process.HasExited) process.Kill(entireProcessTree:true);
            await process.WaitForExitAsync();
            _ = await stdout;
            _ = await stderr;
            Directory.Delete(folder,true);
        }
    }

    private static async Task MustDeny(HttpClient client,HttpRequestMessage request,string name)
    {
        using(request)
        {
            try
            {
                using var response = await client.SendAsync(request);
                if (response.StatusCode is not (HttpStatusCode.BadRequest or
                    HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden))
                    throw new Exception("FAIL: "+name+" unexpected HTTP "+response.StatusCode);
            }
            catch (HttpRequestException) { /* TLS handshake rejected client */ }
            catch (TaskCanceledException ex) { throw new Exception("FAIL: TLS auth request timed out",ex); }
        }
        Console.WriteLine("PASS: "+name);
    }
}
