using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;

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
        try
        {
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
            var metricsPortSource=new TcpListener(IPAddress.Loopback,0);
            metricsPortSource.Start();var metricsPort=((IPEndPoint)metricsPortSource.LocalEndpoint).Port;metricsPortSource.Stop();
            int UnusedPort()
            {
                using var source=new TcpListener(IPAddress.Loopback,0);
                source.Start();
                return ((IPEndPoint)source.LocalEndpoint).Port;
            }
            var secondaryPort=UnusedPort();
            while(secondaryPort==port || secondaryPort==metricsPort) secondaryPort=UnusedPort();
            var urlsPort=UnusedPort();
            while(urlsPort==port || urlsPort==metricsPort || urlsPort==secondaryPort) urlsPort=UnusedPort();
            var defaultHttpPort=UnusedPort();
            while(defaultHttpPort==port || defaultHttpPort==metricsPort || defaultHttpPort==secondaryPort || defaultHttpPort==urlsPort)
                defaultHttpPort=UnusedPort();
            var defaultHttpsPort=UnusedPort();
            while(defaultHttpsPort==port || defaultHttpsPort==metricsPort || defaultHttpsPort==secondaryPort ||
                defaultHttpsPort==urlsPort || defaultHttpsPort==defaultHttpPort)
                defaultHttpsPort=UnusedPort();
            var metricsBody = ValidMetrics();
            var agentStatusBody = ValidAgentStatus();
            var metricsBuilder = WebApplication.CreateSlimBuilder();
            metricsBuilder.WebHost.ConfigureKestrel(server => server.Listen(IPAddress.Loopback,metricsPort));
            await using var metricsApp = metricsBuilder.Build();
            metricsApp.MapGet("/metrics", () => Results.Text(Volatile.Read(ref metricsBody),
                "text/plain; version=0.0.4; charset=utf-8"));
            metricsApp.MapGet("/agent-report-status", () => Results.Text(
                Volatile.Read(ref agentStatusBody), "application/json"));
            await metricsApp.StartAsync();
            var cfg=Path.Combine(dir,"appsettings.json");
            void SetPins(string[] pins,string[]? revoked=null) =>
                File.WriteAllText(cfg,JsonSerializer.Serialize(new {
                    Agent = new {
                        TrustedClientThumbprints = pins,
                        RevokedClientThumbprints = revoked ?? Array.Empty<string>(),
                        LabOnlyClientCaCertificatePath = caPem,
                        GslbMetricsPort = metricsPort,
                        EnableConfigChanges=false,
                        EnableEngineConfigChanges=false,
                        EnableServiceActions=false
                    }
                }));
            SetPins([old.Thumbprint]);
            ProcessStartInfo StartAgent(string agentUrl)
            {
                var start=new ProcessStartInfo("dotnet") {
                    WorkingDirectory=dir,UseShellExecute=false,CreateNoWindow=true,
                    RedirectStandardOutput=true,RedirectStandardError=true
                };
                start.ArgumentList.Add(dll);
                start.Environment["Kestrel__Endpoints__AgentHttps__Url"]=agentUrl;
                start.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Path"]=pfx;
                start.Environment["Kestrel__Endpoints__AgentHttps__Certificate__Password"]=pass;
                return start;
            }
            async Task<bool> IsLoopbackPortOpenAsync(int candidatePort)
            {
                using var probe=new TcpClient();
                try
                {
                    using var timeout=new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
                    await probe.ConnectAsync(IPAddress.Loopback,candidatePort,timeout.Token);
                    return true;
                }
                catch (Exception ex) when (ex is SocketException or OperationCanceledException)
                { return false; }
            }
            async Task RequireLabListenerRejectedAsync(string name,ProcessStartInfo start,
                params int[] forbiddenPorts)
            {
                using var rejected=Process.Start(start) ??
                    throw new Exception("Could not start lab listener rejection case: "+name);
                var rejectedOut=rejected.StandardOutput.ReadToEndAsync();
                var rejectedError=rejected.StandardError.ReadToEndAsync();
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(8));
                try { await rejected.WaitForExitAsync(timeout.Token); }
                catch (OperationCanceledException)
                {
                    // Some Windows hosting threads can outlive the startup throw.
                    // Confirm no endpoint was opened, then stop the failed process.
                    foreach(var candidatePort in forbiddenPorts)
                        if(await IsLoopbackPortOpenAsync(candidatePort))
                        {
                            rejected.Kill(entireProcessTree:true);
                            await rejected.WaitForExitAsync();
                            throw new Exception("Rejected lab startup nevertheless opened a listener for "+name);
                        }
                    rejected.Kill(entireProcessTree:true);
                    await rejected.WaitForExitAsync();
                    var timedOutOutput=await rejectedOut;
                    var timedOutError=await rejectedError;
                    if(!timedOutError.Contains(
                        "Isolated client test CA is restricted to HTTPS loopback-only listeners",
                        StringComparison.Ordinal))
                        throw new Exception("Public lab listener was not rejected by the specific trust guard: "+name+
                            "; stdout="+timedOutOutput[..Math.Min(1500,timedOutOutput.Length)]+
                            "; stderr="+timedOutError[..Math.Min(3000,timedOutError.Length)]);
                    if(timedOutOutput.Contains(pass,StringComparison.Ordinal) ||
                        timedOutError.Contains(pass,StringComparison.Ordinal) ||
                        (timedOutOutput+timedOutError).Contains("BEGIN PRIVATE KEY",StringComparison.Ordinal))
                        throw new Exception("Lab-listener rejection diagnostics exposed secret material for "+name);
                    Console.WriteLine("PASS: lab self-signed trust startup refused before binding for "+name);
                    return;
                }
                var errorText=await rejectedError;
                var outputText=await rejectedOut;
                if(rejected.ExitCode==0 || !errorText.Contains(
                    "Isolated client test CA is restricted to HTTPS loopback-only listeners",
                    StringComparison.Ordinal))
                    throw new Exception("Public lab listener did not fail closed with the expected guard for "+name);
                var combined=outputText+errorText;
                if(combined.Contains(pass,StringComparison.Ordinal) ||
                    combined.Contains("BEGIN PRIVATE KEY",StringComparison.Ordinal))
                    throw new Exception("Lab-listener rejection diagnostics exposed secret material for "+name);
                Console.WriteLine("PASS: lab self-signed trust startup refused for "+name);
            }

            // Exercise actual executable startup, not just a helper predicate.
            var directPublic=StartAgent("https://0.0.0.0:"+port);
            await RequireLabListenerRejectedAsync("public wildcard AgentHttps endpoint",directPublic);
            var secondaryPublic=StartAgent("https://127.0.0.1:"+port);
            secondaryPublic.Environment["Kestrel__Endpoints__ManagementHttps__Url"]="https://0.0.0.0:"+secondaryPort;
            secondaryPublic.Environment["Kestrel__Endpoints__ManagementHttps__Certificate__Path"]=pfx;
            secondaryPublic.Environment["Kestrel__Endpoints__ManagementHttps__Certificate__Password"]=pass;
            await RequireLabListenerRejectedAsync("secondary public Kestrel endpoint",secondaryPublic,port,secondaryPort);
            var urlsPublic=StartAgent("https://127.0.0.1:"+port);
            urlsPublic.Environment["ASPNETCORE_URLS"]="https://0.0.0.0:"+urlsPort;
            await RequireLabListenerRejectedAsync("public ASPNETCORE_URLS binding",urlsPublic,port,urlsPort);
            var httpPortsPublic=StartAgent("https://127.0.0.1:"+port);
            httpPortsPublic.Environment["ASPNETCORE_HTTP_PORTS"]=defaultHttpPort.ToString();
            await RequireLabListenerRejectedAsync("wildcard ASPNETCORE_HTTP_PORTS binding",
                httpPortsPublic,port,defaultHttpPort);
            var httpsPortsPublic=StartAgent("https://127.0.0.1:"+port);
            httpsPortsPublic.Environment["ASPNETCORE_HTTPS_PORTS"]=defaultHttpsPort.ToString();
            await RequireLabListenerRejectedAsync("wildcard ASPNETCORE_HTTPS_PORTS binding",
                httpsPortsPublic,port,defaultHttpsPort);

            var info=StartAgent("https://127.0.0.1:"+port);
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
                var runtimeUrl="https://127.0.0.1:"+port+"/agent/v1/engines/gslb/runtime-status";
                await RequireStatus(unpinned,runtimeUrl,HttpStatusCode.Forbidden,
                    "untrusted client cannot read per-agent GSLB runtime status");
                await RequireRuntimeStatus(a,runtimeUrl);
                Volatile.Write(ref agentStatusBody, ValidAgentStatus(includeClientIp: true));
                await RequireStatus(a,runtimeUrl,HttpStatusCode.BadGateway,
                    "agent status relay rejects unexpected private fields");
                Volatile.Write(ref agentStatusBody, ValidAgentStatus());
                Volatile.Write(ref metricsBody,"# TYPE gatewaycore_gslb_report_gated_sites gauge\n");
                await RequireStatus(a,runtimeUrl,HttpStatusCode.BadGateway,
                    "invalid local metric contract is rejected by authenticated runtime endpoint");
                Volatile.Write(ref metricsBody,ValidMetrics());
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
                var auditOutput=(await stdout)+"\n"+(await stderr);
                try
                {
                    if(!auditOutput.Contains("Rejected lab TLS client certificate",StringComparison.Ordinal) ||
                        !auditOutput.Contains(expired.Thumbprint.ToUpperInvariant(),StringComparison.Ordinal) ||
                        !auditOutput.Contains("NotTimeValid",StringComparison.Ordinal))
                        throw new Exception("Expired lab client certificate rejection did not produce a bounded fingerprint/status audit record");
                    if(auditOutput.Contains(pass,StringComparison.Ordinal) ||
                        auditOutput.Contains("BEGIN PRIVATE KEY",StringComparison.Ordinal))
                        throw new Exception("Agent certificate audit output exposed password or private-key material");
                    Console.WriteLine("PASS: rejected client audit contains only certificate fingerprint and chain status");
                }
                finally { await metricsApp.StopAsync(); }
            }
        }
        }
        finally
        {
            if(Directory.Exists(dir)) Directory.Delete(dir,true);
        }
        if(Directory.Exists(dir))
            throw new Exception("Temporary PKI directory survived acceptance; private keys must not remain as CI artifacts");
        Console.WriteLine("PASS: disposable PKI directory and private-key files removed after acceptance");
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

    private static async Task RequireRuntimeStatus(HttpClient client,string url)
    {
        using var response=await client.GetAsync(url);
        if(response.StatusCode!=HttpStatusCode.OK)
            throw new Exception("FAIL: GSLB runtime status expected 200, got "+response.StatusCode);
        using var payload=JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root=payload.RootElement;
        if(root.GetProperty("type").GetString()!="loopback-gslb-runtime-metrics" ||
            root.GetProperty("quorumTargets").GetProperty("quorum").GetInt32()!=1 ||
            root.GetProperty("quorumTargets").GetProperty("configured").GetInt32()!=2 ||
            root.GetProperty("observerReports").GetProperty("healthy").GetInt32()!=2 ||
            root.GetProperty("observerReports").GetProperty("staleOrMissing").GetInt32()!=1 ||
            root.GetProperty("observerAgents").GetArrayLength()!=2 ||
            root.GetProperty("observerAgents")[0].GetProperty("agentId").GetString()!="agent-1" ||
            root.GetProperty("observerAgents")[0].GetProperty("lastAcceptedAgeSeconds").GetInt64()!=60 ||
            root.GetProperty("observerAgents")[0].GetProperty("rejectedTotal").GetInt32()!=1 ||
            root.GetProperty("observerAgents")[1].GetProperty("staleOrMissingReports").GetInt32()!=2 ||
            root.GetProperty("observerAgents")[1].GetProperty("lastAcceptedUtc").ValueKind!=JsonValueKind.Null ||
            root.GetProperty("observerAgents")[0].TryGetProperty("clientIp",out _) ||
            root.GetProperty("observerAgents")[0].TryGetProperty("certificateThumbprint",out _))
            throw new Exception("FAIL: GSLB runtime status summary mismatch");
        Console.WriteLine("PASS: mTLS agent relays bounded loopback quorum, freshness and privacy-safe per-agent status");
    }

    private static string ValidAgentStatus(bool includeClientIp=false)
    {
        var first = new Dictionary<string, object?>
        {
            ["agentId"]="agent-1", ["lastAcceptedUtc"]="2026-11-18T09:59:00+00:00",
            ["lastAcceptedAgeSeconds"]=60, ["rejectedTotal"]=1,
            ["freshReports"]=2, ["staleOrMissingReports"]=0
        };
        if (includeClientIp) first["clientIp"]="203.0.113.10";
        return JsonSerializer.Serialize(new
        {
            type="loopback-gslb-agent-report-status", checkedUtc="2026-11-18T10:00:00+00:00",
            agents=new object[]
            {
                first,
                new { agentId="agent-2", lastAcceptedUtc=(DateTimeOffset?)null,
                    lastAcceptedAgeSeconds=(long?)null, rejectedTotal=0,
                    freshReports=0, staleOrMissingReports=2 }
            }
        });
    }

    private static string ValidMetrics() => """
# TYPE gatewaycore_gslb_report_gated_sites gauge
gatewaycore_gslb_report_gated_sites 2
gatewaycore_gslb_agent_quorum_targets{state="quorum"} 1
gatewaycore_gslb_agent_quorum_targets{state="below_quorum"} 1
gatewaycore_gslb_agent_evidence_reports{state="healthy"} 2
gatewaycore_gslb_agent_evidence_reports{state="unhealthy"} 1
gatewaycore_gslb_agent_evidence_reports{state="unknown"} 0
gatewaycore_gslb_agent_evidence_reports{state="stale_or_missing"} 1
""";
}
