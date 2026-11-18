using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

public static class ProductLinuxStartupSmoke
{
    public static async Task RunAsync()
    {
        if (!OperatingSystem.IsLinux()) return;
        var dll=Path.Combine(Directory.GetCurrentDirectory(),"bin","Release","net10.0","GatewayCoreYarp.dll");
        if (!File.Exists(dll))
            throw new FileNotFoundException("Build shipping Control Center before smoke test",dll);
        const UnixFileMode privateDir=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
        const UnixFileMode secret=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        var root=Path.Combine(Path.GetTempPath(),"onprem-product-start-"+Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root,privateDir);
        var state=Path.Combine(root,"state");
        Directory.CreateDirectory(state,privateDir);
        var cfgDir=Path.Combine(state,"config");
        Directory.CreateDirectory(cfgDir,privateDir);
        var configPath=Path.Combine(cfgDir,"appsettings.json");
        File.WriteAllText(configPath,JsonSerializer.Serialize(new {
            Logging=new {LogLevel=new Dictionary<string,string> {
                ["Default"]="Warning",["Yarp.ReverseProxy"]="Warning"
            }},
            ReverseProxy=new {
                Routes=new Dictionary<string,object>(),
                Clusters=new Dictionary<string,object>()
            }
        }));
        File.SetUnixFileMode(configPath,secret);
        using var rsa=RSA.Create(3072);
        var req=new CertificateRequest("CN=CI Linux key protection",rsa,
            HashAlgorithmName.SHA256,RSASignaturePadding.Pkcs1);
        using var cert=req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(7));
        var pfx=Path.Combine(root,"keys.pfx");
        var passwordFile=Path.Combine(root,"password");
        var password=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        File.WriteAllBytes(pfx,cert.Export(X509ContentType.Pfx,password));
        File.WriteAllText(passwordFile,password);
        File.SetUnixFileMode(pfx,secret);
        File.SetUnixFileMode(passwordFile,secret);
        using var listener=new TcpListener(IPAddress.Loopback,0);
        listener.Start();
        var port=((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var info=new ProcessStartInfo("dotnet") {
            WorkingDirectory=Directory.GetCurrentDirectory(),
            UseShellExecute=false,RedirectStandardOutput=true,
            RedirectStandardError=true,CreateNoWindow=true
        };
        info.ArgumentList.Add(dll);
        info.Environment["ASPNETCORE_ENVIRONMENT"]="Production";
        info.Environment["ASPNETCORE_URLS"]="http://127.0.0.1:"+port;
        info.Environment["YARP_CONTROL_PLANE_DIR"]=state;
        info.Environment["YARP_RUNTIME_CONFIG_PATH"]=configPath;
        info.Environment["YARP_LINUX_DP_CERT_PFX_PATH"]=pfx;
        info.Environment["YARP_LINUX_DP_CERT_PASSWORD_FILE"]=passwordFile;
        info.Environment.Remove("YARP_EC2_LAB_MODE");
        using var proc=Process.Start(info) ??
            throw new Exception("Could not start real Control Center in Linux production mode");
        var stdout=proc.StandardOutput.ReadToEndAsync();
        var stderr=proc.StandardError.ReadToEndAsync();
        var ready=false;
        try
        {
            using var client=new HttpClient(new HttpClientHandler{UseProxy=false}) {
                Timeout=TimeSpan.FromSeconds(2)
            };
            for(var i=0;i<100;i++)
            {
                if (proc.HasExited) break;
                try
                {
                    using var health=await client.GetAsync("http://127.0.0.1:"+port+"/gateway/health");
                    if(health.IsSuccessStatusCode){ready=true;break;}
                }
                catch(HttpRequestException) {}
                catch(TaskCanceledException) {}
                await Task.Delay(100);
            }
            if(!ready)
                throw new Exception("Real Control Center never became ready on Linux with non-DPAPI X509 key protection");
            Console.WriteLine("PASS: shipping Control Center starts on Ubuntu in Production mode with private RSA X509 key ring");
            var keyDirectory=Path.Combine(state,"data-protection-keys");
            var firstKeyFiles=Directory.GetFiles(keyDirectory,"key-*.xml");
            if(firstKeyFiles.Length==0)
                throw new Exception("Production Linux startup did not persist a Data Protection key");
            var firstKeyIds=firstKeyFiles.Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
            foreach(var keyFile in firstKeyFiles)
            {
                var xml=await File.ReadAllTextAsync(keyFile);
                if(!xml.Contains("<encryptedSecret",StringComparison.Ordinal) ||
                    xml.Contains("<masterKey",StringComparison.Ordinal))
                    throw new Exception("Production Linux Data Protection key XML is not certificate-wrapped");
            }
            Console.WriteLine("PASS: shipping Control Center persisted only certificate-wrapped Linux Data Protection key material");
            using var metrics=await client.GetAsync("http://127.0.0.1:"+port+"/gateway/metrics");
            metrics.EnsureSuccessStatusCode();
            var body=await metrics.Content.ReadAsStringAsync();
            if (!body.Contains("yarp_control_gc_collections_total{generation=\"2\"}") ||
                !body.Contains("yarp_logging_dropped_total ") ||
                !body.Contains("yarp_logging_dropped_high_priority_total "))
                throw new Exception("Production monitoring metrics missing GC Gen2 or log-drop counters");
            Console.WriteLine("PASS: real production Linux gateway exposes loopback-only Gen2 and drop counters");

            // Restart the shipping process against the same protected key ring and
            // certificate. Use a fresh listener port to avoid any socket reuse assumptions.
            proc.Kill(entireProcessTree:true);
            await proc.WaitForExitAsync();
            using var restartListener=new TcpListener(IPAddress.Loopback,0);
            restartListener.Start();
            var restartPort=((IPEndPoint)restartListener.LocalEndpoint).Port;
            restartListener.Stop();
            info.Environment["ASPNETCORE_URLS"]="http://127.0.0.1:"+restartPort;
            using var restarted=Process.Start(info) ??
                throw new Exception("Could not restart the real Control Center against its existing Linux key ring");
            var restartStdout=restarted.StandardOutput.ReadToEndAsync();
            var restartStderr=restarted.StandardError.ReadToEndAsync();
            var restartedReady=false;
            try
            {
                using var restartClient=new HttpClient(new HttpClientHandler{UseProxy=false})
                {
                    Timeout=TimeSpan.FromSeconds(2)
                };
                for(var i=0;i<100;i++)
                {
                    if(restarted.HasExited) break;
                    try
                    {
                        using var health=await restartClient.GetAsync("http://127.0.0.1:"+restartPort+"/gateway/health");
                        if(health.IsSuccessStatusCode){restartedReady=true;break;}
                    }
                    catch(HttpRequestException) {}
                    catch(TaskCanceledException) {}
                    await Task.Delay(100);
                }
                if(!restartedReady)
                    throw new Exception("Production Control Center failed to restart with the existing certificate-wrapped Linux key ring");
                var restartedKeyIds=Directory.GetFiles(keyDirectory,"key-*.xml")
                    .Select(Path.GetFileName).Order(StringComparer.Ordinal).ToArray();
                if(!firstKeyIds.SequenceEqual(restartedKeyIds,StringComparer.Ordinal))
                    throw new Exception("Linux process restart replaced or lost the existing Data Protection key ring");
                Console.WriteLine("PASS: shipping Control Center restarted against the persistent encrypted Linux key ring");
            }
            finally
            {
                if(!restarted.HasExited) restarted.Kill(entireProcessTree:true);
                await restarted.WaitForExitAsync();
                _=await restartStdout;
                _=await restartStderr;
            }
        }
        finally
        {
            if(!proc.HasExited)proc.Kill(entireProcessTree:true);
            await proc.WaitForExitAsync();
            var outText=await stdout;
            var errText=await stderr;
            if(!ready)
                Console.Error.WriteLine("Linux product startup stdout:"+outText[..Math.Min(outText.Length,2500)] +
                    " stderr:"+errText[..Math.Min(errText.Length,5000)]);
            Directory.Delete(root,true);
        }
    }
}
