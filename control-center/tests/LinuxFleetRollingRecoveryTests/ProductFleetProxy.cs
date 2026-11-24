using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

internal sealed class ProductFleetProxy : IDisposable
{
    private readonly Process process;
    private readonly Task<string> stdout,stderr;
    private readonly string config;
    public string Address {get;}
    private ProductFleetProxy(Process p,string path,string address)
    {
        process=p;config=path;Address=address;
        stdout=p.StandardOutput.ReadToEndAsync();stderr=p.StandardError.ReadToEndAsync();
    }
    private static void WriteConfig(string path,
        IReadOnlyDictionary<string,(string Address,bool Draining)> destinations)
    {
        if(destinations.Count==0||destinations.Values.All(x=>x.Draining))
            throw new InvalidOperationException("Fixture must retain an active destination");
        var payload=new {
            Logging=new {LogLevel=new Dictionary<string,string> {["Default"]="Warning"}},
            ReverseProxy=new {
                Routes=new Dictionary<string,object> {
                    ["fleet-fixture"]=new {ClusterId="fleet-fixture",
                        Match=new {Path="/fleet/{**catch-all}"},
                        Transforms=new[]{new {PathRemovePrefix="/fleet"}}}},
                Clusters=new Dictionary<string,object> {
                    ["fleet-fixture"]=new {LoadBalancingPolicy="RoundRobin",
                        Destinations=destinations.ToDictionary(x=>x.Key,x=>(object)new {
                            Address=x.Value.Address+"/",
                            Metadata=new Dictionary<string,string> {
                                ["TrafficState"]=x.Value.Draining?"draining":"active"}})}}}
        };
        var temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
        try
        {
            using(var stream=new FileStream(temp,new FileStreamOptions {
                Mode=FileMode.CreateNew,Access=FileAccess.Write,Share=FileShare.None,
                UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite}))
            {
                JsonSerializer.Serialize(stream,payload);
                stream.Flush(flushToDisk:true);
            }
            File.Move(temp,path,overwrite:true);
        }
        finally {if(File.Exists(temp))File.Delete(temp);}
    }

    public void Apply(IReadOnlyDictionary<string,(string Address,bool Draining)> destinations) =>
        WriteConfig(config,destinations);

    public static async Task<ProductFleetProxy> Start(string root,
        (string Pfx,string Password) cert,HttpClient http,
        IReadOnlyDictionary<string,(string Address,bool Draining)> destinations)
    {
        var dll=Environment.GetEnvironmentVariable("GATEWAYCORE_PRODUCT_DLL");
        var work=Environment.GetEnvironmentVariable("GATEWAYCORE_PRODUCT_WORKDIR");
        if(string.IsNullOrEmpty(dll)||!Path.IsPathFullyQualified(dll)||!File.Exists(dll)||
            string.IsNullOrEmpty(work)||!Directory.Exists(work))
            throw new InvalidOperationException("Shipping gateway executable must be built for cutover acceptance");
        var dirMode=UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute;
        Directory.CreateDirectory(root,dirMode);
        var configDir=Path.Combine(root,"config");Directory.CreateDirectory(configDir,dirMode);
        var config=Path.Combine(configDir,"appsettings.json");
        WriteConfig(config,destinations);
        using var listener=new TcpListener(IPAddress.Loopback,0);
        listener.Start();
        var port=((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        var address="http://127.0.0.1:"+port;
        var start=new ProcessStartInfo("dotnet") {
            WorkingDirectory=work,UseShellExecute=false,RedirectStandardOutput=true,
            RedirectStandardError=true,CreateNoWindow=true};
        start.ArgumentList.Add(dll);
        foreach(var name in start.Environment.Keys.Where(x=>x.StartsWith("YARP_",StringComparison.Ordinal)).ToArray())
            start.Environment.Remove(name);
        start.Environment["ASPNETCORE_ENVIRONMENT"]="Production";
        start.Environment["ASPNETCORE_URLS"]=address;
        start.Environment["YARP_CONTROL_PLANE_DIR"]=root;
        start.Environment["YARP_RUNTIME_CONFIG_PATH"]=config;
        start.Environment["YARP_LINUX_DP_CERT_PFX_PATH"]=cert.Pfx;
        start.Environment["YARP_LINUX_DP_CERT_PASSWORD_FILE"]=cert.Password;
        var gateway=new ProductFleetProxy(Process.Start(start) ??
            throw new InvalidOperationException("Cannot start shipping GatewayCore"),config,address);
        try
        {
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            while(!deadline.IsCancellationRequested&&!gateway.process.HasExited)
            {
                try
                {
                    using var health=await http.GetAsync(address+"/gateway/health",deadline.Token);
                    if(health.IsSuccessStatusCode)return gateway;
                }
                catch(HttpRequestException){}
                catch(TaskCanceledException) when(!deadline.IsCancellationRequested){}
                await Task.Delay(100,deadline.Token);
            }
            throw new InvalidOperationException("Shipping GatewayCore failed readiness");
        }
        catch {gateway.Dispose();throw;}
    }

    public void Dispose()
    {
        try
        {
            if(!process.HasExited)process.Kill(entireProcessTree:true);
            if(!process.WaitForExit(5000))throw new InvalidOperationException("Gateway fixture did not stop");
            _=Task.WaitAll(new Task[]{stdout,stderr},TimeSpan.FromSeconds(3));
        }
        finally{process.Dispose();}
    }
}
