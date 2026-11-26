using Microsoft.AspNetCore.DataProtection;
internal static class ExpiringAffinityTests
{
    public static void Run()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("Expiring affinity: " + label);
            Console.WriteLine("PASS: " + label);
        }
        // Disposable test-only key ring. Never export or copy production keys.
        var dir = Directory.CreateTempSubdirectory("gatewaycore-affinity-test-");
        try
        {
            var a = new ExpiringAffinityTokens(DataProtectionProvider.Create(dir,
                options => options.SetApplicationName("GatewayCoreAffinityLab")));
            var lifetime = TimeSpan.FromMinutes(5);
            const string cluster = "pool-a", key = "__Host-GatewayCore-pool-a";
            var token = a.Issue(cluster,key,lifetime,"origin-a",DateTimeOffset.UtcNow.Add(lifetime));
            var b = new ExpiringAffinityTokens(DataProtectionProvider.Create(dir,
                options => options.SetApplicationName("GatewayCoreAffinityLab")));
            Check(b.Read(cluster,key,lifetime,token)=="origin-a","independent provider reads shared authorized ring");
            Check(b.Read("pool-b",key,lifetime,token) is null,"cross-cluster replay rejected");
            Check(b.Read(cluster,"other",lifetime,token) is null,"different cookie scope rejected");
            Check(b.Read(cluster,key,TimeSpan.FromMinutes(1),token) is null,"changed lifetime invalidates old token");
            var expired=a.Issue(cluster,key,lifetime,"origin-a",DateTimeOffset.UtcNow.AddMinutes(-1));
            Check(b.Read(cluster,key,lifetime,expired) is null,"server rejects expired token");
            Check(b.Read(cluster,key,lifetime,"invalid") is null,"invalid token rejected");
            var isolated = new ExpiringAffinityTokens(DataProtectionProvider.Create(dir,
                options => options.SetApplicationName("OtherApplication")));
            Check(isolated.Read(cluster,key,lifetime,token) is null,"application scope separation");
        }
        finally { dir.Delete(true); }
    }
}
