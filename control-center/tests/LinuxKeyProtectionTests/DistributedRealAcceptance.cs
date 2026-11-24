using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;

// Invoked only by the disposable three-member etcd fixture; no mocked RPC.
// The actual product configuration method and ASP.NET key manager are used.
internal static class DistributedRealAcceptance
{
    internal static int Run(string[] args)
    {
        if (!OperatingSystem.IsLinux() ||
            Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" ||
            Environment.GetEnvironmentVariable("RUNNER_OS")!="Linux" ||
            args.Length!=2 || args[1] is not ("rotate" or "mint" or "verify"))
            return 2;
        ServiceProvider provider;
        try
        {
            var root=LinuxKeyProtection.InitializeStateDirectory();
            var services=new ServiceCollection();
            var builder=services.AddDataProtection().SetApplicationName("GatewayCore.RealDistributedDp.CI.v1")
                .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(root,"data-protection-keys")));
            LinuxKeyProtection.Configure(builder,root);
            provider=services.BuildServiceProvider();
        }
        catch(Exception) { return 4; } // actual startup/quorum refusal
        using(provider)
        {
            try
            {
                if(args[1]=="rotate")
                {
                    provider.GetRequiredService<IKeyManager>().CreateNewKey(
                        DateTimeOffset.UtcNow,DateTimeOffset.UtcNow.AddDays(30));
                    return 0;
                }
                var dp=provider.GetRequiredService<IDataProtectionProvider>()
                    .CreateProtector("real-distributed-cookie");
                if(args[1]=="mint")
                    Console.WriteLine(dp.Protect("disposable-real-distributed-cookie"));
                else
                {
                    var input=Console.ReadLine();
                    if(input is null || dp.Unprotect(input)!="disposable-real-distributed-cookie")
                        return 6;
                }
                return 0;
            }
            catch(Exception) { return 5; } // no secrets or network diagnostics
        }
    }
}
