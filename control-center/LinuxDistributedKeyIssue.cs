using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.Extensions.DependencyInjection;

// Explicit offline operator process using the shipped application's key
// repository. It never starts HTTP listeners and accepts no secret arguments.
internal static class LinuxDistributedKeyIssue
{
    internal static int Run(string[] args)
    {
        if(!OperatingSystem.IsLinux() || Ec2WorkflowLab.Enabled ||
            Environment.GetEnvironmentVariable(LinuxKeyProtection.DistributedRingSetting) is not {Length:>0} path ||
            args.Length<2 || args[1] is not ("bootstrap" or "stage") ||
            (args[1]=="bootstrap"&&args.Length!=2) ||
            (args[1]=="stage"&&args.Length!=3))
        {
            Console.Error.WriteLine("REFUSED: explicit distributed Linux key issuance configuration required");
            return 2;
        }

        DateTimeOffset activation=default;
        if(args[1]=="stage"&&!DateTimeOffset.TryParseExact(args[2],
            "yyyy-MM-dd'T'HH:mm:ss'Z'",CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal|DateTimeStyles.AdjustToUniversal,out activation))
        {
            Console.Error.WriteLine("REFUSED: stage requires exact UTC activation");
            return 2;
        }
        try
        {
            var state=LinuxKeyProtection.InitializeStateDirectory();
            var settings=LinuxKeyProtection.DistributedRingRepository.ReadSettings(path,state);
            if(settings.Mode!="writer")
                throw new InvalidOperationException("Read-only node cannot issue keys");
            var services=new ServiceCollection();
            var builder=services.AddDataProtection().SetApplicationName("GatewayCoreYarpControlCenter")
                .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(state,"data-protection-keys")));
            LinuxKeyProtection.Configure(builder,state);
            using var provider=services.BuildServiceProvider();
            var repo=provider.GetRequiredService<IXmlRepository>() as LinuxKeyProtection.DistributedRingRepository
                ?? throw new InvalidOperationException("Distributed storage is mandatory");
            var manager=provider.GetRequiredService<IKeyManager>();
            var now=DateTimeOffset.UtcNow;
            if(args[1]=="bootstrap")
            {
                repo.RequireEmptyRing();
                activation=now;
            }
            else
            {
                // Allow existing nodes time to refresh their cached key rings.
                // Do not issue a key that activates after all existing keys
                // expire, or schedule multiple competing future generations.
                if(activation<now.AddHours(48)||activation>now.AddDays(7))
                    throw new InvalidOperationException("Activation outside coordinated staging window");
                var keys=manager.GetAllKeys();
                if(!keys.Any(k=>!k.IsRevoked&&k.ActivationDate<=now&&k.ExpirationDate>activation) ||
                    keys.Any(k=>!k.IsRevoked&&k.ActivationDate>now))
                    throw new InvalidOperationException("Existing ring cannot safely stage another key");
            }
            manager.CreateNewKey(activation,activation.AddDays(90));
            Console.WriteLine("PASS: fenced distributed key issued");
            return 0;
        }
        catch(Exception)
        {
            // A failed response could follow a committed mutation. Never
            // retry automatically; inspect the independently approved ring.
            Console.Error.WriteLine("REFUSED OR UNCERTAIN: reconcile distributed key inventory before retry");
            return 1;
        }
    }
}
