using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.DependencyInjection;

// Hosted lifetime handles SCM stop and systemd SIGTERM without killing a
// partially written controller journal. No restart loop after a failed transfer.
internal static class VipControllerService
{
    internal static async Task<int> Run(string[] args)
    {
        var builder=Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
            {Args=Array.Empty<string>(),ContentRootPath=AppContext.BaseDirectory});
        builder.Configuration.Sources.Clear();
        builder.Services.AddWindowsService(o=>o.ServiceName="GatewayCoreVipController");
        builder.Services.Configure<HostOptions>(o=>o.ShutdownTimeout=TimeSpan.FromSeconds(90));
        int result=78;
        builder.Services.AddSingleton<IHostedService>(sp=>new Worker(args,sp.GetRequiredService<IHostApplicationLifetime>(),code=>result=code));
        using var host=builder.Build();
        await host.RunAsync();return result;
    }
    private sealed class Worker(string[] args,IHostApplicationLifetime lifetime,Action<int> completed):BackgroundService
    {
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try
            {
                // The hosted controller accepts only its installed bounded policy mode.
                Console.Error.WriteLine("VIP controller validating installed configuration.");
                VipServiceSecurity.Controller(args);
                Console.Error.WriteLine("VIP controller configuration accepted; opening durable authority.");
                completed(await VipOwnershipCommand.Run(args,stoppingToken));
            }
            catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or ArgumentException or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
            {VipServiceSecurity.ReportWindowsFileAclRefusal(e,7802);Console.Error.WriteLine("VIP controller startup refused: "+e.GetType().Name);completed(78);}
            finally{lifetime.StopApplication();}
        }
    }
}
