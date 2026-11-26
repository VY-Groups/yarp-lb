using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Hosting.WindowsServices;

// Console operation is unchanged. When SCM owns the process, a small native
// host propagates the actual service stop notification to the DNS runtime.
internal sealed class WindowsGslbServiceHost(IHost host, CancellationTokenRegistration registration) : IAsyncDisposable
{
    internal static async Task<WindowsGslbServiceHost?> StartIfServiceAsync(CancellationTokenSource runtimeStop)
    {
        if (!OperatingSystem.IsWindows() || !WindowsServiceHelpers.IsWindowsService()) return null;
        var builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
        {
            Args = [],
            ContentRootPath = AppContext.BaseDirectory
        });
        builder.Services.AddWindowsService(options => options.ServiceName = "GatewayCoreGslb");
        builder.Services.Configure<HostOptions>(options => options.ShutdownTimeout = TimeSpan.FromSeconds(25));
        var host = builder.Build();
        var registration = host.Services.GetRequiredService<IHostApplicationLifetime>()
            .ApplicationStopping.Register(runtimeStop.Cancel);
        try
        {
            await host.StartAsync(runtimeStop.Token);
            return new(host, registration);
        }
        catch
        {
            registration.Dispose();
            host.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            await host.StopAsync(deadline.Token);
        }
        finally
        {
            registration.Dispose();
            host.Dispose();
        }
    }
}
