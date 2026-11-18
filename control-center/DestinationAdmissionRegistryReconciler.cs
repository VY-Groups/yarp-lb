using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Retires idle registry entries after the proxy runtime exposes an accepted config
/// snapshot. Config-filter validation itself remains side-effect free.
/// </summary>
public sealed class DestinationAdmissionRegistryReconciler(
    IProxyStateLookup proxyState,
    DestinationAdmissionManager manager,
    ILogger<DestinationAdmissionRegistryReconciler> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var configured = proxyState.GetClusters()
                    .SelectMany(cluster => cluster.Destinations.Values
                        .Where(destination => DestinationAdmissionPolicy.TryParse(
                            destination.Model.Config.Metadata, out var policy, out _) && policy.Enabled)
                        .Select(destination => (cluster.ClusterId, destination.DestinationId)))
                    .ToArray();
                manager.ReconcileConfiguredDestinations(configured);
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Could not reconcile destination admission registry with the applied proxy configuration");
            }

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }
}
