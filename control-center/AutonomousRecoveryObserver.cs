using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Observes YARP's own active health decisions on a bounded timer even at zero
/// incoming traffic. This does not replace the configured YARP HTTP probes.
/// </summary>
public sealed class AutonomousRecoveryObserver : BackgroundService
{
    private readonly IProxyStateLookup proxy;
    private readonly ILogger<AutonomousRecoveryObserver> logger;

    public AutonomousRecoveryObserver(IProxyStateLookup proxy, ILogger<AutonomousRecoveryObserver> logger)
    {
        this.proxy = proxy;
        this.logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                foreach (var cluster in proxy.GetClusters())
                {
                    foreach (var destination in cluster.Destinations.Values)
                    {
                        if (destination.Health.Active is DestinationHealth.Healthy)
                            TrafficLifecycle.ObserveActiveHealth(destination, true);
                        else if (destination.Health.Active is DestinationHealth.Unhealthy)
                            TrafficLifecycle.ObserveActiveHealth(destination, false);
                        // Unknown is not a successful probe; do not start the ramp.
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "YARP recovery health observation failed; no active health override applied");
            }
            try
            {
                if (!await timer.WaitForNextTickAsync(stoppingToken)) break;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
        }
    }
}
