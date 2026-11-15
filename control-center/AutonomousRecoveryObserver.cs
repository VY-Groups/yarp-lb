using Microsoft.Extensions.Hosting;
using Yarp.ReverseProxy;
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
                        // A healthy active probe does not override an existing
                        // passive ejection. Unknown is not affirmative recovery
                        // evidence. Keep draining destinations out of warmup.
                        TrafficLifecycle.ObserveActiveHealth(destination,
                            RecoveryHealthGate.Eligible(
                                destination.Health.Active,
                                destination.Health.Passive,
                                TrafficLifecycle.IsDraining(destination)));
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
