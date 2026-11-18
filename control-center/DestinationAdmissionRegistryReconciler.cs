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
    private long _configurationRevision;
    private int _lastReportedPolicyConflicts = -1;
    private int _lastReportedCapacityExceeded = -1;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var configured = proxyState.GetClusters()
                    .SelectMany(cluster => cluster.Destinations.Values
                        .Select(destination => (Destination: destination, ClusterId: cluster.ClusterId)))
                    .Select(item => DestinationAdmissionPolicy.TryParse(
                            item.Destination.Model.Config.Metadata, out var policy, out var error)
                        ? new DestinationAdmissionConfiguration(
                            item.ClusterId, item.Destination.DestinationId, policy)
                        : throw new InvalidOperationException(
                            $"Applied destination '{item.ClusterId}/{item.Destination.DestinationId}' has invalid admission policy: {error}"))
                    .ToArray();
                var revision = Interlocked.Increment(ref _configurationRevision);
                var result = manager.ReconcileConfiguredDestinations(revision, configured);
                if (result.PolicyConflicts != _lastReportedPolicyConflicts ||
                    result.CapacityExceeded != _lastReportedCapacityExceeded)
                {
                    _lastReportedPolicyConflicts = result.PolicyConflicts;
                    _lastReportedCapacityExceeded = result.CapacityExceeded;
                    if (result.PolicyConflicts > 0 || result.CapacityExceeded > 0)
                        logger.LogWarning(
                            "Admission reconciliation revision {Revision}: {PolicyConflicts} policy conflicts, {CapacityExceeded} destinations over the tracking limit",
                            revision, result.PolicyConflicts, result.CapacityExceeded);
                }
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested)
            {
                logger.LogWarning(exception, "Could not reconcile destination admission registry with the applied proxy configuration");
            }

            await Task.Delay(TimeSpan.FromSeconds(1), stoppingToken);
        }
    }
}
