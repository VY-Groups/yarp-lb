using Yarp.ReverseProxy.Configuration;

/// <summary>Fail proxy startup and hot reload when opt-in admission policy is malformed.</summary>
public sealed class DestinationAdmissionConfigFilter : IProxyConfigFilter
{
    private readonly DestinationAdmissionManager _manager;

    public DestinationAdmissionConfigFilter(DestinationAdmissionManager manager) => _manager = manager;

    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel)
    {
        foreach (var (destinationId, destination) in cluster.Destinations ??
                     new Dictionary<string, DestinationConfig>())
        {
            if (!DestinationAdmissionPolicy.TryParse(destination.Metadata, out var policy, out var error))
                throw new InvalidOperationException(
                    $"Cluster '{cluster.ClusterId}' destination '{destinationId}' admission policy is invalid: {error}");
            if (policy.Enabled && !_manager.TryGetOrCreate(cluster.ClusterId, destinationId, policy, out _))
                throw new InvalidOperationException(
                    $"Cluster '{cluster.ClusterId}' destination '{destinationId}' admission state is full or has an incompatible live queue-policy change");
        }
        return ValueTask.FromResult(cluster);
    }

    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel) =>
        ValueTask.FromResult(route);
}
