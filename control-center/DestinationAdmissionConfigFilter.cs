using Yarp.ReverseProxy.Configuration;

/// <summary>Fail proxy startup and hot reload when opt-in admission policy is malformed.</summary>
public sealed class DestinationAdmissionConfigFilter : IProxyConfigFilter
{
    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel)
    {
        foreach (var (destinationId, destination) in cluster.Destinations ??
                     new Dictionary<string, DestinationConfig>())
        {
            if (!DestinationAdmissionPolicy.TryParse(destination.Metadata, out _, out var error))
                throw new InvalidOperationException(
                    $"Cluster '{cluster.ClusterId}' destination '{destinationId}' admission policy is invalid: {error}");
        }
        return ValueTask.FromResult(cluster);
    }

    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel) =>
        ValueTask.FromResult(route);
}
