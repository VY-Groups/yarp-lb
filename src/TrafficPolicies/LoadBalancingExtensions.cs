using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.LoadBalancing;
using Yarp.ReverseProxy.Model;

/// <summary>Weighted random selection among YARP's available destinations.</summary>
public sealed class WeightedRandomPolicy : ILoadBalancingPolicy
{
    public string Name => "WeightedRandom";

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        if (availableDestinations.Count == 0) return null;
        var weights = availableDestinations.Select(WeightOf).ToArray();
        var total = weights.Sum();
        var ticket = RandomNumberGenerator.GetInt32(total);
        return availableDestinations[LoadBalancingCore.PickWeightedIndex(weights, ticket)];
    }

    internal static int WeightOf(DestinationState destination)
    {
        var metadata = destination.Model.Config.Metadata;
        if (metadata is null || !metadata.TryGetValue("Weight", out var raw)) return 1;
        if (!LoadBalancingCore.TryWeight(raw, out var weight))
            throw new InvalidOperationException("Invalid Weight metadata for destination " + destination.DestinationId);
        return weight;
    }
}

/// <summary>
/// Deterministic weighted rendezvous hashing by the TCP peer IP.
/// Source-NAT will collapse all requests to the NAT IP. Do not trust
/// unvalidated client-provided X-Forwarded-For headers as identity.
/// </summary>
public sealed class SourceIpHashPolicy : ILoadBalancingPolicy
{
    public string Name => "SourceIpHash";

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        if (availableDestinations.Count == 0) return null;
        var address = context.Connection.RemoteIpAddress?.MapToIPv6().ToString();
        if (string.IsNullOrWhiteSpace(address)) return null;
        var ids = availableDestinations.Select(d => d.DestinationId).ToArray();
        var weights = availableDestinations.Select(WeightedRandomPolicy.WeightOf).ToArray();
        return availableDestinations[LoadBalancingCore.PickRendezvousIndex(address, ids, weights)];
    }
}
