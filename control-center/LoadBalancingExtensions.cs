using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.LoadBalancing;
using Yarp.ReverseProxy.Model;

/// <summary>Weighted random selection among destinations that YARP has already deemed available.</summary>
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
        // The frontend and reviewed-change validation enforce 1..100. Fail closed
        // at runtime rather than silently accepting an invalid deployed weight.
        if (!LoadBalancingCore.TryWeight(raw, out var weight))
            throw new InvalidOperationException("Invalid Weight metadata for destination " + destination.DestinationId);
        return weight;
    }
}

/// <summary>
/// Weighted rendezvous hashing by the TCP peer IP. For L4 SNAT this is the firewall
/// address, NOT the real client. Do not trust user-supplied X-Forwarded-For values.
/// Deploy only after validating the trusted proxy chain and shared identities.
/// </summary>
public sealed class SourceIpHashPolicy : ILoadBalancingPolicy
{
    public string Name => "SourceIpHash";

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        if (availableDestinations.Count == 0) return null;
        var address = context.Connection.RemoteIpAddress?.MapToIPv6().ToString();
        if (string.IsNullOrWhiteSpace(address)) return null; // no identity, no affinity
        var ids = availableDestinations.Select(d => d.DestinationId).ToArray();
        var weights = availableDestinations.Select(WeightedRandomPolicy.WeightOf).ToArray();
        return availableDestinations[LoadBalancingCore.PickRendezvousIndex(address, ids, weights)];
    }
}
