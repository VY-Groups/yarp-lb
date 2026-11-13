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
        // Characterization-preserving two-pass weighted selection. Each HTTP
        // request previously allocated a filtered destination array + weight
        // array and LINQ enumerators. Keep only a bounded stack span of weights.
        Span<int> weights = availableDestinations.Count <= 128
            ? stackalloc int[availableDestinations.Count]
            : new int[availableDestinations.Count];
        var total = 0;
        for (var i = 0; i < availableDestinations.Count; i++)
        {
            var candidate = availableDestinations[i];
            if (TrafficLifecycle.IsDraining(candidate)) continue;
            var weight = TrafficLifecycle.EffectiveWeightedRandomWeight(candidate, WeightOf(candidate));
            weights[i] = weight;
            total = checked(total + weight);
        }
        if (total == 0) return null;
        var ticket = RandomNumberGenerator.GetInt32(total);
        for (var i = 0; i < availableDestinations.Count; i++)
        {
            if (ticket < weights[i]) return availableDestinations[i];
            ticket -= weights[i];
        }
        throw new InvalidOperationException("Weighted selection failed after valid total");
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
        var active = availableDestinations.Where(d => !TrafficLifecycle.IsDraining(d)).ToArray();
        if (active.Length == 0) return null;
        var address = context.Connection.RemoteIpAddress?.MapToIPv6().ToString();
        if (string.IsNullOrWhiteSpace(address)) return null; // no identity, no affinity
        var ids = active.Select(d => d.DestinationId).ToArray();
        // Slow-start is excluded from source-affinity to avoid remapping existing clients.
        var weights = active.Select(WeightedRandomPolicy.WeightOf).ToArray();
        return active[LoadBalancingCore.PickRendezvousIndex(address, ids, weights)];
    }
}
