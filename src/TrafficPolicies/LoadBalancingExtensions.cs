using System.Buffers;
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
        weights.Clear();
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
        // Snapshot the eligible destinations exactly once. In particular, a
        // concurrent drain transition must not change the membership halfway
        // through hashing. Pool the backing arrays instead of materializing
        // three LINQ/ToArray allocations for *every* affinity request.
        var active = ArrayPool<DestinationState>.Shared.Rent(availableDestinations.Count);
        try
        {
            var count = 0;
            for (var i = 0; i < availableDestinations.Count; i++)
            {
                var candidate = availableDestinations[i];
                if (!TrafficLifecycle.IsDraining(candidate)) active[count++] = candidate;
            }
            if (count == 0) return null;
            var address = context.Connection.RemoteIpAddress?.MapToIPv6().ToString();
            if (string.IsNullOrWhiteSpace(address)) return null; // no identity, no affinity

            var ids = ArrayPool<string>.Shared.Rent(count);
            var weights = ArrayPool<int>.Shared.Rent(count);
            try
            {
                // Slow-start is intentionally excluded: do not remap clients
                // during a backend's warmup. Keep the existing weight contract.
                for (var i = 0; i < count; i++)
                {
                    ids[i] = active[i].DestinationId;
                    weights[i] = WeightedRandomPolicy.WeightOf(active[i]);
                }
                var index = LoadBalancingCore.PickRendezvousIndex(address, ids, weights, count);
                return index < 0 ? null : active[index];
            }
            finally
            {
                // Pool storage is shared across requests and tenants. Always
                // clear all references, including on invalid metadata errors.
                ArrayPool<string>.Shared.Return(ids, clearArray: true);
                ArrayPool<int>.Shared.Return(weights, clearArray: true);
            }
        }
        finally
        {
            ArrayPool<DestinationState>.Shared.Return(active, clearArray: true);
        }
    }
}


/// <summary>Capacity-aware HTTP request selection. Not a TCP connection count.
/// Uses only local in-flight YARP counts and the eligible destination snapshot.</summary>
public sealed class WeightedLeastRequestsPolicy : ILoadBalancingPolicy
{
    public string Name => "WeightedLeastRequests";

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        DestinationState? best = null;
        var bestCount = 0;
        var bestWeight = 1;
        var ties = 0;
        for (var i = 0; i < availableDestinations.Count; i++)
        {
            var candidate = availableDestinations[i];
            if (TrafficLifecycle.IsDraining(candidate)) continue;
            var weight = TrafficLifecycle.EffectiveWeightedRandomWeight(candidate, WeightedRandomPolicy.WeightOf(candidate));
            var count = candidate.ConcurrentRequestCount;
            var comparison = best is null ? -1 :
                LoadBalancingCore.CompareProjectedLoad(count, weight, bestCount, bestWeight);
            if (comparison < 0)
            {
                best = candidate;
                bestCount = count;
                bestWeight = weight;
                ties = 1;
            }
            else if (comparison == 0 && Random.Shared.Next(++ties) == 0)
            {
                best = candidate;
                bestCount = count;
                bestWeight = weight;
            }
        }
        return best;
    }
}


/// <summary>Deterministic cyclic weighted HTTP request selection. The cursor
/// belongs to the live cluster, not a process-lifetime map of arbitrary IDs.</summary>
public sealed class WeightedRoundRobinPolicy : ILoadBalancingPolicy
{
    public string Name => "WeightedRoundRobin";
    private sealed class Cursor { internal long Value = -1; }
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<ClusterState, Cursor> cursors = new();

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        var count = availableDestinations.Count;
        if (count == 0) return null;
        Span<int> weights = count <= 128 ? stackalloc int[count] : new int[count];
        weights.Clear();
        var total = 0;
        for (var i = 0; i < count; i++)
        {
            var candidate = availableDestinations[i];
            if (TrafficLifecycle.IsDraining(candidate)) continue;
            var weight = TrafficLifecycle.EffectiveWeightedRandomWeight(candidate, WeightedRandomPolicy.WeightOf(candidate));
            weights[i] = weight;
            total = checked(total + weight);
        }
        if (total == 0) return null;
        var cursor = cursors.GetValue(cluster, static _ => new Cursor());
        var ticket = (int)(unchecked((ulong)Interlocked.Increment(ref cursor.Value)) % (ulong)total);
        for (var i = 0; i < count; i++)
        {
            if (ticket < weights[i]) return availableDestinations[i];
            ticket -= weights[i];
        }
        throw new InvalidOperationException("Invalid weighted rotation");
    }
}


/// <summary>Local successful GET/HEAD completion latency, with bounded lifetime
/// samples and periodic exploration. No retry or synthetic request is issued.</summary>
public sealed class FastestResponsePolicy : ILoadBalancingPolicy
{
    public string Name => "FastestResponse";
    private sealed class Sample
    {
        internal double Milliseconds;
        internal long Timestamp;
    }
    private sealed class Cursor { internal long Value = -1; }
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<DestinationState, Sample> Samples = new();
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<ClusterState, Cursor> cursors = new();

    public static void Observe(DestinationState destination, double milliseconds)
    {
        if (!double.IsFinite(milliseconds) || milliseconds < 0) return;
        var sample = Samples.GetValue(destination, static _ => new Sample());
        lock (sample)
        {
            var now = System.Diagnostics.Stopwatch.GetTimestamp();
            sample.Milliseconds = sample.Timestamp == 0 ||
                System.Diagnostics.Stopwatch.GetElapsedTime(sample.Timestamp, now).TotalSeconds >= 60
                ? milliseconds : sample.Milliseconds * 0.8 + milliseconds * 0.2;
            sample.Timestamp = now;
        }
    }

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        DestinationState? best = null, exploration = null;
        var bestScore = double.PositiveInfinity;
        var count = 0;
        var cursor = cursors.GetValue(cluster, static _ => new Cursor());
        var ticket = unchecked((ulong)Interlocked.Increment(ref cursor.Value));
        var now = System.Diagnostics.Stopwatch.GetTimestamp();
        foreach (var candidate in availableDestinations)
        {
            if (TrafficLifecycle.IsDraining(candidate)) continue;
            count++;
            if (Random.Shared.Next(count) == 0) exploration = candidate;
            if (!Samples.TryGetValue(candidate, out var sample)) continue;
            lock (sample)
            {
                if (sample.Timestamp == 0 ||
                    System.Diagnostics.Stopwatch.GetElapsedTime(sample.Timestamp, now).TotalSeconds >= 60)
                    continue;
                if (sample.Milliseconds < bestScore)
                {
                    bestScore = sample.Milliseconds;
                    best = candidate;
                }
            }
        }
        return ticket % 8 == 0 ? exploration : best ?? exploration;
    }
}
