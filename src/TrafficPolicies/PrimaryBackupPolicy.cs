using System.Security.Cryptography;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.LoadBalancing;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Opt-in HTTP backend selection: use healthy available primaries while any
/// exist; otherwise route to ONE fixed backup (lowest ordinal destination ID).
/// Matches HAProxy's first-backup *routing intent*, not its wire protocol.
/// No retries, cache, dynamic promotion, or session replication are performed.
/// </summary>
public sealed class PrimaryBackupPolicy : ILoadBalancingPolicy
{
    public string Name => "PrimaryBackup";

    public DestinationState? PickDestination(HttpContext context, ClusterState cluster,
        IReadOnlyList<DestinationState> availableDestinations)
    {
        if (availableDestinations.Count == 0) return null;

        // No per-request LINQ or heap allocation for ordinary <=128 destination pools.
        Span<int> primaryWeights = availableDestinations.Count <= 128
            ? stackalloc int[availableDestinations.Count]
            : new int[availableDestinations.Count];
        primaryWeights.Clear(); // stackalloc memory must never carry stale weights
        DestinationState? backup = null;
        for (var i = 0; i < availableDestinations.Count; i++)
        {
            var candidate = availableDestinations[i];
            if (TrafficLifecycle.IsDraining(candidate)) continue;
            var metadata = candidate.Model.Config.Metadata;
            var raw = metadata is not null && metadata.TryGetValue("TrafficRole", out var role)
                ? role : null;
            if (!PrimaryBackupCore.TryBackupRole(raw, out var isBackup))
                throw new InvalidOperationException(
                    "Invalid TrafficRole metadata for destination " + candidate.DestinationId);
            if (isBackup)
            {
                if (backup is null ||
                    string.CompareOrdinal(candidate.DestinationId, backup.DestinationId) < 0)
                    backup = candidate;
                continue;
            }

            var configured = WeightedRandomPolicy.WeightOf(candidate);
            primaryWeights[i] = TrafficLifecycle.EffectiveWeightedRandomWeight(candidate, configured);
        }

        var total = PrimaryBackupCore.PrimaryWeightTotal(primaryWeights);
        if (total == 0) return backup;
        var ticket = RandomNumberGenerator.GetInt32(total);
        var index = PrimaryBackupCore.PickPrimaryIndex(primaryWeights, ticket);
        return index < 0 ? null : availableDestinations[index];
    }
}
