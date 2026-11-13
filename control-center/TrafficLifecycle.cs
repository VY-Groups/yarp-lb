using System.Diagnostics;
using System.Runtime.CompilerServices;
using Yarp.ReverseProxy.Model;

/// <summary>Local health transition observation, new-request drain, and weighted warmup.</summary>
public static class TrafficLifecycle
{
    private sealed class WarmupState { internal long FirstEligibleTick; }
    private static readonly ConditionalWeakTable<DestinationState, WarmupState> Timers = new();

    public static bool IsDraining(DestinationState destination) =>
        destination.Model.Config.Metadata is { } meta &&
        meta.TryGetValue("TrafficState", out var raw) &&
        string.Equals(raw, "draining", StringComparison.OrdinalIgnoreCase);

    public static void Observe(IReadOnlyList<DestinationState> all, IReadOnlyList<DestinationState> available)
    {
        foreach (var dest in all)
        {
            var ready = !IsDraining(dest);
            if (ready)
            {
                ready = false;
                for (var i = 0; i < available.Count; i++)
                    if (ReferenceEquals(available[i], dest)) { ready = true; break; }
            }
            var state = Timers.GetValue(dest, _ => new WarmupState());
            if (!ready) Interlocked.Exchange(ref state.FirstEligibleTick, 0);
            else Interlocked.CompareExchange(ref state.FirstEligibleTick, Stopwatch.GetTimestamp(), 0);
        }
    }

    public static int EffectiveWeightedRandomWeight(DestinationState destination, int configuredWeight)
    {
        var meta = destination.Model.Config.Metadata;
        if (meta is null || !meta.TryGetValue("SlowStartSeconds", out var raw) ||
            !LoadBalancingCore.TrySlowStartSeconds(raw, out var seconds) || seconds == 0)
            return configuredWeight;
        var state = Timers.GetValue(destination, _ => new WarmupState());
        var tick = Volatile.Read(ref state.FirstEligibleTick);
        if (tick == 0)
        {
            Interlocked.CompareExchange(ref state.FirstEligibleTick, Stopwatch.GetTimestamp(), 0);
            tick = Volatile.Read(ref state.FirstEligibleTick);
        }
        return LoadBalancingCore.RampedWeight(configuredWeight, Stopwatch.GetElapsedTime(tick).TotalSeconds, seconds);
    }
}
