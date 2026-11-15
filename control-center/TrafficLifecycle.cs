using System.Diagnostics;
using System.Runtime.CompilerServices;
using Yarp.ReverseProxy.Model;

/// <summary>Local health transition observation, new-request drain, and weighted warmup.</summary>
public static class TrafficLifecycle
{
    private sealed class WarmupState { internal long FirstEligibleTick; internal int LastSlowStartSeconds; internal int WasEligible; }
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
            var metadata = dest.Model.Config.Metadata;
            var seconds = metadata is not null && metadata.TryGetValue("SlowStartSeconds", out var raw) &&
                LoadBalancingCore.TrySlowStartSeconds(raw, out var configured) ? configured : 0;
            // A config update that turns warmup on (or changes its window) must start
            // a NEW ramp, even if YARP retains the same DestinationState instance.
            var prior = Interlocked.Exchange(ref state.LastSlowStartSeconds, seconds);
            var wasEligible = Interlocked.Exchange(ref state.WasEligible, ready ? 1 : 0) == 1;
            // Begin a fresh ramp on the first observed recovery or a changed
            // warmup interval, rather than keeping a previous eligibility timer.
            if (!ready || seconds == 0)
                Interlocked.Exchange(ref state.FirstEligibleTick, 0);
            else if (!wasEligible || prior != seconds)
                Interlocked.Exchange(ref state.FirstEligibleTick, Stopwatch.GetTimestamp());
            else
                Interlocked.CompareExchange(ref state.FirstEligibleTick, Stopwatch.GetTimestamp(), 0);
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
