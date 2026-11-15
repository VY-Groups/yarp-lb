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
            ObserveEligibility(dest, ready);
        }
    }

    /// <summary>
    /// Called by the periodic YARP active-health observer even when no user request
    /// is received. An unhealthy-to-healthy event starts a new warmup ramp.
    /// Passive/unknown states are intentionally not interpreted as a healthy probe.
    /// </summary>
    public static void ObserveActiveHealth(DestinationState destination, bool healthy)
    {
        ObserveEligibility(destination, healthy && !IsDraining(destination));
    }

    private static void ObserveEligibility(DestinationState dest, bool ready)
    {
        var state = Timers.GetValue(dest, _ => new WarmupState());
        var metadata = dest.Model.Config.Metadata;
        var seconds = metadata is not null && metadata.TryGetValue("SlowStartSeconds", out var raw) &&
            LoadBalancingCore.TrySlowStartSeconds(raw, out var configured) ? configured : 0;
        // Serialize eligibility transitions to avoid a delayed request overwriting
        // the ramp started by a background health state change.
        lock (state)
        {
            var prior = state.LastSlowStartSeconds;
            var wasEligible = state.WasEligible == 1;
            state.LastSlowStartSeconds = seconds;
            state.WasEligible = ready ? 1 : 0;
            if (!ready || seconds == 0)
                Volatile.Write(ref state.FirstEligibleTick, 0);
            else if (!wasEligible || prior != seconds)
                Volatile.Write(ref state.FirstEligibleTick, Stopwatch.GetTimestamp());
            else if (Volatile.Read(ref state.FirstEligibleTick) == 0)
                Volatile.Write(ref state.FirstEligibleTick, Stopwatch.GetTimestamp());
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
