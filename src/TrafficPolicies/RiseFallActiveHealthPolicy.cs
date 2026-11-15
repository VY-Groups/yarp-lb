using System.Globalization;
using System.Runtime.CompilerServices;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Opt-in HAProxy-style rise/fall hysteresis using the existing YARP active probe
/// scheduler. No duplicate probes and no HTTP request replay.
/// </summary>
public sealed class RiseFallActiveHealthPolicy : IActiveHealthCheckPolicy
{
    public const string PolicyName = "RiseFall";
    private sealed class DestinationCounter { public RiseFallCounter Counter = new(2, 3); }
    private readonly ConditionalWeakTable<DestinationState, DestinationCounter> counters = new();
    private readonly IDestinationHealthUpdater updater;
    public RiseFallActiveHealthPolicy(IDestinationHealthUpdater updater) => this.updater = updater;
    public string Name => PolicyName;

    public void ProbingCompleted(ClusterState cluster, IReadOnlyList<DestinationProbingResult> probingResults)
    {
        if (probingResults.Count == 0) return;
        var meta = cluster.Model.Config.Metadata;
        static int Read(IReadOnlyDictionary<string,string>? data, string key, int fallback)
        {
            if (data is null || !data.TryGetValue(key, out var raw)) return fallback;
            if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var n) || n is < 1 or > 10)
                throw new InvalidOperationException($"{key} must be 1..10");
            return n;
        }
        // Config is validated in the admin review API. Fail-safe also prevents
        // accidentally marking a destination healthy on malformed config.
        int rise, fall;
        try
        {
            rise = Read(meta, "RiseFall.Rise", 2);
            fall = Read(meta, "RiseFall.Fall", 3);
        }
        catch (InvalidOperationException)
        {
            updater.SetActive(cluster, probingResults.Select(x =>
                new NewActiveDestinationHealth(x.Destination, DestinationHealth.Unhealthy)).ToArray());
            return;
        }
        var results = new NewActiveDestinationHealth[probingResults.Count];
        for (var i = 0; i < probingResults.Count; i++)
        {
            var entry = probingResults[i];
            var counter = counters.GetValue(entry.Destination, _ => new DestinationCounter());
            bool healthy;
            lock (counter)
            {
                counter.Counter.Configure(rise, fall);
                healthy = counter.Counter.Observe(entry.Response is { IsSuccessStatusCode: true });
            }
            results[i] = new NewActiveDestinationHealth(entry.Destination,
                healthy ? DestinationHealth.Healthy : DestinationHealth.Unhealthy);
        }
        updater.SetActive(cluster, results);
    }
}
