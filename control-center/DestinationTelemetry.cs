using System.Collections.Concurrent;

/// <summary>
/// Process-lifetime destination counters with a hard cardinality limit. Unknown
/// destinations after the limit are aggregated rather than emitted as labels.
/// </summary>
public sealed class DestinationTelemetry
{
    public const int MaximumTrackedDestinations = 4096;

    private readonly ConcurrentDictionary<string, DestinationCounters> _entries = new(StringComparer.Ordinal);
    private readonly object _registrationLock = new();
    private long _untrackedRequests;

    public int TrackedDestinationCount => _entries.Count;
    public long UntrackedRequests => Interlocked.Read(ref _untrackedRequests);

    public IEnumerable<KeyValuePair<string, DestinationCounters>> Entries => _entries;

    public bool TryGetValue(string id, out DestinationCounters counters) => _entries.TryGetValue(id, out counters!);

    /// <summary>Records one request, returning false when only the aggregate overflow counter was updated.</summary>
    public bool Record(string id, int status, double elapsedMs)
    {
        if (_entries.TryGetValue(id, out var counters))
        {
            counters.Record(status, elapsedMs);
            return true;
        }

        // Avoid serializing steady-state overflow traffic on the registration lock.
        // A request racing the final insertion may be aggregated once, which is
        // preferable to allowing cardinality beyond the hard cap.
        if (_entries.Count >= MaximumTrackedDestinations)
        {
            IncrementSaturating(ref _untrackedRequests);
            return false;
        }

        lock (_registrationLock)
        {
            // Another request can register the same ID after the initial lookup.
            if (_entries.TryGetValue(id, out counters))
            {
                counters.Record(status, elapsedMs);
                return true;
            }

            if (_entries.Count >= MaximumTrackedDestinations)
            {
                IncrementSaturating(ref _untrackedRequests);
                return false;
            }

            counters = new DestinationCounters();
            _entries.TryAdd(id, counters);
            counters.Record(status, elapsedMs);
            return true;
        }
    }

    private static void IncrementSaturating(ref long counter)
    {
        while (true)
        {
            var current = Interlocked.Read(ref counter);
            if (current == long.MaxValue) return;
            if (Interlocked.CompareExchange(ref counter, current + 1, current) == current) return;
        }
    }
}

/// <summary>Managed destination counters: no request paths or client identity labels.</summary>
public sealed class DestinationCounters
{
    public long Requests, ServerErrors, ClientErrors, TotalMicros;
    public double MeanLatencyMs => Interlocked.Read(ref Requests) is var r && r > 0
        ? Interlocked.Read(ref TotalMicros) / 1000.0 / r : 0;

    public void Record(int status, double elapsedMs)
    {
        Interlocked.Increment(ref Requests);
        if (status >= 500) Interlocked.Increment(ref ServerErrors);
        else if (status >= 400) Interlocked.Increment(ref ClientErrors);
        Interlocked.Add(ref TotalMicros, (long)(elapsedMs * 1000));
    }
}
