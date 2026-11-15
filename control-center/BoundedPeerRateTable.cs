using System.Diagnostics;
using System.Globalization;
using System.Net;

/// <summary>
/// Fixed-window, process-local peer-IP table with a hard cardinality ceiling.
/// Only the trusted TCP peer IP is used; no forwarded header is accepted.
/// </summary>
public sealed class BoundedPeerRateTable
{
    private readonly object gate = new();
    private readonly Dictionary<IPAddress, Entry> entries = new();
    private readonly int maxEntries;
    private readonly int requestsPerMinute;
    private readonly long windowTicks;
    private readonly record struct Entry(long WindowStart, int Count);

    public BoundedPeerRateTable(int requestsPerMinute, int maxEntries)
    {
        if (requestsPerMinute is < 1 or > 1_000_000) throw new ArgumentOutOfRangeException(nameof(requestsPerMinute));
        if (maxEntries is < 1 or > 65536) throw new ArgumentOutOfRangeException(nameof(maxEntries));
        this.requestsPerMinute = requestsPerMinute;
        this.maxEntries = maxEntries;
        windowTicks = checked(60L * Stopwatch.Frequency);
    }

    public static BoundedPeerRateTable? FromEnvironment(string? requestLimit, string? capacity)
    {
        // Explicit opt-in. A typo must not silently disable a configured policy.
        if (requestLimit is null)
        {
            if (capacity is not null)
                throw new InvalidOperationException("GATEWAY_PROXY_IP_TABLE_CAPACITY requires GATEWAY_PROXY_IP_RATE_PER_MINUTE");
            return null;
        }
        if (!int.TryParse(requestLimit, NumberStyles.None, CultureInfo.InvariantCulture, out var requests)
            || requests is < 1 or > 1_000_000)
            throw new InvalidOperationException("GATEWAY_PROXY_IP_RATE_PER_MINUTE must be 1..1000000");
        var max = 4096;
        if (capacity is not null && (!int.TryParse(capacity, NumberStyles.None, CultureInfo.InvariantCulture, out max)
            || max is < 1 or > 65536))
            throw new InvalidOperationException("GATEWAY_PROXY_IP_TABLE_CAPACITY must be 1..65536");
        return new BoundedPeerRateTable(requests, max);
    }

    public bool TryAdmit(IPAddress? peer, long now)
    {
        if (peer is null) return false; // unknown client identity: fail closed
        peer = peer.MapToIPv6();
        lock (gate)
        {
            if (entries.TryGetValue(peer, out var item))
            {
                if (now < item.WindowStart || now - item.WindowStart >= windowTicks)
                {
                    entries[peer] = new Entry(now, 1);
                    return true;
                }
                if (item.Count >= requestsPerMinute) return false;
                entries[peer] = item with { Count = item.Count + 1 };
                return true;
            }
            if (entries.Count >= maxEntries)
            {
                // Expiry reclamation only on full table; never grow beyond cap.
                foreach (var entry in entries.Where(x => now < x.Value.WindowStart ||
                    now - x.Value.WindowStart >= windowTicks).Select(x => x.Key).ToArray())
                    entries.Remove(entry);
                if (entries.Count >= maxEntries) return false;
            }
            entries.Add(peer, new Entry(now, 1));
            return true;
        }
    }
}
