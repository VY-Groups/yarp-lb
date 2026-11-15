using System.Globalization;
using System.Threading.RateLimiting;

/// <summary>Process-local, bounded proxy concurrency and FIFO waiting capacity.</summary>
public readonly record struct ProxyConcurrencySettings(int PermitLimit, int QueueLimit)
{
    public static ProxyConcurrencySettings FromEnvironment(string? permits, string? queue)
    {
        static int Parse(string? raw, int fallback, int minimum, int maximum, string name)
        {
            if (raw is null) return fallback;
            if (!int.TryParse(raw, NumberStyles.None, CultureInfo.InvariantCulture, out var result)
                || result < minimum || result > maximum)
                throw new InvalidOperationException($"{name} must be an integer {minimum}..{maximum}");
            return result;
        }
        // Conservative test defaults; deployment operators must size from measured concurrency.
        return new ProxyConcurrencySettings(
            Parse(permits, 128, 1, 100000, "GATEWAY_PROXY_CONCURRENCY"),
            Parse(queue, 0, 0, 4096, "GATEWAY_PROXY_QUEUE_LIMIT"));
    }

    public ConcurrencyLimiterOptions ToLimiterOptions() => new()
    {
        PermitLimit = PermitLimit,
        QueueLimit = QueueLimit,
        QueueProcessingOrder = QueueProcessingOrder.OldestFirst
    };
}
