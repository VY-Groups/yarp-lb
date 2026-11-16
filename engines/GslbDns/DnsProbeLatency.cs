// Local probe latency is not client RTT. This advisory input is consumed only
// by an opt-in DNS routing policy and never overrides backend health.
internal sealed class DnsProbeLatency
{
    private readonly object gate = new();
    private double emaMilliseconds;
    private int samples;
    private long lastSuccessMs = long.MinValue;

    public void ObserveSuccess(TimeSpan elapsed, long monotonicMs)
    {
        var value = Math.Clamp(elapsed.TotalMilliseconds, 0.1, 60_000);
        lock (gate)
        {
            // A monotonic-clock jump or long outage invalidates prior averages.
            if (monotonicMs < lastSuccessMs ||
                (lastSuccessMs != long.MinValue && monotonicMs - lastSuccessMs > 60_000))
                samples = 0;
            emaMilliseconds = samples == 0 ? value : (0.25 * value + 0.75 * emaMilliseconds);
            samples = Math.Min(1000, samples + 1);
            lastSuccessMs = monotonicMs;
        }
    }

    public void ObserveFailure()
    {
        lock (gate)
        {
            samples = 0;
            lastSuccessMs = long.MinValue;
        }
    }

    public bool TryRead(long monotonicMs, int minimumSamples, int maxAgeMs, out double milliseconds)
    {
        if (minimumSamples is < 1 or > 20 || maxAgeMs is < 1000 or > 60_000)
            throw new ArgumentOutOfRangeException(nameof(minimumSamples));
        lock (gate)
        {
            milliseconds = 0;
            if (samples < minimumSamples || lastSuccessMs == long.MinValue ||
                monotonicMs < lastSuccessMs || monotonicMs - lastSuccessMs > maxAgeMs)
                return false;
            milliseconds = emaMilliseconds;
            return true;
        }
    }
}
