// Independent, deterministic DNS backend health hysteresis.
// Only the single probe loop mutates an instance. Concurrent DNS readers
// consume a separately published Volatile health snapshot on the Site.
internal sealed class DnsHealthHysteresis
{
    private readonly int failureThreshold;
    private readonly int successThreshold;
    private int passes;
    private int fails;

    public DnsHealthHysteresis(int failureThreshold, int successThreshold)
    {
        if (failureThreshold is < 1 or > 10 || successThreshold is < 1 or > 10)
            throw new ArgumentOutOfRangeException(nameof(failureThreshold),
                "Both DNS probe thresholds must be between 1 and 10");
        this.failureThreshold = failureThreshold;
        this.successThreshold = successThreshold;
    }

    public bool IsHealthy { get; private set; }

    public bool Observe(bool succeeded)
    {
        if (succeeded)
        {
            fails = 0;
            if (passes < successThreshold) passes++;
            if (passes >= successThreshold) IsHealthy = true;
        }
        else
        {
            passes = 0;
            if (fails < failureThreshold) fails++;
            if (fails >= failureThreshold) IsHealthy = false;
        }
        return IsHealthy;
    }
}
