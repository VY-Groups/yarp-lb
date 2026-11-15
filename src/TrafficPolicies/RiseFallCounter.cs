/// <summary>Pure state machine for separately configurable health failure and recovery streaks.</summary>
public sealed class RiseFallCounter
{
    public int Failures { get; private set; }
    public int Successes { get; private set; }
    public bool Healthy { get; private set; }
    public int Rise { get; private set; }
    public int Fall { get; private set; }

    public RiseFallCounter(int rise, int fall) => Configure(rise, fall);

    public void Configure(int rise, int fall)
    {
        if (rise is < 1 or > 10 || fall is < 1 or > 10)
            throw new ArgumentOutOfRangeException(nameof(rise), "Rise and fall must be 1..10");
        if (Rise == rise && Fall == fall) return;
        Rise = rise;
        Fall = fall;
        Healthy = false; // fail closed until the configured rise streak is observed
        Failures = 0;
        Successes = 0;
    }

    public bool Observe(bool probeSucceeded)
    {
        if (probeSucceeded)
        {
            Failures = 0;
            Successes = Math.Min(Rise, Successes + 1);
            if (!Healthy && Successes >= Rise) Healthy = true;
        }
        else
        {
            Successes = 0;
            Failures = Math.Min(Fall, Failures + 1);
            if (Healthy && Failures >= Fall) Healthy = false;
        }
        return Healthy;
    }
}
