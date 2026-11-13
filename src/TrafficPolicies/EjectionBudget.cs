/// <summary>
/// Pure per-cluster capacity ceiling used by the failover policy. The
/// user-specified minimum reserve always wins over the percentage ceiling.
/// </summary>
public static class EjectionBudget
{
    public static int Allowed(int total, int percent, int minHealthyRemaining)
    {
        if (total < 0 || percent is < 1 or > 100 || minHealthyRemaining < 0)
            throw new ArgumentOutOfRangeException(nameof(total));
        var limit = Math.Min(total - minHealthyRemaining, (int)((long)total * percent / 100));
        return Math.Max(0, limit);
    }
}
