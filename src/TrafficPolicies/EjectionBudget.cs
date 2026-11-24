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

    // With active health enabled, only affirmative active health counts as
    // reserve. Unknown during startup, unhealthy, draining, and already
    // reserved/passively ejected nodes cannot provide a healthy alternative.
    public static bool EligibleForReserve(bool activeEnabled,bool activeHealthy,
        bool passiveUnhealthy,bool draining,bool reserved)=>
        (!activeEnabled || activeHealthy) && !passiveUnhealthy && !draining && !reserved;

    public static bool CanReserve(int cap,int reserved,int eligibleAlternatives,
        int minimumRemaining,bool candidateEligible)=>
        candidateEligible && cap>0 && reserved>=0 && reserved<cap &&
        minimumRemaining>=0 && eligibleAlternatives>=minimumRemaining;
}
