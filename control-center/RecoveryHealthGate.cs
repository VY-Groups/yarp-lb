/// <summary>
/// Pure admission decision: only an affirmative active-health success may
/// initiate idle recovery; passive ejection and draining always veto it.
/// </summary>
public static class RecoveryHealthGate
{
    public static bool Eligible(bool activeHealthy, bool passiveEjected, bool draining) =>
        activeHealthy && !passiveEjected && !draining;
}
