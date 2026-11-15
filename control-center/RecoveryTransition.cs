/// <summary>
/// Pure eligibility-edge logic shared by request and idle health observation.
/// It never changes YARP's own health decision or sends a request.
/// </summary>
public static class RecoveryTransition
{
    public static bool ShouldRestartRamp(bool wasEligible, bool ready, int previousSeconds, int currentSeconds)
    {
        if (currentSeconds <= 0 || !ready) return false;
        return !wasEligible || previousSeconds != currentSeconds;
    }
}
