/// <summary>Guards a queued request against forwarding to a destination that changed after selection.</summary>
public static class DestinationAdmissionForwarding
{
    /// <summary>
    /// A queued request is bound to its original destination. Recheck the current
    /// available set after the permit is granted; never transfer it to another
    /// destination when the selected one was removed, became unhealthy, or drained.
    /// </summary>
    public static bool IsStillEligibleAfterWait<TDestination>(
        string selectedDestinationId,
        IReadOnlyList<TDestination> currentAvailable,
        Func<TDestination, string> destinationId,
        Func<TDestination, bool> isDraining)
    {
        ArgumentNullException.ThrowIfNull(selectedDestinationId);
        ArgumentNullException.ThrowIfNull(currentAvailable);
        ArgumentNullException.ThrowIfNull(destinationId);
        ArgumentNullException.ThrowIfNull(isDraining);

        for (var i = 0; i < currentAvailable.Count; i++)
        {
            var candidate = currentAvailable[i];
            if (string.Equals(destinationId(candidate), selectedDestinationId, StringComparison.Ordinal) &&
                !isDraining(candidate))
                return true;
        }
        return false;
    }
}
