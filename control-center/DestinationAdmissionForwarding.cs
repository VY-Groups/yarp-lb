/// <summary>Guards a queued request against forwarding to a destination that changed after selection.</summary>
public static class DestinationAdmissionForwarding
{
    // Cancellation may win just after the queue completes but before its
    // asynchronous continuation runs. A granted lease is not permission
    // to forward a timed-out, aborted or stopping request.
    public static DestinationAdmissionFailure FailureAfterGrant(
        CancellationToken requestAborted, CancellationToken applicationStopping,
        CancellationToken queueWait)
    {
        if (requestAborted.IsCancellationRequested) return DestinationAdmissionFailure.ClientAborted;
        if (applicationStopping.IsCancellationRequested) return DestinationAdmissionFailure.ServiceStopping;
        if (queueWait.IsCancellationRequested) return DestinationAdmissionFailure.QueueTimeout;
        return DestinationAdmissionFailure.None;
    }

    // Only a request that entered the FIFO queue has a deadline. The monotonic
    // check closes the timer-callback race where the deadline elapsed before a
    // permit grant but its cancellation callback has not run yet.
    public static DestinationAdmissionFailure CompleteQueueWait(
        bool wasQueued,
        CancellationToken queueWait,
        CancellationToken requestAborted,
        CancellationToken applicationStopping,
        long waitStartedTimestamp,
        TimeSpan queueTimeout)
    {
        if (wasQueued && waitStartedTimestamp < 0) throw new ArgumentOutOfRangeException(nameof(waitStartedTimestamp));
        if (queueTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(queueTimeout));

        if (requestAborted.IsCancellationRequested) return DestinationAdmissionFailure.ClientAborted;
        if (applicationStopping.IsCancellationRequested) return DestinationAdmissionFailure.ServiceStopping;
        if (!wasQueued) return DestinationAdmissionFailure.None;
        if (queueWait.IsCancellationRequested) return DestinationAdmissionFailure.QueueTimeout;

        return System.Diagnostics.Stopwatch.GetElapsedTime(waitStartedTimestamp) >= queueTimeout
            ? DestinationAdmissionFailure.QueueTimeout
            : DestinationAdmissionFailure.None;
    }

    /// <summary>
    /// A queued request is bound to its original destination. Recheck the current
    /// available set after the permit is granted; never transfer it to another
    /// destination when the selected one was removed, became unhealthy, or drained.
    /// </summary>
    public static bool IsStillEligibleAfterWait<TDestination>(
        string selectedDestinationId,
        IReadOnlyList<TDestination> currentAvailable,
        Func<TDestination, string> destinationId,
        Func<TDestination, bool> isDraining,
        Func<TDestination, bool>? matchesOriginalSelection = null)
    {
        ArgumentNullException.ThrowIfNull(selectedDestinationId);
        ArgumentNullException.ThrowIfNull(currentAvailable);
        ArgumentNullException.ThrowIfNull(destinationId);
        ArgumentNullException.ThrowIfNull(isDraining);

        for (var i = 0; i < currentAvailable.Count; i++)
        {
            var candidate = currentAvailable[i];
            if (string.Equals(destinationId(candidate), selectedDestinationId, StringComparison.Ordinal) &&
                !isDraining(candidate) &&
                (matchesOriginalSelection is null || matchesOriginalSelection(candidate)))
                return true;
        }
        return false;
    }
}
