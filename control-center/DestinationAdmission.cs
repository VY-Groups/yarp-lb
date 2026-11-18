using System.Globalization;
using System.Text.Json.Nodes;

/// <summary>Opt-in per-destination request admission limits stored in destination Metadata.</summary>
public readonly record struct DestinationAdmissionPolicy(int MaxInFlight, int MaxPending, int QueueTimeoutMs)
{
    public const string MaxInFlightKey = "GatewayCore.Admission.MaxInFlight";
    public const string MaxPendingKey = "GatewayCore.Admission.MaxPending";
    public const string QueueTimeoutMsKey = "GatewayCore.Admission.QueueTimeoutMs";
    public const int MaximumPending = 4096;
    public const int DefaultQueueTimeoutMs = 5000;
    public bool Enabled => MaxInFlight > 0;

    public static bool TryParse(IReadOnlyDictionary<string, string>? metadata,
        out DestinationAdmissionPolicy policy, out string error)
    {
        policy = default;
        error = "";
        if (metadata is null) return true;

        var hasMax = metadata.TryGetValue(MaxInFlightKey, out var maxText);
        var hasPending = metadata.TryGetValue(MaxPendingKey, out var pendingText);
        var hasTimeout = metadata.TryGetValue(QueueTimeoutMsKey, out var timeoutText);
        if (!hasMax && !hasPending && !hasTimeout) return true;
        if (!hasMax)
        {
            error = $"{MaxInFlightKey} is required when per-destination admission metadata is configured";
            return false;
        }
        if (!TryInteger(maxText, 1, 50000, out var maxInFlight))
        {
            error = $"{MaxInFlightKey} must be an integer from 1 to 50000";
            return false;
        }
        var maxPending = 0;
        if (hasPending && !TryInteger(pendingText, 0, MaximumPending, out maxPending))
        {
            error = $"{MaxPendingKey} must be an integer from 0 to {MaximumPending}";
            return false;
        }
        var timeoutMs = DefaultQueueTimeoutMs;
        if (hasTimeout && !TryInteger(timeoutText, 1, 60000, out timeoutMs))
        {
            error = $"{QueueTimeoutMsKey} must be an integer from 1 to 60000";
            return false;
        }
        policy = new DestinationAdmissionPolicy(maxInFlight, maxPending, timeoutMs);
        return true;
    }

    public static bool TryParse(JsonObject? metadata, out DestinationAdmissionPolicy policy, out string error)
    {
        if (metadata is null) return TryParse((IReadOnlyDictionary<string, string>?)null, out policy, out error);
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var key in new[] { MaxInFlightKey, MaxPendingKey, QueueTimeoutMsKey })
        {
            if (!metadata.TryGetPropertyValue(key, out var value)) continue;
            if (value is null)
            {
                policy = default;
                error = $"{key} cannot be null";
                return false;
            }
            values[key] = value.ToString();
        }
        return TryParse(values, out policy, out error);
    }

    private static bool TryInteger(string? text, int min, int max, out int result) =>
        int.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out result) &&
        result >= min && result <= max;
}

public enum DestinationAdmissionFailure
{
    None,
    QueueFull,
    QueueTimeout,
    ClientAborted,
    ServiceStopping,
    DestinationUnavailable,
    RegistryFull
}

public readonly record struct DestinationAdmissionSnapshot(
    int InFlight, int Queued, long Rejected, long TimedOut, long Canceled,
    long WaitDurationCount, double WaitDurationSecondsSum);

public readonly record struct DestinationAdmissionConfiguration(
    string Cluster, string Destination, DestinationAdmissionPolicy Policy);

public readonly record struct DestinationAdmissionReconcileResult(
    bool Applied, int PolicyConflicts, int CapacityExceeded);

/// <summary>
/// FIFO request gate for one stable cluster/destination identity. It tracks the
/// whole proxy middleware lifetime, rather than a TCP connection or response-header wait.
/// </summary>
public sealed class DestinationAdmissionState
{
    private sealed class Waiter(CancellationToken cancellationToken, Action? releasePending)
    {
        internal readonly TaskCompletionSource<DestinationAdmissionLease> Completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly CancellationToken CancellationToken = cancellationToken;
        internal readonly long CreatedTimestamp = System.Diagnostics.Stopwatch.GetTimestamp();
        internal LinkedListNode<Waiter>? Node;
        internal CancellationTokenRegistration Registration;
        internal bool Completed;
        internal Action? ReleasePending = releasePending;
        internal void ReleasePendingReservation() => Interlocked.Exchange(ref ReleasePending, null)?.Invoke();
    }

    private readonly object _sync = new();
    private readonly LinkedList<Waiter> _waiters = new();
    private DestinationAdmissionPolicy _policy;
    private bool _admissionBlocked;
    private int _inFlight;
    private long _rejected;
    private long _timedOut;
    private long _canceled;
    private long _waitDurationCount;
    private long _waitDurationTicks;
    private readonly Func<bool>? _reservePending;
    private readonly Action? _releasePending;

    public DestinationAdmissionState(DestinationAdmissionPolicy policy,
        Func<bool>? reservePending = null, Action? releasePending = null)
    {
        _policy = policy;
        _reservePending = reservePending;
        _releasePending = releasePending;
    }

    public DestinationAdmissionSnapshot Snapshot
    {
        get
        {
            lock (_sync)
                return new(_inFlight, _waiters.Count,
                    Interlocked.Read(ref _rejected), Interlocked.Read(ref _timedOut),
                    Interlocked.Read(ref _canceled), Interlocked.Read(ref _waitDurationCount),
                    Interlocked.Read(ref _waitDurationTicks) / (double)System.Diagnostics.Stopwatch.Frequency);
        }
    }

    public bool IsIdle
    {
        get { lock (_sync) return _inFlight == 0 && _waiters.Count == 0; }
    }

    public DestinationAdmissionPolicy Policy
    {
        get { lock (_sync) return _policy; }
    }

    /// <summary>
    /// Apply a policy change without resetting live permits. A queue-limit decrease
    /// that would strand already accepted waiters is rejected atomically.
    /// </summary>
    public bool TryUpdatePolicy(DestinationAdmissionPolicy policy)
    {
        List<Waiter>? granted = null;
        lock (_sync)
        {
            if (_waiters.Count > policy.MaxPending)
            {
                _admissionBlocked = true;
                return false;
            }
            _policy = policy;
            _admissionBlocked = false;
            granted = GrantWaitersLocked();
        }
        CompleteGranted(granted);
        return true;
    }

    public ValueTask<DestinationAdmissionLease?> AcquireAsync(CancellationToken cancellationToken)
    {
        Waiter? waiter = null;
        lock (_sync)
        {
            if (cancellationToken.IsCancellationRequested)
                return ValueTask.FromCanceled<DestinationAdmissionLease?>(cancellationToken);

            // A failed queue-shrink update fences handles acquired under the
            // previous revision from adding new work. Existing waiters remain
            // accepted and continue to drain through Release().
            if (_admissionBlocked)
            {
                Interlocked.Increment(ref _rejected);
                return ValueTask.FromResult<DestinationAdmissionLease?>(null);
            }

            if (_inFlight < _policy.MaxInFlight && _waiters.Count == 0)
            {
                _inFlight++;
                return ValueTask.FromResult<DestinationAdmissionLease?>(new DestinationAdmissionLease(this));
            }

            if (_waiters.Count >= _policy.MaxPending ||
                (_reservePending is not null && !_reservePending()))
            {
                Interlocked.Increment(ref _rejected);
                return ValueTask.FromResult<DestinationAdmissionLease?>(null);
            }

            waiter = new Waiter(cancellationToken, _releasePending);
            waiter.Node = _waiters.AddLast(waiter);
        }

        if (cancellationToken.CanBeCanceled)
        {
            var registration = cancellationToken.Register(static state =>
            {
                var tuple = ((DestinationAdmissionState Owner, Waiter Waiter))state!;
                tuple.Owner.CancelWaiter(tuple.Waiter);
            }, (this, waiter));
            var disposeRegistration = false;
            lock (_sync)
            {
                if (waiter.Completed) disposeRegistration = true;
                else waiter.Registration = registration;
            }
            if (disposeRegistration) registration.Dispose();
        }
        return AwaitWaiter(waiter);
    }

    public void RecordTimeout() => Interlocked.Increment(ref _timedOut);

    private void RecordWaitDuration(Waiter waiter)
    {
        var elapsed = System.Diagnostics.Stopwatch.GetTimestamp() - waiter.CreatedTimestamp;
        Interlocked.Add(ref _waitDurationTicks, Math.Max(0, elapsed));
        Interlocked.Increment(ref _waitDurationCount);
    }

    private static async ValueTask<DestinationAdmissionLease?> AwaitWaiter(Waiter waiter) =>
        await waiter.Completion.Task.ConfigureAwait(false);

    private void CancelWaiter(Waiter waiter)
    {
        var removed = false;
        lock (_sync)
        {
            if (!waiter.Completed && waiter.Node is not null)
            {
                _waiters.Remove(waiter.Node);
                waiter.Node = null;
                waiter.Completed = true;
                removed = true;
            }
        }
        if (!removed) return;
        RecordWaitDuration(waiter);
        waiter.ReleasePendingReservation();
        Interlocked.Increment(ref _canceled);
        waiter.Completion.TrySetCanceled(waiter.CancellationToken);
    }

    private void Release()
    {
        List<Waiter>? granted;
        lock (_sync)
        {
            if (_inFlight <= 0) throw new InvalidOperationException("Destination admission permit underflow");
            _inFlight--;
            granted = GrantWaitersLocked();
        }
        CompleteGranted(granted);
    }

    private List<Waiter>? GrantWaitersLocked()
    {
        List<Waiter>? granted = null;
        while (_inFlight < _policy.MaxInFlight && _waiters.First is { } first)
        {
            var waiter = first.Value;
            _waiters.RemoveFirst();
            waiter.Node = null;
            waiter.Completed = true;
            _inFlight++;
            (granted ??= new List<Waiter>()).Add(waiter);
        }
        return granted;
    }

    private void CompleteGranted(List<Waiter>? granted)
    {
        if (granted is null) return;
        foreach (var waiter in granted)
        {
            waiter.Registration.Dispose();
            RecordWaitDuration(waiter);
            waiter.ReleasePendingReservation();
            waiter.Completion.TrySetResult(new DestinationAdmissionLease(this));
        }
    }

    public sealed class DestinationAdmissionLease : IDisposable
    {
        private DestinationAdmissionState? _owner;
        internal DestinationAdmissionLease(DestinationAdmissionState owner) => _owner = owner;
        public void Dispose() => Interlocked.Exchange(ref _owner, null)?.Release();
    }
}

/// <summary>A reference to a registry entry held from admission lookup through forwarding completion.</summary>
public sealed class DestinationAdmissionHandle : IDisposable
{
    private Action? _release;
    internal DestinationAdmissionHandle(DestinationAdmissionState state, Action release)
    { State = state; _release = release; }
    public DestinationAdmissionState State { get; }
    public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
}

/// <summary>
/// Bounded per-destination registry. Lookups acquire a reference while holding the
/// registry lock; an entry can only be retired after config removal, zero references,
/// and an idle gate, so no request can race eviction and create a second gate.
/// </summary>
public sealed class DestinationAdmissionManager
{
    public const int MaximumTrackedDestinations = 4096;
    public const int MaximumGlobalPending = 16384;
    private readonly object _sync = new();
    private sealed class Entry(DestinationAdmissionState state)
    {
        public DestinationAdmissionState State { get; } = state;
        public int References;
        public bool Configured;
        public bool PolicyConflict;
    }
    private readonly Dictionary<(string Cluster, string Destination), Entry> _states = new();
    private int _pending;
    private long _lastConfigurationRevision;
    public int PendingCount => Volatile.Read(ref _pending);
    public int TrackedDestinationCount { get { lock (_sync) return _states.Count; } }

    public bool TryAcquireHandle(string clusterId, string destinationId,
        out DestinationAdmissionHandle? handle, out bool policyConflict)
    {
        lock (_sync)
        {
            var key = (clusterId, destinationId);
            if (_states.TryGetValue(key, out var existing) && existing.Configured)
            {
                handle = null;
                if (existing.PolicyConflict) { policyConflict = true; return false; }
                existing.References++;
                handle = new(existing.State, () => ReleaseHandle(key, existing));
                policyConflict = false;
                return true;
            }
            handle = null;
            policyConflict = false;
            return false;
        }
    }

    /// <summary>
    /// Apply policies from an already-applied proxy snapshot. Monotonic revisions
    /// fence delayed snapshots; request-time lookups never change a gate's policy.
    /// </summary>
    public DestinationAdmissionReconcileResult ReconcileConfiguredDestinations(long revision,
        IEnumerable<DestinationAdmissionConfiguration> configured)
    {
        var active = configured.Where(item => item.Policy.Enabled)
            .ToDictionary(item => (item.Cluster, item.Destination), item => item.Policy);
        lock (_sync)
        {
            if (revision <= _lastConfigurationRevision)
                return new(false, 0, 0);

            var policyConflicts = 0;
            var capacityExceeded = 0;
            foreach (var (key, policy) in active)
            {
                if (_states.TryGetValue(key, out var existing))
                {
                    existing.Configured = true;
                    existing.PolicyConflict = !existing.State.TryUpdatePolicy(policy);
                    if (existing.PolicyConflict) policyConflicts++;
                    continue;
                }
                if (_states.Count >= MaximumTrackedDestinations)
                {
                    capacityExceeded++;
                    continue;
                }

                var entry = new Entry(new DestinationAdmissionState(policy, TryReservePending, ReleasePending))
                { Configured = true };
                _states.Add(key, entry);
            }

            foreach (var pair in _states.ToArray())
            {
                var isConfigured = active.ContainsKey(pair.Key);
                pair.Value.Configured = isConfigured;
                if (!isConfigured && pair.Value.References == 0 && pair.Value.State.IsIdle)
                    _states.Remove(pair.Key);
            }
            _lastConfigurationRevision = revision;
            return new(true, policyConflicts, capacityExceeded);
        }
    }

    private void ReleaseHandle((string Cluster, string Destination) key, Entry entry)
    {
        lock (_sync)
        {
            if (entry.References <= 0) throw new InvalidOperationException("Destination registry reference underflow");
            entry.References--;
            if (entry.References == 0 && !entry.Configured && entry.State.IsIdle &&
                _states.TryGetValue(key, out var current) && ReferenceEquals(current, entry))
                _states.Remove(key);
        }
    }

    public bool TryGetSnapshot(string clusterId, string destinationId, out DestinationAdmissionSnapshot snapshot)
    {
        lock (_sync)
        {
            if (_states.TryGetValue((clusterId, destinationId), out var entry))
            {
                snapshot = entry.State.Snapshot;
                return true;
            }
            snapshot = default;
            return false;
        }
    }

    private bool TryReservePending()
    {
        while (true)
        {
            var current = Volatile.Read(ref _pending);
            if (current >= MaximumGlobalPending) return false;
            if (Interlocked.CompareExchange(ref _pending, current + 1, current) == current) return true;
        }
    }

    private void ReleasePending()
    {
        if (Interlocked.Decrement(ref _pending) < 0)
            throw new InvalidOperationException("Global destination admission queue underflow");
    }
}
