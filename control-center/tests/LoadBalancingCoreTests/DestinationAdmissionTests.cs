using System.Collections.Generic;
using System.Diagnostics;
using System.Text.Json.Nodes;

public static class DestinationAdmissionTests
{
    public static async Task RunAsync()
    {
        static void Check(bool ok, string label)
        {
            if (!ok) throw new Exception("FAIL: " + label);
            Console.WriteLine("PASS: " + label);
        }
        static DestinationAdmissionConfiguration Config(string cluster, string destination,
            DestinationAdmissionPolicy policy) => new(cluster, destination, policy);
        static void Apply(DestinationAdmissionManager manager, long revision,
            params DestinationAdmissionConfiguration[] configured)
        {
            var result = manager.ReconcileConfiguredDestinations(revision, configured);
            if (!result.Applied) throw new Exception("FAIL: fresh applied-config revision was rejected");
        }

        Check(DestinationAdmissionPolicy.TryParse((IReadOnlyDictionary<string, string>?)null, out var disabled, out _) && !disabled.Enabled,
            "per-destination admission stays disabled by default");
        var valid = new Dictionary<string, string>
        {
            [DestinationAdmissionPolicy.MaxInFlightKey] = "2",
            [DestinationAdmissionPolicy.MaxPendingKey] = "3",
            [DestinationAdmissionPolicy.QueueTimeoutMsKey] = "1500"
        };
        Check(DestinationAdmissionPolicy.TryParse(valid, out var policy, out _) &&
              policy == new DestinationAdmissionPolicy(2, 3, 1500), "explicit per-destination bounds parse");
        Check(DestinationAdmissionPolicy.TryParse(JsonNode.Parse("{\"GatewayCore.Admission.MaxInFlight\":\"2\",\"GatewayCore.Admission.MaxPending\":\"0\"}") as JsonObject,
                out var jsonPolicy, out _) && jsonPolicy == new DestinationAdmissionPolicy(2, 0, 5000),
            "JSON configuration defaults queue timeout and disables pending queue");
        foreach (var bad in new[] { "0", "-1", "50001", "1.5", " 2" })
        {
            var values = new Dictionary<string, string> { [DestinationAdmissionPolicy.MaxInFlightKey] = bad };
            Check(!DestinationAdmissionPolicy.TryParse(values, out _, out _), "invalid max in-flight rejects " + bad);
        }
        var incomplete = new Dictionary<string, string>
        {
            [DestinationAdmissionPolicy.MaxPendingKey] = "1"
        };
        Check(!DestinationAdmissionPolicy.TryParse(incomplete, out _, out _),
            "queue settings cannot enable a partial policy");

        var single = new DestinationAdmissionState(new DestinationAdmissionPolicy(1, 2, 5000));
        using var first = await single.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: first destination permit should be acquired");
        var fifo1 = single.AcquireAsync(CancellationToken.None).AsTask();
        var fifo2 = single.AcquireAsync(CancellationToken.None).AsTask();
        var full = await single.AcquireAsync(CancellationToken.None);
        Check(full is null, "queue capacity rejects excess request immediately");
        Check(single.Snapshot is { InFlight: 1, Queued: 2, Rejected: 1 },
            "in-flight, queued and rejected counts are exact");
        first.Dispose();
        using var second = await fifo1.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: first FIFO waiter should receive the released permit");
        Check(!fifo2.IsCompleted, "oldest waiter receives the released slot first");
        second.Dispose();
        using var third = await fifo2.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: second FIFO waiter should receive the next permit");
        third.Dispose();
        Check(single.Snapshot is { InFlight: 0, Queued: 0, WaitDurationCount: 2 }, "permit accounting and queue wait timing return to zero after FIFO drain");

        var canceledGate = new DestinationAdmissionState(new DestinationAdmissionPolicy(1, 2, 5000));
        using var held = await canceledGate.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: cancellation fixture permit should be acquired");
        using var cancel = new CancellationTokenSource();
        var canceledWait = canceledGate.AcquireAsync(cancel.Token).AsTask();
        cancel.Cancel();
        var canceled = false;
        try { await canceledWait.WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (OperationCanceledException) { canceled = true; }
        Check(canceled && canceledGate.Snapshot is { InFlight: 1, Queued: 0, Canceled: 1, WaitDurationCount: 1 },
            "client cancellation removes its queued waiter without leaking a slot");
        var nextWait = canceledGate.AcquireAsync(CancellationToken.None).AsTask();
        held.Dispose();
        using var next = await nextWait.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: next waiter should receive the released permit");
        next.Dispose();

        var grantRaceGate = new DestinationAdmissionState(new DestinationAdmissionPolicy(1, 1, 5000));
        using (var raceHeld = await grantRaceGate.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: grant/cancellation race fixture"))
        using (var raceAbort = new CancellationTokenSource())
        using (var raceShutdown = new CancellationTokenSource())
        using (var raceTimeout = CancellationTokenSource.CreateLinkedTokenSource(raceAbort.Token, raceShutdown.Token))
        {
            var raceWaiter = grantRaceGate.AcquireAsync(raceTimeout.Token).AsTask();
            raceHeld.Dispose();
            using (var granted = await raceWaiter.WaitAsync(TimeSpan.FromSeconds(2)) ??
                throw new Exception("FAIL: race waiter must receive a permit"))
            {
                Check(DestinationAdmissionForwarding.FailureAfterGrant(raceAbort.Token,
                    raceShutdown.Token, raceTimeout.Token) == DestinationAdmissionFailure.None,
                    "uncanceled granted request remains eligible");
                raceTimeout.Cancel();
                Check(DestinationAdmissionForwarding.FailureAfterGrant(raceAbort.Token,
                    raceShutdown.Token, raceTimeout.Token) == DestinationAdmissionFailure.QueueTimeout,
                    "queue timeout after grant fences forwarding");
                raceShutdown.Cancel();
                Check(DestinationAdmissionForwarding.FailureAfterGrant(raceAbort.Token,
                    raceShutdown.Token, raceTimeout.Token) == DestinationAdmissionFailure.ServiceStopping,
                    "shutdown wins over queue timeout after grant");
                raceAbort.Cancel();
                Check(DestinationAdmissionForwarding.FailureAfterGrant(raceAbort.Token,
                    raceShutdown.Token, raceTimeout.Token) == DestinationAdmissionFailure.ClientAborted,
                    "client abort wins over other rejection causes");
            }
            Check(grantRaceGate.Snapshot is { InFlight: 0, Queued: 0 },
                "post-grant cancellation rejection releases the lease and queue slot");
        }

        using (var completedQueueWait = new CancellationTokenSource())
        {
            var started = Stopwatch.GetTimestamp();
            Check(DestinationAdmissionForwarding.CompleteQueueWait(completedQueueWait,
                    CancellationToken.None, CancellationToken.None, started, TimeSpan.FromSeconds(30)) ==
                  DestinationAdmissionFailure.None && !completedQueueWait.IsCancellationRequested,
                "successful admission disarms its queue timer before forwarding");
            completedQueueWait.Cancel();
        }
        using (var expiredQueueWait = new CancellationTokenSource())
        {
            // Model the timer callback being delayed past its deadline: the
            // CTS is still live, but the monotonic deadline itself has passed.
            var startedBeforeTimeout = Stopwatch.GetTimestamp() -
                (long)Math.Ceiling(Stopwatch.Frequency * 2d);
            Check(DestinationAdmissionForwarding.CompleteQueueWait(expiredQueueWait,
                    CancellationToken.None, CancellationToken.None, startedBeforeTimeout,
                    TimeSpan.FromSeconds(1)) == DestinationAdmissionFailure.QueueTimeout,
                "elapsed monotonic deadline fences grant even before timer callback cancels");
        }
        using (var canceledQueueWait = new CancellationTokenSource())
        {
            canceledQueueWait.Cancel();
            Check(DestinationAdmissionForwarding.CompleteQueueWait(canceledQueueWait,
                    CancellationToken.None, CancellationToken.None, Stopwatch.GetTimestamp(),
                    TimeSpan.FromSeconds(30)) == DestinationAdmissionFailure.QueueTimeout,
                "already-fired queue cancellation remains fenced after timer disarm");
        }

        var drainGate = new DestinationAdmissionState(new DestinationAdmissionPolicy(1, 1, 5000));
        using var activeOnEast = await drainGate.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: selected destination permit should be acquired");
        var queuedForEast = drainGate.AcquireAsync(CancellationToken.None).AsTask();
        Check(drainGate.Snapshot is { InFlight: 1, Queued: 1 },
            "request queues behind the originally selected backend");
        activeOnEast.Dispose();
        using var grantedForEast = await queuedForEast.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: queued request should receive the released destination permit");
        var availableAfterFailure = new[] { new AdmissionDestination("west", IsDraining: false) };
        Check(!DestinationAdmissionForwarding.IsStillEligibleAfterWait("east", availableAfterFailure,
                  static destination => destination.Id, static destination => destination.IsDraining),
            "queued request is rejected rather than transferred when its backend becomes unavailable and another remains healthy");
        var drainingSelected = new[] { new AdmissionDestination("east", IsDraining: true) };
        Check(!DestinationAdmissionForwarding.IsStillEligibleAfterWait("east", drainingSelected,
                  static destination => destination.Id, static destination => destination.IsDraining),
            "queued request is rejected when its selected backend is marked draining");
        var stillEligible = new[] { new AdmissionDestination("east", IsDraining: false) };
        Check(DestinationAdmissionForwarding.IsStillEligibleAfterWait("east", stillEligible,
                  static destination => destination.Id, static destination => destination.IsDraining),
            "queued request can continue when its original backend remains available and ready");
        grantedForEast.Dispose();
        Check(drainGate.Snapshot is { InFlight: 0, Queued: 0 },
            "post-queue rejection path releases the granted backend permit");

        var manager = new DestinationAdmissionManager();
        Apply(manager, 1, Config("app", "east", new(1, 0, 5000)), Config("app", "west", new(1, 0, 5000)));
        Check(manager.TryAcquireHandle("app", "east", out var eastHandle, out _) && eastHandle is not null,
            "manager creates bounded destination gate");
        Check(manager.TryAcquireHandle("app", "west", out var westHandle, out _) && westHandle is not null,
            "manager creates independent destination gate");
        var policyUpdate = new DestinationAdmissionState(new DestinationAdmissionPolicy(1, 1, 5000));
        using var updateHeld = await policyUpdate.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: policy update fixture permit should be acquired");
        var updateWaiter = policyUpdate.AcquireAsync(CancellationToken.None).AsTask();
        Check(!policyUpdate.TryUpdatePolicy(new(1, 0, 5000)) && policyUpdate.Snapshot.Queued == 1,
            "queue shrink refuses to strand an already accepted waiter");
        updateHeld.Dispose();
        using var updatedPermit = await updateWaiter.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: policy update fixture waiter should receive the released permit");
        updatedPermit.Dispose();
        using var eastPermit = await eastHandle!.State.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: east permit should be acquired");
        using var westPermit = await westHandle!.State.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: west permit should be independent");
        var rejectedShrink = !eastHandle.State.TryUpdatePolicy(new(1, 0, 5000));
        Check(!rejectedShrink, "policy remains applicable when no queued requests would be stranded");
        Check(eastHandle.State.Snapshot.InFlight == 1 && westHandle.State.Snapshot.InFlight == 1,
            "separate destinations hold independent simultaneous capacity");
        eastHandle.Dispose();
        westHandle.Dispose();

        var boundedManager = new DestinationAdmissionManager();
        Apply(boundedManager, 1, Config("app", "queued", new(1, 1, 5000)));
        Check(boundedManager.TryAcquireHandle("app", "queued", out var queuedHandle, out _) && queuedHandle is not null,
            "manager creates a queued destination state");
        using var queuedStateHandle = queuedHandle!;
        var queuedState = queuedStateHandle.State;
        using var queuedHeld = await queuedState!.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: manager queue fixture permit should be acquired");
        using var queuedCancel = new CancellationTokenSource();
        var managerWaiter = queuedState.AcquireAsync(queuedCancel.Token).AsTask();
        Check(boundedManager.PendingCount == 1, "manager reserves one global queued-request slot");
        queuedCancel.Cancel();
        try { await managerWaiter.WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (OperationCanceledException) { }
        Check(boundedManager.PendingCount == 0, "canceled waiter releases global queue capacity");
        var managerWaiter2 = queuedState.AcquireAsync(CancellationToken.None).AsTask();
        queuedHeld.Dispose();
        using var managerGranted = await managerWaiter2.WaitAsync(TimeSpan.FromSeconds(2)) ??
            throw new Exception("FAIL: manager queue fixture waiter should be granted");
        Check(boundedManager.PendingCount == 0, "granted waiter releases global queue capacity");

        var retirementManager = new DestinationAdmissionManager();
        Apply(retirementManager, 1, Config("app", "retiring", new(1, 0, 5000)));
        Check(retirementManager.TryAcquireHandle("app", "retiring", out var firstHandle, out _) && firstHandle is not null,
            "registry returns a reference-counted handle");
        var firstState = firstHandle!.State;
        using var firstLease = await firstState.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: retiring fixture permit should be acquired");
        Apply(retirementManager, 2);
        Check(!retirementManager.TryAcquireHandle("app", "retiring", out _, out _) &&
              retirementManager.TrackedDestinationCount == 1,
            "retired destination stops new handles but keeps its gate while a forwarding lease is live");
        firstLease.Dispose();
        firstHandle.Dispose();
        Check(retirementManager.TrackedDestinationCount == 0,
            "retired gate is reclaimed after its last handle and forwarding lease finish");

        var racingManager = new DestinationAdmissionManager();
        Apply(racingManager, 1, Config("app", "race", new(1, 0, 5000)));
        var overlap = 0;
        var maximumOverlap = 0;
        var racers = Enumerable.Range(0, 2).Select(_iteration => Task.Run(async () =>
        {
            for (var i = 0; i < 500; i++)
            {
                if (!racingManager.TryAcquireHandle("app", "race", out var handle, out _) || handle is null)
                    throw new Exception("FAIL: race registry lookup unexpectedly failed");
                using (handle)
                {
                    using var lease = await handle.State.AcquireAsync(CancellationToken.None);
                    if (lease is null) continue;
                    var current = Interlocked.Increment(ref overlap);
                    int observed;
                    do { observed = Volatile.Read(ref maximumOverlap); }
                    while (current > observed && Interlocked.CompareExchange(ref maximumOverlap, current, observed) != observed);
                    await Task.Yield();
                    Interlocked.Decrement(ref overlap);
                }
            }
        })).ToArray();
        await Task.WhenAll(racers);
        Check(maximumOverlap == 1 && racingManager.TrackedDestinationCount == 1,
            "concurrent acquisition never splits one configured destination into independent gates");

        var snapshotManager = new DestinationAdmissionManager();
        using var staleCaptured = new ManualResetEventSlim();
        using var releaseStaleSnapshot = new ManualResetEventSlim();
        DestinationAdmissionReconcileResult staleResult = default;
        var stalePublisher = Task.Run(() =>
        {
            // Simulate an older applied-config snapshot captured before revision 2,
            // but delayed until after revision 2 has already reconciled.
            staleCaptured.Set();
            releaseStaleSnapshot.Wait();
            staleResult = snapshotManager.ReconcileConfiguredDestinations(1,
                [Config("app", "revision-race", new(2, 0, 5000))]);
        });
        staleCaptured.Wait();
        Apply(snapshotManager, 2, Config("app", "revision-race", new(1, 0, 5000)));
        releaseStaleSnapshot.Set();
        await stalePublisher.WaitAsync(TimeSpan.FromSeconds(2));
        Check(!staleResult.Applied, "older applied-config revision is rejected after a newer revision");
        if (!snapshotManager.TryAcquireHandle("app", "revision-race", out var currentPolicyHandle, out _) ||
            currentPolicyHandle is null)
            throw new Exception("FAIL: reconciled destination could not be acquired");
        Check(currentPolicyHandle.State.Policy == new DestinationAdmissionPolicy(1, 0, 5000),
            "delayed permissive snapshot cannot restore stale higher limits");
        using (currentPolicyHandle)
        using (var onlyPermit = await currentPolicyHandle.State.AcquireAsync(CancellationToken.None) ??
               throw new Exception("FAIL: current admission permit should be available"))
        {
            Check(await currentPolicyHandle.State.AcquireAsync(CancellationToken.None) is null,
                "reconciled current policy governs subsequent requests");
        }

        var conflictManager = new DestinationAdmissionManager();
        Apply(conflictManager, 1, Config("app", "shrink-conflict", new(1, 1, 5000)));
        if (!conflictManager.TryAcquireHandle("app", "shrink-conflict", out var conflictHandle, out _) ||
            conflictHandle is null)
            throw new Exception("FAIL: conflict fixture destination could not be acquired");
        if (!conflictManager.TryAcquireHandle("app", "shrink-conflict", out var delayedHandle, out _) ||
            delayedHandle is null)
            throw new Exception("FAIL: delayed admission handle should be acquired before policy shrink");
        using (conflictHandle)
        using (delayedHandle)
        using (var heldConflictPermit = await conflictHandle.State.AcquireAsync(CancellationToken.None) ??
               throw new Exception("FAIL: conflict fixture permit should be acquired"))
        {
            var acceptedWaiter = conflictHandle.State.AcquireAsync(CancellationToken.None).AsTask();
            Check(conflictHandle.State.Snapshot.Queued == 1,
                "applied policy shrink fixture has one accepted waiter");
            var conflicted = conflictManager.ReconcileConfiguredDestinations(2,
                [Config("app", "shrink-conflict", new(1, 0, 5000))]);
            Check(conflicted.Applied && conflicted.PolicyConflicts == 1 &&
                  !conflictManager.TryAcquireHandle("app", "shrink-conflict", out _, out var updateConflict) && updateConflict,
                "unsafe applied queue shrink blocks new handles until accepted waiter drains");
            var delayedAcquire = await delayedHandle.State.AcquireAsync(CancellationToken.None);
            Check(delayedAcquire is null && conflictHandle.State.Snapshot is { Queued: 1, Rejected: 1 },
                "handle acquired before a failed shrink cannot enqueue afterward while accepted waiters drain");
            heldConflictPermit.Dispose();
            using var drainedWaiter = await acceptedWaiter.WaitAsync(TimeSpan.FromSeconds(2)) ??
                throw new Exception("FAIL: previously accepted waiter should drain under old policy");
            drainedWaiter.Dispose();
        }
        var safeRetry = conflictManager.ReconcileConfiguredDestinations(3,
            [Config("app", "shrink-conflict", new(1, 0, 5000))]);
        if (!safeRetry.Applied || safeRetry.PolicyConflicts != 0 ||
            !conflictManager.TryAcquireHandle("app", "shrink-conflict", out var retryHandle, out _) || retryHandle is null)
            throw new Exception("FAIL: later applied revision did not install the safe policy");
        Check(retryHandle.State.Policy == new DestinationAdmissionPolicy(1, 0, 5000),
            "later monotonic applied revision installs the policy after accepted waiters drain");
        retryHandle.Dispose();

        var canceledManager = new DestinationAdmissionManager();
        Apply(canceledManager, 1, Config("app", "cancel", new(1, 1, 5000)));
        Check(canceledManager.TryAcquireHandle("app", "cancel", out var ownerHandle, out _) && ownerHandle is not null,
            "cancellation registry owner acquired");
        using var ownerLease = await ownerHandle!.State.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: cancellation registry owner permit should be acquired");
        Check(canceledManager.TryAcquireHandle("app", "cancel", out var waiterHandle, out _) && waiterHandle is not null,
            "cancellation waiter holds a registry reference");
        using var waiterRegistryHandle = waiterHandle!;
        using var timeoutToken = new CancellationTokenSource();
        var timedWait = waiterRegistryHandle.State.AcquireAsync(timeoutToken.Token).AsTask();
        Apply(canceledManager, 2);
        timeoutToken.Cancel();
        try { await timedWait.WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (OperationCanceledException) { waiterRegistryHandle.State.RecordTimeout(); }
        waiterRegistryHandle.Dispose();
        ownerLease.Dispose();
        ownerHandle.Dispose();
        Check(canceledManager.PendingCount == 0 && canceledManager.TrackedDestinationCount == 0,
            "timeout cancellation releases queue reservation and retired registry entry");

        var churnManager = new DestinationAdmissionManager();
        var churnSucceeded = true;
        long churnRevision = 0;
        for (var i = 0; i <= DestinationAdmissionManager.MaximumTrackedDestinations; i++)
        {
            var key = "destination-" + i;
            Apply(churnManager, ++churnRevision, Config("churn", key, new(1, 0, 5000)));
            if (!churnManager.TryAcquireHandle("churn", key, out var churnHandle, out _) || churnHandle is null)
            { churnSucceeded = false; break; }
            churnHandle!.Dispose();
            Apply(churnManager, ++churnRevision);
        }
        Check(churnSucceeded && churnManager.TrackedDestinationCount == 0,
            "4097 destination replacements are reclaimed without exceeding the registry cap");
    }

    private readonly record struct AdmissionDestination(string Id, bool IsDraining);
}
