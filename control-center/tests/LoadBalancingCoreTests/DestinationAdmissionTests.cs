using System.Collections.Generic;
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

        var manager = new DestinationAdmissionManager();
        Check(manager.TryGetOrCreate("app", "east", new(1, 0, 5000), out var east) && east is not null,
            "manager creates bounded destination gate");
        Check(manager.TryGetOrCreate("app", "west", new(1, 0, 5000), out var west) && west is not null,
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
        using var eastPermit = await east!.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: east permit should be acquired");
        using var westPermit = await west!.AcquireAsync(CancellationToken.None) ??
            throw new Exception("FAIL: west permit should be independent");
        var rejectedShrink = !east.TryUpdatePolicy(new(1, 0, 5000));
        Check(!rejectedShrink, "policy remains applicable when no queued requests would be stranded");
        Check(east.Snapshot.InFlight == 1 && west.Snapshot.InFlight == 1,
            "separate destinations hold independent simultaneous capacity");

        var boundedManager = new DestinationAdmissionManager();
        Check(boundedManager.TryGetOrCreate("app", "queued", new(1, 1, 5000), out var queuedState) && queuedState is not null,
            "manager creates a queued destination state");
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
    }
}
