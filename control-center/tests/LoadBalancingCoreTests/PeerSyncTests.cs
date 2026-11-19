using System.Net;
using System.Text;

public static class PeerSyncTests
{
    private sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset currentUtc = utcNow;
        private long timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;
        public override long GetTimestamp() => timestamp;
        public override DateTimeOffset GetUtcNow() => currentUtc;

        public void SetUtcNow(DateTimeOffset value) => currentUtc = value;
        public void Advance(TimeSpan elapsed)
        {
            timestamp += elapsed.Ticks;
            currentUtc += elapsed;
        }
    }

    public static void Run()
    {
        static void Check(bool condition,string name)
        {
            if(!condition) throw new Exception("FAIL: " + name);
            Console.WriteLine("PASS: " + name);
        }
        var secret=Enumerable.Repeat((byte)0x42,32).ToArray();
        var publisherClock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var publisherDiagnostics = new PeerSyncPublisherDiagnostics(publisherClock);
        var initialPublisher = publisherDiagnostics.Snapshot();
        Check(initialPublisher.AttemptsTotal == 0 && initialPublisher.AcknowledgementsTotal == 0 &&
              initialPublisher.LastAcknowledgedAgeSeconds is null && initialPublisher.InFlightRequests == 0,
            "publisher diagnostics start bounded with no fabricated acknowledgement");
        publisherDiagnostics.BeginAttempt();
        Check(publisherDiagnostics.Snapshot().InFlightRequests == 1,
            "publisher diagnostics expose one in-flight request without queueing");
        publisherDiagnostics.RecordResponse(acknowledged: false);
        publisherDiagnostics.EndAttempt();
        publisherDiagnostics.BeginAttempt();
        publisherDiagnostics.RecordResponse(acknowledged: true);
        publisherDiagnostics.EndAttempt();
        publisherDiagnostics.BeginAttempt();
        publisherDiagnostics.RecordResponse(acknowledged: false, expectedChallenge: true);
        publisherDiagnostics.EndAttempt();
        publisherClock.Advance(TimeSpan.FromSeconds(4));
        publisherDiagnostics.BeginAttempt();
        publisherDiagnostics.RecordTransportFailure();
        publisherDiagnostics.EndAttempt();
        publisherDiagnostics.RecordResynchronization();
        var publisherStatus = publisherDiagnostics.Snapshot();
        Check(publisherStatus.AttemptsTotal == 4 && publisherStatus.AcknowledgementsTotal == 1 &&
              publisherStatus.HttpFailuresTotal == 1 && publisherStatus.TransportFailuresTotal == 1 &&
              publisherStatus.ResynchronizationsTotal == 1 &&
              publisherStatus.LastAcknowledgedAgeSeconds == 4 && publisherStatus.InFlightRequests == 0,
            "publisher diagnostics count acknowledgements, failures, challenges, resynchronization and monotonic ack age");
        var publisherMetricText = new StringBuilder();
        PeerSyncPrometheus.Append(publisherMetricText, configured: true, status: null,
            publisher: publisherStatus);
        Check(publisherMetricText.ToString().Contains("yarp_peer_sync_publish_attempts_total 4\n", StringComparison.Ordinal) &&
              publisherMetricText.ToString().Contains("yarp_peer_sync_publish_http_failures_total 1\n", StringComparison.Ordinal) &&
              publisherMetricText.ToString().Contains("yarp_peer_sync_publish_last_ack_age_seconds 4\n", StringComparison.Ordinal) &&
              publisherMetricText.ToString().Contains("yarp_peer_sync_publish_in_flight 0\n", StringComparison.Ordinal) &&
              !publisherMetricText.ToString().Contains("yarp_peer_sync_publish_acknowledgements_total{", StringComparison.Ordinal) &&
              !publisherMetricText.ToString().Contains("node-a", StringComparison.Ordinal),
            "publisher metrics expose delivery and age with fixed cardinality and no peer identity labels");

        var deltaSource = new PeerStateJournal("delta-a", "delta-b", secret, 2);
        var deltaClock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var deltaReceiver = new PeerStateJournal("delta-b", "delta-a", secret, 2,
            TimeSpan.FromSeconds(3), timeProvider: deltaClock);
        var dm = PeerStateJournal.CurrentMinute();
        var ip1 = IPAddress.Parse("192.0.2.1");
        var ip2 = IPAddress.Parse("192.0.2.2");
        deltaSource.Observe(ip1, dm);
        deltaSource.Observe(ip2, dm);
        var full = deltaSource.Snapshot(dm) with { ReceiverEpoch = deltaReceiver.ReceiverEpoch };
        Check(deltaReceiver.ApplyBoundFrame(full, dm), "delta baseline full snapshot accepted");
        deltaSource.Observe(ip1, dm);
        var nextFull = deltaSource.Snapshot(dm) with { ReceiverEpoch = deltaReceiver.ReceiverEpoch };
        var delta = PeerDelta.Select(nextFull, full);
        Check(delta.BaseSequence == full.Sequence && delta.Counters.Count == 1,
            "only changed absolute counters are sent in delta");
        Check(!deltaReceiver.ApplyBoundFrame(delta with { BaseSequence = full.Sequence + 1 }, dm),
            "wrong delta base does not mutate receiver");
        var changedKey = delta.Counters.Keys.Single();
        var lowerDeltaKey = changedKey.ToLowerInvariant();
        Check(lowerDeltaKey != changedKey, "delta fixture contains a hexadecimal letter");
        Check(!deltaReceiver.ApplyBoundFrame(delta with { Counters = new Dictionary<string,int>
            { [lowerDeltaKey] = delta.Counters[changedKey] } }, dm) &&
            deltaReceiver.PeerTelemetry(dm) == (2, 2L),
            "noncanonical delta cannot inflate identity cardinality or change the accepted baseline");
        Check(deltaReceiver.ApplyBoundFrame(delta, dm) &&
              deltaReceiver.PeerTelemetry(dm) == (2, 3L) && !deltaReceiver.ApplyBoundFrame(delta, dm),
            "delta merges once without discarding unchanged keys");
        var lostFull = deltaSource.Snapshot(dm) with { ReceiverEpoch = deltaReceiver.ReceiverEpoch };
        deltaSource.Observe(ip2, dm);
        var latestFull = deltaSource.Snapshot(dm) with { ReceiverEpoch = deltaReceiver.ReceiverEpoch };
        Check(!deltaReceiver.ApplyBoundFrame(PeerDelta.Select(latestFull, lostFull), dm),
            "missing predecessor forces full snapshot resynchronization");
        Check(deltaReceiver.ApplyBoundFrame(PeerDelta.Select(latestFull, null), dm) &&
              deltaReceiver.PeerTelemetry(dm) == (2, 4L), "full backfill repairs sequence gap");
        var freshFull = deltaSource.Snapshot(dm) with { ReceiverEpoch = deltaReceiver.ReceiverEpoch };
        deltaClock.Advance(TimeSpan.FromSeconds(4));
        Check(!deltaReceiver.ApplyBoundFrame(PeerDelta.Select(freshFull, latestFull), dm) &&
              deltaReceiver.PeerTelemetry(dm) == (0, 0L), "expired baseline cannot be revived by delta");
        Check(deltaReceiver.ApplyBoundFrame(freshFull, dm) && deltaReceiver.PeerTelemetry(dm) == (2, 4L),
            "fresh full snapshot restores expired receiver");
        var replacementReceiver = new PeerStateJournal("delta-b", "delta-a", secret, 2);
        var replacementFull = deltaSource.Snapshot(dm) with { ReceiverEpoch = replacementReceiver.ReceiverEpoch };
        Check(PeerDelta.Select(replacementFull, freshFull).BaseSequence == 0 &&
              replacementReceiver.ApplyBoundFrame(replacementFull, dm), "receiver restart forces full backfill");

        var a=new PeerStateJournal("node-a","node-b",secret,2);
        var b=new PeerStateJournal("node-b","node-a",secret,2);
        var now=PeerStateJournal.CurrentMinute();
        var client=IPAddress.Parse("10.123.4.5");
        a.Observe(client,now);
        a.Observe(IPAddress.Parse("::ffff:10.123.4.5"),now);
        var frame=a.Snapshot(now);
        var serializedFrame = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(frame);
        // Exercise the network-facing gate independently of the journal's
        // pure counter-state tests below.
        var bootReceiver = new PeerStateJournal("node-b", "node-a", secret, 2);
        var bound = frame with { ReceiverEpoch = bootReceiver.ReceiverEpoch };
        Check(PeerStateJournal.IsReceiverEpoch(bootReceiver.ReceiverEpoch) &&
              !bootReceiver.ApplyBoundFrame(frame, now) &&
              bootReceiver.PeerTelemetry(now) == (0, 0L),
            "unbound initial snapshot cannot populate a receiver");
        Check(bootReceiver.ApplyBoundFrame(bound, now) &&
              !bootReceiver.ApplyBoundFrame(bound, now),
            "receiver-bound signed snapshot is accepted once");
        var replacement = new PeerStateJournal("node-b", "node-a", secret, 2);
        Check(replacement.ReceiverEpoch != bootReceiver.ReceiverEpoch &&
              !replacement.ApplyBoundFrame(bound, now) &&
              replacement.PeerTelemetry(now) == (0, 0L),
            "receiver process replacement rejects captured old-boot snapshot even with empty journal");
        var rebound = a.Snapshot(now) with { ReceiverEpoch = replacement.ReceiverEpoch };
        Check(replacement.ApplyBoundFrame(rebound, now) &&
              replacement.PeerTelemetry(now) == (1, 2L),
            "new snapshot bound to replacement receiver recovers counters");
        var signer = new PeerSignedMessages(secret);
        var boundBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(bound);
        var signedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var (boundNonce, boundSignature) = signer.Sign("node-a", signedAt, boundBytes);
        var reboundBytes = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            bound with { ReceiverEpoch = replacement.ReceiverEpoch });
        Check(!signer.Verify("node-a", "node-a", signedAt, boundNonce, boundSignature, reboundBytes, signedAt) &&
              signer.Verify("node-a", "node-a", signedAt, boundNonce, boundSignature, boundBytes, signedAt),
            "rewriting the receiver epoch invalidates the original HMAC");
        Check(System.Text.Json.JsonDocument.Parse(serializedFrame).RootElement
                  .GetProperty("ProtocolVersion").GetInt32() == PeerStateFrame.CurrentProtocolVersion,
            "peer snapshots carry an explicit protocol version");
        var frameJson = System.Text.Json.JsonDocument.Parse(serializedFrame).RootElement;
        Check(frameJson.GetProperty("TableId").GetString() == PeerStateTableContract.TableId &&
              frameJson.GetProperty("TableVersion").GetInt32() == PeerStateTableContract.TableVersion &&
              frameJson.GetProperty("EntryTtlSeconds").GetInt32() == PeerStateTableContract.EntryTtlSeconds,
            "peer snapshots carry a typed table schema and bounded entry TTL");
        var missingVersionRejected = false;
        try
        {
            _ = System.Text.Json.JsonSerializer.Deserialize<PeerStateFrame>(
                "{\"NodeId\":\"node-a\",\"Minute\":1,\"Sequence\":1,\"Counters\":{},\"SourceEpoch\":1}");
        }
        catch (System.Text.Json.JsonException) { missingVersionRejected = true; }
        Check(missingVersionRejected, "unversioned legacy peer frames are rejected");
        var missingTableContractRejected = false;
        try
        {
            _ = System.Text.Json.JsonSerializer.Deserialize<PeerStateFrame>(
                "{\"NodeId\":\"node-a\",\"Minute\":1,\"Sequence\":1,\"Counters\":{},\"SourceEpoch\":1,\"ProtocolVersion\":2}");
        }
        catch (System.Text.Json.JsonException) { missingTableContractRejected = true; }
        Check(missingTableContractRejected, "peer frames missing required table contract are rejected");
        Check(!b.Apply(frame with { ProtocolVersion = PeerStateFrame.CurrentProtocolVersion + 1 }, now),
            "unknown peer protocol versions are rejected without changing state");
        Check(b.PeerTelemetry(now) == (0, 0L),
            "unknown peer protocol version leaves receiver telemetry unchanged");
        Check(!b.Apply(frame with { TableId = "unknown-table" }, now) &&
              !b.Apply(frame with { TableVersion = PeerStateTableContract.TableVersion + 1 }, now) &&
              !b.Apply(frame with { EntryTtlSeconds = PeerStateTableContract.EntryTtlSeconds + 1 }, now) &&
              b.RetainedRemoteEntries == 0,
            "unknown table, schema version, and TTL are rejected without retaining state");
        Check(frame.Counters.Count==1 && frame.Counters.Values.Single()==2,
            "IPv4 and mapped IPv6 share one hashed identity");
        Check(!frame.Counters.Keys.Single().Contains("10.123"),"no plaintext peer IP transmitted");
        var lower = new string('a',64);
        var upper = lower.ToUpperInvariant();
        Check(!b.Apply(frame with { Counters = new Dictionary<string,int>
            { [upper] = 1, [lower] = 1 } }, now) && b.PeerTelemetry(now) == (0, 0L),
            "case aliases cannot create two identities for one digest");
        Check(!b.Apply(frame with { Counters = new Dictionary<string,int> { [lower] = 1 } }, now),
            "noncanonical lowercase full frame rejected without advancing replay state");
        Check(b.Apply(frame,now),"accept first bounded peer snapshot");
        Check(b.PeerTelemetry(now)==(1,2L),"peer telemetry matches signed source counts");
        // Accepted snapshots must have a recent receipt time, not merely
        // share the same UTC minute. Use an injected clock to avoid sleeps.
        var clock = DateTimeOffset.UtcNow;
        var monotonicClock = new ManualTimeProvider(clock);
        var ageLimited = new PeerStateJournal("node-b", "node-a", secret, 2,
            TimeSpan.FromSeconds(6), () => clock, monotonicClock);
        Check(ageLimited.Apply(frame,now) && ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "fresh remote frame is visible to operational status");
        clock = clock.AddHours(-1);
        monotonicClock.SetUtcNow(clock);
        Check(ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "wall-clock rollback does not prematurely expire monotonic peer freshness");
        var boundaryClock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var boundaryJournal = new PeerStateJournal("node-b", "node-a", secret, 2,
            TimeSpan.FromSeconds(60), timeProvider: boundaryClock);
        Check(boundaryJournal.Apply(frame, now), "peer recency boundary fixture accepts a signed frame");
        boundaryClock.Advance(TimeSpan.FromSeconds(15));
        Check(PeerSyncFreshness.IsRecent(boundaryJournal.Status(now), TimeSpan.FromSeconds(15)),
            "exact recency tolerance remains recent");
        boundaryClock.Advance(TimeSpan.FromMilliseconds(900));
        var overTolerance = boundaryJournal.Status(now);
        Check(overTolerance.LastAcceptedAgeSeconds == 15 &&
              overTolerance.LastAcceptedElapsed is { } exactAge &&
              exactAge > TimeSpan.FromSeconds(15) && exactAge < TimeSpan.FromSeconds(16) &&
              !PeerSyncFreshness.IsRecent(overTolerance, TimeSpan.FromSeconds(15)),
            "a 15.9-second monotonic age is not recent at a 15-second threshold despite integer display rounding");
        monotonicClock.Advance(TimeSpan.FromSeconds(7));
        clock = monotonicClock.GetUtcNow();
        Check(!ageLimited.Status(now).RemoteReportedInCurrentMinute &&
              ageLimited.Status(now).RemoteIdentities == 0 &&
              ageLimited.PeerTelemetry(now)==(0,0L) && ageLimited.RetainedRemoteEntries == 0,
            "monotonic TTL expires and collects remote frame within the same minute");
        var expiredStatus = ageLimited.Status(now);
        Check(expiredStatus.LastAcceptedAgeSeconds == 7,
            "monotonic last-accepted age remains observable after stale counters are collected");
        var peerMetricText = new StringBuilder();
        PeerSyncPrometheus.Append(peerMetricText, configured: true, status: expiredStatus);
        Check(peerMetricText.ToString().Contains("yarp_peer_sync_enabled 1\n", StringComparison.Ordinal) &&
              peerMetricText.ToString().Contains("yarp_peer_sync_remote_fresh 0\n", StringComparison.Ordinal) &&
              peerMetricText.ToString().Contains("yarp_peer_sync_last_accepted_age_seconds 7\n", StringComparison.Ordinal) &&
              !peerMetricText.ToString().Contains("node-a", StringComparison.Ordinal),
            "Prometheus exports peer freshness and monotonic age with no peer identity labels");
        var disabledMetricText = new StringBuilder();
        PeerSyncPrometheus.Append(disabledMetricText, configured: false, status: null);
        Check(disabledMetricText.ToString().Contains("yarp_peer_sync_enabled 0\n", StringComparison.Ordinal) &&
              disabledMetricText.ToString().Contains("yarp_peer_sync_remote_fresh 0\n", StringComparison.Ordinal) &&
              disabledMetricText.ToString().Contains("yarp_peer_sync_last_accepted_age_seconds NaN\n", StringComparison.Ordinal),
            "unconfigured peer metrics report disabled and unknown receipt age with NaN");
        Check(!ageLimited.Apply(frame,now),
            "expired frame cannot be replayed to revive stale counters");
        var recovered = a.Snapshot(now);
        Check(ageLimited.Apply(recovered,now) &&
              ageLimited.PeerTelemetry(now)==(1,2L) && ageLimited.RetainedRemoteEntries == 1,
            "new higher-sequence frame restores live remote telemetry");
        clock = clock.AddHours(-1);
        monotonicClock.SetUtcNow(clock);
        Check(ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "wall-clock rollback does not invalidate freshly received peer telemetry");
        monotonicClock.Advance(TimeSpan.FromSeconds(7));
        Check(!ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "monotonic TTL expires telemetry despite wall-clock rollback");
        Check(ageLimited.RetainedRemoteEntries == 0,
            "monotonic expiry collects remote state while preserving replay high-water marks");
        var invalidFreshness = false;
        try { _ = new PeerStateJournal("node-b","node-a",secret,2,
                          TimeSpan.FromSeconds(61)); }
        catch(ArgumentOutOfRangeException) { invalidFreshness = true; }
        Check(invalidFreshness, "unbounded remote freshness rejected");
        Check(!b.Apply(frame,now),"duplicate sequence rejected");
        var rollback=a.Snapshot(now);
        rollback.Counters.Clear();
        Check(!b.Apply(rollback,now),"state rollback rejected");

        // A delayed frame from the same process epoch is distinct from an
        // exact replay: it has a lower sequence but identical counters. It
        // must neither replace the newest sequence nor refresh the receipt TTL.
        var orderingSource = new PeerStateJournal("node-a", "node-b", secret, 2);
        orderingSource.Observe(IPAddress.Parse("10.123.4.8"), now);
        var delayedFrame = orderingSource.Snapshot(now);
        var currentFrame = orderingSource.Snapshot(now);
        var orderingClock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var orderingReceiver = new PeerStateJournal("node-b", "node-a", secret, 2,
            TimeSpan.FromSeconds(6), timeProvider: orderingClock);
        Check(orderingReceiver.Apply(currentFrame, now),
            "newest same-epoch sequence is accepted before delayed delivery");
        orderingClock.Advance(TimeSpan.FromSeconds(5));
        Check(!orderingReceiver.Apply(delayedFrame, now) &&
              orderingReceiver.Status(now).RemoteSequence == currentFrame.Sequence &&
              orderingReceiver.Status(now).RemoteRequests == 1,
            "delayed lower sequence with unchanged counters cannot replace the newest frame");
        orderingClock.Advance(TimeSpan.FromSeconds(2));
        Check(!orderingReceiver.Status(now).RemoteReportedInCurrentMinute,
            "rejected delayed frame does not refresh the peer receipt TTL");

        var minuteSource = new PeerStateJournal("node-a", "node-b", secret, 2);
        minuteSource.Observe(IPAddress.Parse("10.123.4.9"), now);
        var previousMinuteFrame = minuteSource.Snapshot(now);
        minuteSource.Observe(IPAddress.Parse("10.123.4.10"), now + 1);
        var nextMinuteFrame = minuteSource.Snapshot(now + 1);
        var minuteRollbackReceiver = new PeerStateJournal("node-b", "node-a", secret, 2,
            TimeSpan.FromSeconds(6), timeProvider: new ManualTimeProvider(DateTimeOffset.UtcNow));
        Check(minuteRollbackReceiver.Apply(previousMinuteFrame, now) &&
              minuteRollbackReceiver.Apply(nextMinuteFrame, now + 1),
            "peer accepts complete snapshots as its source advances to a new minute");
        Check(!minuteRollbackReceiver.Apply(previousMinuteFrame, now) &&
              minuteRollbackReceiver.Status(now + 1).RemoteReportedInCurrentMinute &&
              minuteRollbackReceiver.Status(now + 1).RemoteRequests == 1,
            "receiver clock rollback cannot replay an older source minute over newer peer telemetry");

        Check(!b.Apply(new PeerStateFrame("node-c",now,500,new()),now),"unknown peer rejected");
        Check(!b.Apply(new PeerStateFrame("node-a",now+2,999,new()),now),
            "future minute rejected");
        a.Observe(IPAddress.Parse("10.123.4.6"),now);
        a.Observe(IPAddress.Parse("10.123.4.7"),now);
        Check(a.Snapshot(now).Counters.Count==2,"peer identity cardinality hard cap");
        Check(b.Apply(a.Snapshot(now),now),"larger sequence merges without losing counters");
        Check(b.PeerTelemetry(now)==(2,3L),"monotonic remote counts");
        // Restarting the sender resets its process counters and per-minute
        // sequence, but a newer authenticated boot epoch must resynchronize.
        var beforeRestart = a.Snapshot(now);
        System.Threading.Thread.Sleep(20);
        var restarted = new PeerStateJournal("node-a", "node-b", secret, 2);
        restarted.Observe(IPAddress.Parse("10.123.4.5"), now);
        var afterRestart = restarted.Snapshot(now);
        Check(afterRestart.SourceEpoch > beforeRestart.SourceEpoch,
            "new sender process has a strictly newer boot epoch");
        Check(b.Apply(afterRestart,now),
            "legitimate sender restart replaces stale process counters");
        Check(b.PeerTelemetry(now)==(1,1L),
            "peer counts reset to newly synchronized process after restart");
        Check(!b.Apply(beforeRestart,now),
            "old boot epoch cannot replay an obsolete snapshot after recovery");

        Check(b.PeerTelemetry(now+1)==(0,0L),"stale peer telemetry expires from current minute");

        var localGc = new PeerStateJournal("node-a", "node-b", secret, 2);
        localGc.Observe(IPAddress.Parse("10.123.4.11"), now);
        Check(localGc.RetainedLocalEntries == 1, "local peer table retains current-minute entry");
        _ = localGc.Status(now + 1);
        Check(localGc.RetainedLocalEntries == 0,
            "local table is collected at the first observation boundary after its minute TTL");

        var localRollback = new PeerStateJournal("node-a", "node-b", secret, 2);
        localRollback.Observe(client, now);
        var previousLocal = localRollback.Snapshot(now);
        localRollback.Observe(client, now + 1);
        localRollback.Observe(client, now + 1);
        var currentLocal = localRollback.Snapshot(now + 1);
        localRollback.Observe(IPAddress.Parse("10.123.4.99"), now);
        Check(localRollback.Status(now).LocalIdentities == 0 &&
              localRollback.Status(now).LocalRequests == 0,
            "rollback status hides counters from the newer minute");
        Check(localRollback.RetainedLocalEntries == 1 &&
              localRollback.Status(now + 1).LocalRequests == 2,
            "late observation and status cannot clear or pollute the current local minute");
        var staleSnapshotRejected = false;
        try { _ = localRollback.Snapshot(now); }
        catch (InvalidOperationException) { staleSnapshotRejected = true; }
        Check(staleSnapshotRejected,
            "publisher cannot relabel newer counters as a regressed minute");
        var recoveredLocal = localRollback.Snapshot(now + 1);
        Check(recoveredLocal.Sequence == currentLocal.Sequence + 1 &&
              recoveredLocal.Counters.Single().Value == 2 &&
              recoveredLocal.Minute > previousLocal.Minute,
            "local sequence and counters survive clock catch-up without rollback");
        Check(localRollback.Snapshot(now + 2).Counters.Count == 0 &&
              localRollback.Status(now + 2).LocalRequests == 0,
            "normal forward minute transition still collects local telemetry");

        var remoteMinuteGcSource = new PeerStateJournal("node-a", "node-b", secret, 2);
        remoteMinuteGcSource.Observe(IPAddress.Parse("10.123.4.12"), now);
        var remoteMinuteGc = new PeerStateJournal("node-b", "node-a", secret, 2);
        Check(remoteMinuteGc.Apply(remoteMinuteGcSource.Snapshot(now), now) &&
              remoteMinuteGc.RetainedRemoteEntries == 1,
            "remote peer table retains accepted current-minute entry");
        _ = remoteMinuteGc.Status(now + 1);
        Check(remoteMinuteGc.RetainedRemoteEntries == 0,
            "remote table is collected after its declared minute TTL");

        var rollbackSource = new PeerStateJournal("node-a", "node-b", secret, 2);
        rollbackSource.Observe(IPAddress.Parse("10.123.4.13"), now);
        var rollbackFrame = rollbackSource.Snapshot(now);
        var rollbackTime = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var rollbackGcReceiver = new PeerStateJournal("node-b", "node-a", secret, 2,
            TimeSpan.FromSeconds(60), timeProvider: rollbackTime);
        Check(rollbackGcReceiver.Apply(rollbackFrame, now),
            "remote minute rollback fixture accepts an initial current-minute snapshot");
        Check(!rollbackGcReceiver.Status(now + 1).RemoteReportedInCurrentMinute &&
              rollbackGcReceiver.RetainedRemoteEntries == 0,
            "advancing the receiver minute collects remote state");
        Check(!rollbackGcReceiver.Status(now).RemoteReportedInCurrentMinute &&
              rollbackGcReceiver.RetainedRemoteEntries == 0,
            "rolling the receiver minute backward cannot make collected state fresh again");
        Check(!rollbackGcReceiver.Apply(rollbackFrame, now),
            "minute rollback does not reset replay high-water marks");
        Check(rollbackGcReceiver.Apply(rollbackSource.Snapshot(now), now) &&
              rollbackGcReceiver.Status(now).RemoteReportedInCurrentMinute,
            "only a new higher-sequence snapshot restores freshness after minute rollback");

        var maxFrame = new PeerStateJournal("node-a", "node-b", secret, 2048);
        for (var i = 0; i < 2048; i++)
            maxFrame.Observe(new IPAddress(new byte[] { 10, 20,
                (byte)(i / 256), (byte)(i % 256) }), now);
        var bytesAtCap = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
            maxFrame.Snapshot(now));
        Check(bytesAtCap.Length <= 262144,
            "maximum configured peer snapshot fits signed 256KiB transport");
        Check(maxFrame.Status(now).LocalIdentities == 2048,
            "bounded high-cardinality local operational snapshot");
        maxFrame.Observe(IPAddress.Parse("10.90.90.90"), now);
        Check(maxFrame.Status(now).LocalIdentities == 2048,
            "new peer admission capped without evicting tracked peers");
        var capRejected = false;
        try { _ = new PeerStateJournal("node-a", "node-b", secret, 2049); }
        catch (ArgumentException) { capRejected = true; }
        Check(capRejected, "oversized transport configuration rejected");
        Check(PeerSyncSettings.FromEnvironment(null,null,null,null,null,null) is null,
            "disabled peer sync remains disabled without required configuration");

        var auth=new PeerSignedMessages(secret);
        var bytes=Encoding.UTF8.GetBytes("{\"NodeId\":\"node-a\"}");
        const long t=1763200000;
        var (nonce,sig)=auth.Sign("node-a",t,bytes);
        Check(auth.Verify("node-a","node-a",t,nonce,sig,bytes,t),"valid signed frame accepted");
        Check(!auth.Verify("node-a","node-a",t,nonce,sig,bytes,t),"replayed nonce rejected");

        var clockFence = new PeerSignedMessages(secret);
        var (expiredNonce, expiredSig) = clockFence.Sign("node-a", t, bytes);
        Check(clockFence.Verify("node-a", "node-a", t, expiredNonce, expiredSig, bytes, t),
            "nonce clock-fence fixture accepts initial authenticated frame");
        var (newNonce, newSig) = clockFence.Sign("node-a", t + 61, bytes);
        Check(clockFence.Verify("node-a", "node-a", t + 61, newNonce, newSig, bytes, t + 61),
            "authenticated forward clock observation collects expired nonce window");
        Check(!clockFence.Verify("node-a", "node-a", t, expiredNonce, expiredSig, bytes, t),
            "clock rollback cannot replay a nonce after collection");
        var (freshNonce, freshSig) = clockFence.Sign("node-a", t, bytes);
        Check(!clockFence.Verify("node-a", "node-a", t, freshNonce, freshSig, bytes, t),
            "clock rollback cannot reopen a previously closed timestamp window");
        var (recoveryNonce, recoverySig) = clockFence.Sign("node-a", t + 62, bytes);
        Check(clockFence.Verify("node-a", "node-a", t + 62, recoveryNonce, recoverySig, bytes, t + 62),
            "fresh authenticated peer frames recover when wall clock catches up");
        var unauthenticatedFence = new PeerSignedMessages(secret);
        Check(!unauthenticatedFence.Verify("node-a", "node-a", t + 1000, newNonce, newSig, bytes, t + 1000) &&
              unauthenticatedFence.Verify("node-a", "node-a", t, expiredNonce, expiredSig, bytes, t),
            "forged future frame cannot advance the authenticated time fence");
        var (nonce2,sig2)=auth.Sign("node-a",t,bytes);
        Check(!auth.Verify("node-a","node-b",t,nonce2,sig2,bytes,t),
            "wrong peer identity rejected");
        Check(!auth.Verify("node-a","node-a",t,nonce2,sig2,bytes,t+90),
            "stale signed frame rejected");
        Check(!auth.Verify("node-a","node-a",long.MinValue,nonce2,sig2,bytes,t),
            "extreme negative timestamp rejected without exception");
        Check(!auth.Verify("node-a","node-a",long.MaxValue,nonce2,sig2,bytes,t),
            "extreme positive timestamp rejected without exception");
        Check(!auth.Verify("node-a","node-a",t,nonce2,sig2,Encoding.UTF8.GetBytes("tampered"),t),
            "altered payload rejected");
        Check(PeerSyncSettings.FromEnvironment(null,null,null,null,null,null) is null,
            "peer synchronization disabled by default");
        foreach(var url in new[]{"http://localhost/gateway/internal/peer-sync",
            "https://node/gateway/internal/peer-sync?extra=true",
            "https://name:secret@node/gateway/internal/peer-sync"})
        {
            var failed=false;
            try { PeerSyncSettings.FromEnvironment("node-a","node-b",url,
                     new string('z',32),null,null); }
            catch(InvalidOperationException) { failed=true; }
            Check(failed,"insecure or noncanonical peer URL rejected");
        }
    }
}
