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
        var a=new PeerStateJournal("node-a","node-b",secret,2);
        var b=new PeerStateJournal("node-b","node-a",secret,2);
        var now=PeerStateJournal.CurrentMinute();
        var client=IPAddress.Parse("10.123.4.5");
        a.Observe(client,now);
        a.Observe(IPAddress.Parse("::ffff:10.123.4.5"),now);
        var frame=a.Snapshot(now);
        var serializedFrame = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(frame);
        Check(System.Text.Json.JsonDocument.Parse(serializedFrame).RootElement
                  .GetProperty("ProtocolVersion").GetInt32() == PeerStateFrame.CurrentProtocolVersion,
            "peer snapshots carry an explicit protocol version");
        var missingVersionRejected = false;
        try
        {
            _ = System.Text.Json.JsonSerializer.Deserialize<PeerStateFrame>(
                "{\"NodeId\":\"node-a\",\"Minute\":1,\"Sequence\":1,\"Counters\":{},\"SourceEpoch\":1}");
        }
        catch (System.Text.Json.JsonException) { missingVersionRejected = true; }
        Check(missingVersionRejected, "unversioned legacy peer frames are rejected");
        Check(!b.Apply(frame with { ProtocolVersion = PeerStateFrame.CurrentProtocolVersion + 1 }, now),
            "unknown peer protocol versions are rejected without changing state");
        Check(b.PeerTelemetry(now) == (0, 0L),
            "unknown peer protocol version leaves receiver telemetry unchanged");
        Check(frame.Counters.Count==1 && frame.Counters.Values.Single()==2,
            "IPv4 and mapped IPv6 share one hashed identity");
        Check(!frame.Counters.Keys.Single().Contains("10.123"),"no plaintext peer IP transmitted");
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
        monotonicClock.Advance(TimeSpan.FromSeconds(7));
        clock = monotonicClock.GetUtcNow();
        Check(!ageLimited.Status(now).RemoteReportedInCurrentMinute &&
              ageLimited.Status(now).RemoteIdentities == 0 &&
              ageLimited.PeerTelemetry(now)==(0,0L),
            "monotonic TTL expires remote frame within the same minute");
        Check(!ageLimited.Apply(frame,now),
            "expired frame cannot be replayed to revive stale counters");
        var recovered = a.Snapshot(now);
        Check(ageLimited.Apply(recovered,now) &&
              ageLimited.PeerTelemetry(now)==(1,2L),
            "new higher-sequence frame restores live remote telemetry");
        clock = clock.AddHours(-1);
        monotonicClock.SetUtcNow(clock);
        Check(ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "wall-clock rollback does not invalidate freshly received peer telemetry");
        monotonicClock.Advance(TimeSpan.FromSeconds(7));
        Check(!ageLimited.Status(now).RemoteReportedInCurrentMinute,
            "monotonic TTL expires telemetry despite wall-clock rollback");
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
