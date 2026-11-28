internal static class LocalVipAdmissionTests
{
    private sealed class Clock : TimeProvider
    {
        internal long Now;
        public override long TimestampFrequency => 1000;
        public override long GetTimestamp() => Now;
    }
    internal static void Run()
    {
        static void Must(bool ok, string label)
        {
            if (!ok) throw new Exception("Local VIP admission: " + label);
            Console.WriteLine("PASS: " + label);
        }
        var clock = new Clock();
        using var gate = new LocalVipAdmission([("guarded","192.0.2.10")],clock);
        var row = new LocalNetworkInventory.InterfaceRow("fixture","eth0","Ethernet","Up",
            [new("192.0.2.10",24)],[],false);
        var snapshot = new LocalNetworkInventory.Snapshot("fixture","Linux",DateTimeOffset.UnixEpoch,[row],false);
        Must(!gate.Allows("guarded") && gate.Allows("legacy") && gate.Allows(null),"initially closed only for guarded sockets");
        gate.Refresh(clock.Now,snapshot);
        Must(gate.Allows("guarded"),"fresh unique local address opens admission");
        clock.Now=2999;
        Must(gate.Allows("guarded"),"freshness before deadline");
        clock.Now=3000;
        Must(!gate.Allows("guarded"),"stale observation closes admission");
        gate.Refresh(clock.Now,snapshot with { Truncated=true });
        Must(!gate.Allows("guarded"),"truncated observation cannot authorize");
        gate.Refresh(clock.Now,snapshot with { Interfaces=[] });
        Must(!gate.Allows("guarded"),"withdrawn address closes admission");
        gate.Refresh(clock.Now,snapshot with { Interfaces=[row,row with { Name="eth1" }] });
        Must(!gate.Allows("guarded"),"duplicate local assignment closes admission");
        gate.Refresh(clock.Now,snapshot with { Interfaces=[row with { Status="Down" }] });
        Must(!gate.Allows("guarded"),"down interface closes admission");
        gate.Refresh(clock.Now,snapshot);
        Must(gate.Allows("guarded"),"fresh recovery opens admission");
        clock.Now=2999;
        Must(!gate.Allows("guarded"),"backward timestamp refuses observation");
        gate.Invalidate();
        Must(!gate.Allows("guarded"),"failed observation closes admission");
    }
}
