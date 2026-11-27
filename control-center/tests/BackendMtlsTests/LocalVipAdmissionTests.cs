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
        using var quorumGate=new LocalVipAdmission([("guarded","192.0.2.10")],clock,
            new(){{"guarded",_=>Task.FromResult(true)}});
        var confirmed=new Dictionary<string,bool>{{"guarded",true}};
        quorumGate.Refresh(clock.Now,snapshot,confirmed);
        Must(!quorumGate.Allows("guarded"),"quorum cannot authorize an incorrect host prefix");
        row=row with{Addresses=[new("192.0.2.10",32)]};
        snapshot=snapshot with{Interfaces=[row]};
        quorumGate.Refresh(clock.Now,snapshot with{Interfaces=[row with{DefaultGateways=["192.0.2.1"]}]},confirmed);
        Must(!quorumGate.Allows("guarded"),"quorum cannot authorize a default-route interface");
        quorumGate.Refresh(clock.Now,snapshot with{Interfaces=[row with{Type="Loopback"}]},confirmed);
        Must(!quorumGate.Allows("guarded"),"quorum cannot authorize a loopback interface");
        quorumGate.Refresh(clock.Now,snapshot with{Interfaces=[row with{Addresses=[new("192.0.2.10",32),new("192.0.2.10",32)]}]},confirmed);
        Must(!quorumGate.Allows("guarded"),"quorum cannot authorize duplicate address records");
        quorumGate.Refresh(clock.Now,snapshot);
        Must(!quorumGate.Allows("guarded"),"local address alone cannot authorize distributed VIP");
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",true}});
        Must(quorumGate.Allows("guarded"),"local and exact quorum observation required");
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",false}});
        Must(!quorumGate.Allows("guarded"),"lost ownership closes guarded socket");
        clock.Now=4000;
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",true}});
        int aborted=0;
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out var completed),"fresh request tracked");
        completed!.Dispose();
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out var active),"second request tracked");
        Must(quorumGate.Active("guarded")==1,"in-flight count excludes completed request");
        clock.Now=7000;
        quorumGate.Sweep();
        quorumGate.Sweep();
        Must(aborted==1&&!quorumGate.TryEnter("guarded",()=>{},out _),"stale watchdog aborts once and rejects new traffic");
        active!.Dispose();
        Must(quorumGate.Active("guarded")==0,"aborted pipeline completion releases slot");
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",true}});
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out active),"recovered admission");
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",false}});
        Must(aborted==2,"ownership denial aborts immediately");
        active!.Dispose();
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",true}});
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out active),"fresh request after denial");
        clock.Now=10000;
        quorumGate.Refresh(clock.Now,snapshot,new Dictionary<string,bool>{{"guarded",true}});
        Must(aborted==3,"fresh sample cannot hide expired earlier authorization");
        active!.Dispose();
        var leases=new List<IDisposable>();
        try
        {
            for(int i=0;i<4096;i++)
            {
                MustQuiet(quorumGate.TryEnter("guarded",()=>{},out var item));
                leases.Add(item!);
            }
            Must(!quorumGate.TryEnter("guarded",()=>{},out _),"bounded per-socket tracking");
        }
        finally {foreach(var item in leases)item.Dispose();}
        Must(quorumGate.Active("guarded")==0,"all tracked slots released");
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out var draining),"healthy in-flight request before planned drain");
        quorumGate.SetPlannedDrains(["guarded"]);
        quorumGate.Sweep();
        Must(aborted==3&&quorumGate.IsDraining("guarded")&&!quorumGate.TryEnter("guarded",()=>{},out _),
            "planned drain refuses new requests without aborting existing healthy traffic");
        draining!.Dispose();
        Must(quorumGate.Active("guarded")==0,"planned drain reaches zero active requests");
        quorumGate.SetPlannedDrains([]);
        Must(quorumGate.TryEnter("guarded",()=>aborted++,out draining),"explicit resume admits fresh traffic");
        draining!.Dispose();
        quorumGate.SetPlannedDrains(["guarded"]);
        var persisted=VipDrainState.Parse(VipDrainState.Encode(["192.0.2.10"]),["192.0.2.10"]);
        using var restarted=new LocalVipAdmission([("guarded","192.0.2.10")],clock);
        restarted.SetPlannedDrains(persisted.Select(_=>"guarded"));
        restarted.Refresh(clock.Now,snapshot);
        Must(!restarted.TryEnter("guarded",()=>{},out _),"durable drain survives guard reconstruction");
        foreach(var bad in new[]{"null","[\"192.0.2.11\"]","[\"192.0.2.10\",\"192.0.2.10\"]"})
        {
            try{_=VipDrainState.Parse(System.Text.Encoding.UTF8.GetBytes(bad),["192.0.2.10"]);throw new Exception("invalid drain state accepted");}
            catch(InvalidDataException){}
        }
        int sharedCalls=0,separateCalls=0;
        Func<CancellationToken,Task<bool>> shared=_=>{sharedCalls++;return Task.FromResult(true);};
        Func<CancellationToken,Task<bool>> separate=_=>{separateCalls++;return Task.FromResult(false);};
        using var grouped=new LocalVipAdmission([("a","192.0.2.10"),("b","192.0.2.10"),("c","192.0.2.11"),("d","192.0.2.10")],clock,
            new(){{"a",shared},{"b",shared},{"c",shared},{"d",separate}});
        var results=grouped.PollAuthorities(default).GetAwaiter().GetResult();
        Must(sharedCalls==2&&separateCalls==1&&results["a"]&&results["b"]&&results["c"]&&!results["d"],
            "one authority poll per exact address and probe, no cross-address or cross-probe reuse");
        using(var canceled=new CancellationTokenSource())
        {
            canceled.Cancel();
            results=grouped.PollAuthorities(canceled.Token).GetAwaiter().GetResult();
            Must(results.Values.All(x=>!x),"canceled sample never authorizes traffic");
        }
        static void MustQuiet(bool ok){if(!ok)throw new Exception("VIP request tracking refused early");}
    }
}
