internal static class VipFenceContractTests
{
    private sealed class TestClock:TimeProvider
    {
        internal long Now;
        public override long TimestampFrequency=>1000;
        public override long GetTimestamp()=>Now;
    }
    internal static async Task Run()
    {
        string scope=new('A',64),oldPin=new('B',64),newPin=new('C',64);
        var current=new FleetQuorum.Fence("vip_"+oldPin,10);
        int activations=0,revocations=0;
        Task<FleetQuorum.Fence?> Observe(CancellationToken t)=>Task.FromResult<FleetQuorum.Fence?>(current);
        Task<FleetQuorum.Fence> Revoke(string pin,long epoch,CancellationToken t)
        {revocations++;current=new("vip_revoked_"+pin,11);return Task.FromResult(current);}
        Task<FleetQuorum.Fence> Activate(string pin,long epoch,string next,long expires,byte[] sig,CancellationToken t)
        {activations++;current=new("vip_"+next,12);return Task.FromResult(current);}
        Task<(long,byte[])> Fail(VipFenceProvider.Request req,CancellationToken t)=>throw new HttpRequestException("unavailable");
        Task<(long,byte[])> Fence(VipFenceProvider.Request req,CancellationToken t)
        {
            if(req.RevokedEpoch!=11||current.Transaction!="vip_revoked_"+oldPin)throw new Exception("Provider before durable revocation");
            return Task.FromResult((1000L,new byte[70]));
        }
        try{await VipFencedTransfer.Run(scope,oldPin,10,newPin,false,Observe,Revoke,Fail,Activate,default);throw new Exception("expected failure");}
        catch(HttpRequestException){}
        if(activations!=0||revocations!=1||current.Transaction!="vip_revoked_"+oldPin)throw new Exception("Unsafe provider failure");
        await VipFencedTransfer.Run(scope,oldPin,11,newPin,true,Observe,Revoke,Fence,Activate,default);
        if(activations!=1||revocations!=1||current.Transaction!="vip_"+newPin)throw new Exception("Exact resume failed");
        var request=new VipFenceProvider.Request(scope,oldPin,11,newPin);
        var permit=new VipFenceProvider.Permit(scope,oldPin,11,newPin,1050,Convert.ToBase64String(new byte[70]));
        _=VipFenceProvider.Validate(request,permit,1000);
        foreach(var invalid in new[]{permit with{RevokedEpoch=12},permit with{Expires=999},permit with{NewPin=oldPin},permit with{Expires=1301}})
        {
            try{_=VipFenceProvider.Validate(request,invalid,1000);throw new Exception("Expected permit rejection");}
            catch(InvalidDataException){}
        }
        await VipRedfishFenceTests.Run();
        await VipRemoteIntegrationTests.Run();
        var strict=VipPolicyDocument.Default(scope,oldPin,newPin,true) with{PollSeconds=10,FailureSeconds=20};
        strict.Validate(scope);
        foreach(var invalid in new[]{strict with{FailureSamples=2},strict with{PollSeconds=1},strict with{FailureSeconds=10},
            strict with{MinimumOwnerSeconds=60},strict with{OtherPin=oldPin}})
        {try{invalid.Validate(scope);throw new Exception("Unsafe HA policy accepted.");}catch(InvalidDataException){}}
        var clock=new TestClock();
        var policy=new VipAutomaticPolicy(clock);
        var nodeRequest=new VipFenceProvider.NodeRequest(scope,oldPin,10,newPin,"nonce");
        var node=new VipFenceProvider.NodeEvidence(scope,oldPin,10,newPin,"nonce",false,true,false,true);
        _=VipFenceProvider.ValidateNode(nodeRequest,node);
        try{_=VipFenceProvider.ValidateNode(nodeRequest,node with{Nonce="old"});throw new Exception("replayed node response accepted");}
        catch(InvalidDataException){}
        var active=new FleetQuorum.Fence("vip_"+oldPin,10);
        if(policy.Observe(active,node,newPin,true)!=null)throw new Exception("premature failover");
        clock.Now=5000;
        if(policy.Observe(active,node,newPin,true)!=null)throw new Exception("premature failover");
        clock.Now=10000;
        if(policy.Observe(active,node,newPin,true)!="failover")throw new Exception("qualified failover missing");
        policy.Reset();
        var healthy=node with{OwnerServing=true};
        if(policy.Observe(active,healthy,newPin,true)!=null)throw new Exception("premature failback");
        clock.Now=130000;
        if(policy.Observe(active,healthy,newPin,true)!=null)throw new Exception("premature failback");
        clock.Now=310000;
        if(policy.Observe(active,healthy,newPin,true)!="failback")throw new Exception("stable failback missing");
        if(policy.Observe(active,healthy with{OtherEligible=false},newPin,true)!=null)throw new Exception("ineligible peer admitted");
        policy.Reset();
        var plannedDrain=node with{OwnerDrained=true};
        for(int i=0;i<4;i++)
        {
            clock.Now+=5000;
            if(policy.Observe(active,plannedDrain,newPin,true)!=null)
                throw new Exception("planned maintenance triggered unsolicited failover");
        }
        var dir=Directory.CreateTempSubdirectory("vip-auto-test-");
        try
        {
            if(OperatingSystem.IsLinux())File.SetUnixFileMode(dir.FullName,UnixFileMode.UserRead|UnixFileMode.UserWrite|UnixFileMode.UserExecute);
            var path=Path.Combine(dir.FullName,"journal");
            var intent=new VipAutomaticJournal.Transition(scope,oldPin,10,newPin,"failover");
            using(var journal=new VipAutomaticJournal(path,scope,oldPin,newPin))journal.Begin(intent);
            using(var journal=new VipAutomaticJournal(path,scope,oldPin,newPin))
            {
                if(journal.Pending!=intent)throw new Exception("pending transfer lost after restart");
                journal.Complete(12);
            }
            using(var journal=new VipAutomaticJournal(path,scope,oldPin,newPin))
                if(journal.Pending!=null||journal.LastCompletedEpoch!=12)throw new Exception("completion lost");
        }
        finally{dir.Delete(true);}
        Console.WriteLine("PASS: fence provider exact response, failure remains revoked, exact resume, failover/failback policy and durable transition journal");
    }
}
