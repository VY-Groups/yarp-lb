internal static class VipFenceContractTests
{
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
        Console.WriteLine("PASS: fence provider exact response, failure remains revoked, exact resume");
    }
}
