// Actual separate processes against disposable real three-member Raft.
if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")=="true" && args.Length>0 && args[0]=="--vip-owner")
    return await VipOwnershipCommand.Run(args);
if(Environment.GetEnvironmentVariable("GITHUB_ACTIONS")!="true" || args.Length!=4 ||
   !long.TryParse(args[3],out var epoch))return 2;
try
{
    if(args[0]=="vip-check")
    {
        using var vip=FleetQuorum.OpenVip(args[1],args[2]);
        return await vip.IsVipOwner(epoch,CancellationToken.None)?0:1;
    }
    using var quorum=FleetQuorum.Open(args[1],args[0]!="assert")??throw new InvalidOperationException();
    if(args[0]=="acquire")Console.WriteLine((await quorum.Acquire(args[2],epoch)).Epoch);
    else if(args[0]=="assert")await quorum.Assert(args[2],epoch);
    else if(args[0]=="release")await quorum.Release(args[2],epoch,"rolled-back");
    else if(args[0]=="wrong-outcome")await quorum.Release(args[2],epoch,"activated");
    else return 2;
    return 0;
}
catch(Exception e){Console.Error.WriteLine("Quorum rejected: "+e.GetType().Name);return 1;}
