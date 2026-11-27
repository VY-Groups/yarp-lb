// No takeover authority on the gateway. Reconcile only the independently
// authorized local address; a journal uncertainty never becomes ownership.
internal static class VipLocalReconcile
{
    internal static async Task Run(VipAddressJournal log,long epoch,bool own,
        Func<VipHostAddressPlatform.Observation> inspect,
        Func<VipHostAddressPlatform.Observation,bool,CancellationToken,Task> change,
        Func<long,CancellationToken,Task<bool>> isOwner,CancellationToken token)
    {
        if(epoch<1||epoch<(log.Last?.Epoch??0))throw new InvalidDataException("Stale VIP ownership revision.");
        if(log.Last?.Phase is "assign-intent" or "reassign-intent")
            throw new InvalidDataException("Uncertain assignment; independent recovery required.");
        var observed=inspect();
        if(observed.Present&&log.Last?.Phase is not ("assigned" or "withdraw-intent"))
            throw new InvalidDataException("Unmanaged local address cannot be adopted.");
        async Task Withdraw()
        {
            if(log.Last?.Phase=="assigned")log.Append(log.Last.Epoch,"withdraw-intent");
            if(log.Last?.Phase!="withdraw-intent")throw new InvalidDataException("Withdrawal lacks journal authority.");
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var state=inspect();
            if(state.Present)await change(state,false,timeout.Token);
            if(inspect().Present)throw new InvalidOperationException("VIP withdrawal unconfirmed.");
            log.Append(log.Last.Epoch,"withdrawn");
        }
        if(log.Last?.Phase=="withdraw-intent"||
            (log.Last?.Phase=="assigned"&&(!own||log.Last.Epoch!=epoch)))
            await Withdraw();
        if(!own)return;
        if(!await isOwner(epoch,token))throw new InvalidOperationException("Fresh exact VIP ownership not confirmed.");
        observed=inspect();
        if(log.Last?.Phase=="assigned"&&log.Last.Epoch==epoch&&observed.Ready)return;
        if(observed.Present)throw new InvalidDataException("Non-ready existing address cannot be adopted.");
        bool reassign=log.Last?.Phase=="assigned"&&log.Last.Epoch==epoch;
        log.Append(epoch,reassign?"reassign-intent":"assign-intent");
        await change(observed,true,token);
        if(!inspect().Ready)throw new InvalidOperationException("VIP readiness unconfirmed.");
        log.Append(epoch,"assigned");
        bool confirmed=false;
        try{confirmed=await isOwner(epoch,token);}
        finally{if(!confirmed)await Withdraw();}
        if(!confirmed)throw new InvalidOperationException("Ownership lost during reconciliation; local address withdrawn.");
    }
}
