// Exact production provider action, shared with the disposable integration fixture.
internal static class VipProviderActions
{
    internal static async Task<VipFenceProvider.NodeEvidence> Run(string action,VipFenceProvider.NodeRequest r,
        Func<Task> AssertOwner,Func<CancellationToken,Task<bool>> ownerOff,Func<CancellationToken,Task<bool>> peerOff,
        Func<string,bool,CancellationToken,Task<VipRemoteNode.Evidence>> nodeStatus,
        Func<bool,CancellationToken,Task<VipRemoteNode.DrainEvidence>> drain,CancellationToken token)
    {
        if(action is not ("node-status" or "drain-node" or "activate-node"))throw new InvalidDataException("Unknown action.");
        await AssertOwner();
        bool serving=false,eligible=false,drained=false;
        if(action=="activate-node")
        {
            // Before starting the successor, independently re-observe
            // physical isolation of the predecessor.
            if(!await peerOff(token))throw new InvalidDataException("Node action conditions not confirmed.");
            await AssertOwner();
            serving=(await nodeStatus(r.OwnerPin,true,token)).Serving;
            if(!serving||!await peerOff(token))throw new InvalidDataException("Node action conditions not confirmed.");
        }
        else
        {
            if(!await peerOff(token))
                eligible=(await nodeStatus(r.OtherPin,false,token)).Eligible;
            if(!await ownerOff(token))
            {
                var health=await nodeStatus(r.OwnerPin,false,token);
                serving=health.Serving;
                var before=await drain(false,token);
                drained=before.ManualDrain||before.Draining;
                if(action=="drain-node")
                {
                    if(!eligible||before.ManualDrain)throw new InvalidDataException("Node action conditions not confirmed.");
                    await AssertOwner();
                    var observed=await drain(true,token);
                    while(observed.Active!=0)
                    {
                        await Task.Delay(250,token);await AssertOwner();
                        observed=await drain(false,token);
                    }
                    if(!observed.Draining||observed.ManualDrain)throw new InvalidDataException("Node action conditions not confirmed.");
                    drained=true;serving=false;
                }
            }
            else if(action=="drain-node")throw new InvalidDataException("Node action conditions not confirmed.");
        }
        await AssertOwner();
        return new VipFenceProvider.NodeEvidence(r.Scope,r.OwnerPin,r.Epoch,r.OtherPin,r.Nonce,
            serving,eligible,drained,true);
    }
}
