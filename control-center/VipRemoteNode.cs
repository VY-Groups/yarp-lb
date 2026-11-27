using System.Text.Json.Serialization;

// Fixed node-agent protocol. The request never specifies an executable,
// target address, service name or configuration file.
internal static class VipRemoteNode
{
    internal sealed record Request(string Scope,string OwnerPin,long Epoch,string OtherPin,string Nonce);
    internal sealed record Evidence(string Scope,string OwnerPin,long Epoch,string OtherPin,string Nonce,string NodePin,
        [property:JsonRequired] bool Serving,[property:JsonRequired] bool Eligible);
    internal sealed record DrainRequest(string Scope,long Epoch,string Nonce,bool Drain);
    internal sealed record DrainEvidence(string Scope,long Epoch,string Nonce,
        [property:JsonRequired] bool Draining,[property:JsonRequired] bool ManualDrain,[property:JsonRequired] int Active);
    internal static void Validate(Request r,string scope,string localPin)
    {
        VipFenceProvider.ValidatePair(r.Scope,r.OwnerPin,r.OtherPin);
        if(r.Scope!=scope||r.Epoch<1||!VipFenceProvider.Pin(r.Nonce)||
            (localPin!=r.OwnerPin&&localPin!=r.OtherPin))
            throw new InvalidDataException("Unrelated node request.");
    }
    internal static Evidence Match(Request r,string pin,Evidence e)
    {
        Validate(r,r.Scope,pin);
        if(e.Scope!=r.Scope||e.OwnerPin!=r.OwnerPin||e.OtherPin!=r.OtherPin||e.Epoch!=r.Epoch||
            e.Nonce!=r.Nonce||e.NodePin!=pin||(pin==r.OwnerPin&&e.Eligible)||(pin==r.OtherPin&&e.Serving))
            throw new InvalidDataException("Unrelated or contradictory node evidence.");
        return e;
    }
    internal static DrainEvidence Match(DrainRequest r,DrainEvidence e)
    {
        if(e.Scope!=r.Scope||e.Epoch!=r.Epoch||e.Nonce!=r.Nonce||e.Active<0||(r.Drain&&!e.Draining))
            throw new InvalidDataException("Unrelated or incomplete drain evidence.");
        return e;
    }
}
