using System.Security.Cryptography;

namespace GatewayCore.Licensing;

public static class FleetLicensePolicy
{
    // Controller may share the exact installation with one managed agent.
    // Count it once, but reject repeated identities among remote endpoints.
    public static void Validate(VerifiedLicense local,IReadOnlyList<VerifiedLicense> remotes,DateTimeOffset now)
    {
        if(remotes.Count is < 1 or > 20)throw new InvalidDataException("Invalid managed fleet size.");
        static bool Active(VerifiedLicense v,DateTimeOffset utc)=>
            v.SiteId is not null && v.Allows("ha") && v.Allows("fleet") && v.NotBefore<=utc && utc<v.ExpiresAt;
        if(!Active(local,now) || !local.Allows("l7"))throw new CryptographicException("Local site-bound fleet entitlement required.");
        var remoteAllocations=new HashSet<string>(StringComparer.Ordinal);
        var remoteKeys=new HashSet<string>(StringComparer.Ordinal);
        var allAllocations=new HashSet<string>(StringComparer.Ordinal){local.AllocationId};
        var allKeys=new HashSet<string>(StringComparer.Ordinal){local.InstallationKeySha256};
        var sites=new HashSet<string>(StringComparer.Ordinal){local.SiteId!};
        foreach(var peer in remotes)
        {
            if(!Active(peer,now) || peer.LicenseId!=local.LicenseId || peer.CustomerId!=local.CustomerId ||
                peer.DeploymentId!=local.DeploymentId || peer.Edition!=local.Edition ||
                peer.MaxNodes!=local.MaxNodes || peer.MaxSites!=local.MaxSites || peer.ExpiresAt!=local.ExpiresAt ||
                !peer.Features.SetEquals(local.Features) ||
                !remoteAllocations.Add(peer.AllocationId) || !remoteKeys.Add(peer.InstallationKeySha256))
                throw new CryptographicException("Foreign, inconsistent or duplicate fleet entitlement.");
            var newAllocation=allAllocations.Add(peer.AllocationId);
            var newKey=allKeys.Add(peer.InstallationKeySha256);
            if(newAllocation!=newKey || (!newAllocation && peer.PayloadSha256!=local.PayloadSha256))
                throw new CryptographicException("Allocation and installation binding conflict.");
            sites.Add(peer.SiteId!);
        }
        if(allAllocations.Count>local.MaxNodes || sites.Count>local.MaxSites ||
            (sites.Count>1 && !local.Allows("dc-dr")))
            throw new CryptographicException("Signed node/site limit or DC-DR entitlement exceeded.");
    }
}
