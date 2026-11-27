using System.Net;
using System.Security.Cryptography;
using System.Text;

// Startup pins the journal epoch for the lifetime of this gateway process.
// A new owner revision always requires a new process and a reconciled address.
internal sealed class VipJournalBinding
{
    private readonly string path,scope,interfaceId;
    private readonly IPAddress address,management;
    internal long Epoch {get;}
    internal VipJournalBinding(GatewayListenerIsolation.VirtualSocket service,IPAddress management)
    {
        address=VipHostAddressPlatform.Parse(service.Ip);this.management=management;
        scope=FleetQuorum.VipScope(service.VipFleetId!,service.Ip);
        interfaceId=service.VipInterfaceId!;
        path=Path.Combine(service.VipJournalDirectory!,Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(address.ToString())))+".journal");
        using var journal=new VipAddressJournal(path,scope,interfaceId,address.ToString(),readOnly:true);
        if(journal.Last?.Phase!="assigned"||!VipHostAddressPlatform.Inspect(interfaceId,address,management).Ready)
            throw new InvalidDataException("Reconcile the journal-bound VIP before starting the gateway.");
        Epoch=journal.Last.Epoch;
    }
    internal bool Current()
    {
        try
        {
            using var journal=new VipAddressJournal(path,scope,interfaceId,address.ToString(),readOnly:true);
            return journal.Last is {Phase:"assigned"} entry && entry.Epoch==Epoch &&
                VipHostAddressPlatform.Inspect(interfaceId,address,management).Ready;
        }
        catch(Exception error) when(error is IOException or InvalidDataException or UnauthorizedAccessException or
            InvalidOperationException or System.Net.NetworkInformation.NetworkInformationException or System.Text.Json.JsonException)
        {return false;}
    }
}
