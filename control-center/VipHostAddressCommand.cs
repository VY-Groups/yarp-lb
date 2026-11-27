using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

internal static class VipHostAddressCommand
{
    internal static async Task<int> Run(string[] args)
    {
        try
        {
            if(args.Length!=5||args[4] is not ("status" or "assign" or "withdraw" or "reconcile"))
                throw new ArgumentException("Usage: --vip-address <private-journal-directory> <virtual-service-id> <interface-id> status|assign|withdraw|reconcile");
            var dir=Path.GetFullPath(args[1]);
            if(!Path.IsPathFullyQualified(args[1])||!Directory.Exists(dir))throw new InvalidDataException("Existing private absolute journal directory required.");
            if(OperatingSystem.IsWindows())WindowsStateProtection.ValidateOfflineKeyRingDirectory(dir);
            else if(OperatingSystem.IsLinux())PrivateKeyFileSecurity.ValidateLinuxPrivateStateDirectory(dir,"VIP journal");
            else throw new PlatformNotSupportedException();
            using var listeners=GatewayListenerIsolation.FromEnvironment()??throw new InvalidDataException("Reviewed isolated listeners required.");
            var service=listeners.VirtualServices.SingleOrDefault(s=>s.Id==args[2])??throw new InvalidDataException("Unknown virtual service.");
            bool journalBound=service.VipJournalDirectory is not null;
            if(!service.RequireLocalAddressPresence||service.VipQuorumConfigPath is null||
                (!journalBound&&service.VipOwnershipEpoch is not >0))
                throw new InvalidDataException("Exact distributed VIP configuration required.");
            if(journalBound && (!string.Equals(dir,Path.GetFullPath(service.VipJournalDirectory!),OperatingSystem.IsWindows()?StringComparison.OrdinalIgnoreCase:StringComparison.Ordinal)||
                service.VipInterfaceId!=args[3]||args[4]=="assign"))
                throw new InvalidDataException("Journal-bound VIP requires the configured directory/interface and reconcile instead of assign.");
            if(!journalBound&&args[4]=="reconcile")throw new InvalidDataException("Reconcile requires journal-bound mode.");
            var ip=VipHostAddressPlatform.Parse(service.Ip);
            var management=IPAddress.Parse(listeners.Config.ManagementIp);
            if(ip.Equals(management)||ip.Equals(IPAddress.Parse(listeners.Config.TrafficIp)))
                throw new InvalidDataException("Primary listener address cannot be mutated.");
            var scope=FleetQuorum.VipScope(service.VipFleetId!,service.Ip);
            var file=Path.Combine(dir,Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(ip.ToString())))+".journal");
            using var log=new VipAddressJournal(file,scope,args[3],ip.ToString());
            var observed=VipHostAddressPlatform.Inspect(args[3],ip,management);
            long epoch=service.VipOwnershipEpoch??log.Last?.Epoch??0;
            using var deadline=new CancellationTokenSource(TimeSpan.FromSeconds(30));
            async Task Withdraw()
            {
                // Compensation has an independent deadline even if the quorum check timed out.
                using var withdrawalDeadline=new CancellationTokenSource(TimeSpan.FromSeconds(20));
                if(log.Last?.Phase=="assigned")log.Append(log.Last.Epoch,"withdraw-intent");
                if(log.Last?.Phase!="withdraw-intent")throw new InvalidDataException("Only a journal-confirmed owned address can be withdrawn.");
                var current=VipHostAddressPlatform.Inspect(args[3],ip,management);
                if(current.Present)await VipHostAddressPlatform.Change(current,ip,false,withdrawalDeadline.Token);
                if(VipHostAddressPlatform.Inspect(args[3],ip,management).Present)throw new InvalidOperationException("Withdrawal unconfirmed.");
                log.Append(log.Last.Epoch,"withdrawn");
            }
            if(args[4]=="reconcile")
            {
                using var authority=FleetQuorum.OpenVip(service.VipQuorumConfigPath,scope);
                var current=await authority.ObserveVipReader(deadline.Token);
                epoch=current.Epoch;
                await VipLocalReconcile.Run(log,current.Epoch,current.Own,
                    ()=>VipHostAddressPlatform.Inspect(args[3],ip,management),
                    (observation,add,token)=>VipHostAddressPlatform.Change(observation,ip,add,token),
                    authority.IsVipOwner,deadline.Token);
            }
            else if(args[4]=="assign")
            {
                if(log.Last?.Phase is not (null or "withdrawn") || observed.Present)
                    throw new InvalidDataException("Preexisting or unconfirmed assignment cannot be adopted.");
                using var authority=FleetQuorum.OpenVip(service.VipQuorumConfigPath,scope);
                if(!await authority.IsVipOwner(epoch,deadline.Token))throw new InvalidOperationException("Ownership unconfirmed.");
                log.Append(epoch,"assign-intent");
                await VipHostAddressPlatform.Change(observed,ip,true,deadline.Token);
                log.Append(epoch,"assigned");
                // If the post-mutation quorum check fails, attempt conservative withdrawal.
                bool authorized=false;
                try {authorized=await authority.IsVipOwner(epoch,deadline.Token);}
                catch(Exception error) when(error is HttpRequestException or InvalidOperationException or InvalidDataException or OperationCanceledException or JsonException or KeyNotFoundException or FormatException or OverflowException){}
                if(!authorized)
                {
                    await Withdraw();
                    throw new InvalidOperationException("Ownership lost during assignment; withdrawal confirmed.");
                }
            }
            else if(args[4]=="withdraw")
            {
                if(log.Last?.Phase=="withdrawn"&&!observed.Present){}
                else await Withdraw();
            }
            var final=VipHostAddressPlatform.Inspect(args[3],ip,management);
            Console.WriteLine(JsonSerializer.Serialize(new {scope,address=ip.ToString(),epoch,phase=log.Last?.Phase??"unmanaged",present=final.Present,ready=final.Ready,eligibleToStart=journalBound&&args[4]=="reconcile"&&log.Last?.Phase=="assigned"&&log.Last.Epoch==epoch&&final.Ready}));
            return 0;
        }
        catch(Exception error) when(error is IOException or InvalidDataException or UnauthorizedAccessException or
            InvalidOperationException or ArgumentException or System.ComponentModel.Win32Exception or
            HttpRequestException or JsonException or CryptographicException or PlatformNotSupportedException or OperationCanceledException)
        {
            Console.Error.WriteLine("VIP host action refused or unconfirmed: "+error.GetType().Name+". Inspect the journal and local address state before recovery.");
            return 78;
        }
    }
}
