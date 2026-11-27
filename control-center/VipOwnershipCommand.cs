using System.Globalization;
using System.Security.Cryptography;

// Local writer command, never exposed as a remote HTTP endpoint. The writer
// must be independently provisioned and must not run on either gateway node.
internal static class VipOwnershipCommand
{
    internal static async Task<int> Run(string[] args)
    {
        try
        {
            if(args.Length<4)throw new ArgumentException("Usage: --vip-owner <writer-config> <scope> status|revoke|activate ...");
            using var authority=FleetQuorum.OpenVipWriter(args[1],args[2]);
            using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(
                args[3] is "transfer" or "resume-transfer"?90:25));
            long Number(string s)=>long.Parse(s,NumberStyles.None,CultureInfo.InvariantCulture);
            FleetQuorum.Fence? state;
            if((args[3] is "automatic-policy" or "recover-policy")&&args.Length==7)
            {
                var policy=VipPolicyDocument.Load(args[4],args[2]);
                using var stop=new CancellationTokenSource();
                ConsoleCancelEventHandler cancel=(_,eventArgs)=>{eventArgs.Cancel=true;stop.Cancel();};
                Console.CancelKeyPress+=cancel;
                try{await VipAutomaticController.Run(args[2],policy.PreferredPin,policy.OtherPin,args[5],args[6],
                    policy.FailbackEnabled,args[3]=="recover-policy",authority,stop.Token,policy);}
                catch(OperationCanceledException) when(stop.IsCancellationRequested){}
                finally{Console.CancelKeyPress-=cancel;}
                return 0;
            }
            if((args[3] is "automatic" or "recover-automatic")&&args.Length==9&&args[8] is "failback-on" or "failback-off")
            {
                using var stop=new CancellationTokenSource();
                ConsoleCancelEventHandler cancel=(_,eventArgs)=>{eventArgs.Cancel=true;stop.Cancel();};
                Console.CancelKeyPress+=cancel;
                try{await VipAutomaticController.Run(args[2],args[4],args[5],args[6],args[7],
                    args[8]=="failback-on",args[3]=="recover-automatic",authority,stop.Token);}
                catch(OperationCanceledException) when(stop.IsCancellationRequested){}
                finally{Console.CancelKeyPress-=cancel;}
                return 0;
            }
            if(args[3]=="status" && args.Length==4)state=await authority.ObserveVip(timeout.Token);
            else if(args[3]=="revoke" && args.Length==6)
                state=await authority.RevokeVip(args[4],Number(args[5]),timeout.Token);
            else if(args[3] is "transfer" or "resume-transfer" && args.Length==8)
            {
                // Explicit local independently authorized writer only. Provider
                // is configured before any quorum mutation; a failed provider
                // never re-enables the old or successor owner.
                using var provider=VipFenceProvider.Open(args[7],args[2],args[4],args[6]);
                state=await VipFencedTransfer.Run(args[2],args[4],Number(args[5]),args[6],
                    args[3]=="resume-transfer",authority.ObserveVip,authority.RevokeVip,
                    provider.Fence,authority.ActivateVip,timeout.Token);
            }
            else if(args[3]=="activate" && args.Length==9)
            {
                // Permit is a detached DER ECDSA signature, not a password or
                // shell command. Exact epoch and successor bind it to one transition.
                var path=args[8];
                if(!Path.IsPathFullyQualified(path))throw new InvalidDataException("Absolute permit signature path required.");
                var info=new FileInfo(path);
                if(!info.Exists || info.Length is <64 or >80 || (info.Attributes&FileAttributes.ReparsePoint)!=0)
                    throw new InvalidDataException("Invalid permit signature file.");
                using var input=File.OpenRead(path);
                var signature=new byte[checked((int)info.Length)];
                input.ReadExactly(signature);
                if(input.ReadByte()!=-1)throw new InvalidDataException("Permit signature changed.");
                state=await authority.ActivateVip(args[4],Number(args[5]),args[6],Number(args[7]),signature,timeout.Token);
            }
            else throw new ArgumentException("Invalid VIP ownership command.");
            Console.WriteLine(System.Text.Json.JsonSerializer.Serialize(new {owner=state?.Transaction,epoch=state?.Epoch??0}));
            return 0;
        }
        catch(Exception error) when(error is IOException or InvalidDataException or CryptographicException or ArgumentException or
            InvalidOperationException or UnauthorizedAccessException or HttpRequestException or OperationCanceledException or
            System.Text.Json.JsonException or KeyNotFoundException or FormatException or OverflowException)
        {
            Console.Error.WriteLine("VIP ownership command refused or unconfirmed: "+error.GetType().Name+
                ". Use status to reconcile before retrying. Never bypass fencing.");
            return 78;
        }
    }
}
