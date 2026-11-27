using System.Text;
using System.Text.Json;

internal sealed class VipAutomaticJournal : IDisposable
{
    internal sealed record Transition(string Scope,string OldPin,long OldEpoch,string NewPin,string Kind,long FinalEpoch=0);
    private readonly FileStream file;
    private readonly string scope,preferred,other;
    internal Transition? Pending {get;private set;}
    internal long LastCompletedEpoch {get;private set;}
    internal VipAutomaticJournal(string path,string scope,string preferred,string other)
    {
        VipFenceProvider.ValidatePair(scope,preferred,other);
        this.scope=scope;this.preferred=preferred;this.other=other;
        if(!Path.IsPathFullyQualified(path)||!Directory.Exists(Path.GetDirectoryName(path))||
            (File.GetAttributes(Path.GetDirectoryName(path)!)&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Protected absolute controller journal required.");
        if(OperatingSystem.IsLinux()&&(File.GetUnixFileMode(Path.GetDirectoryName(path)!)&
            (UnixFileMode.GroupRead|UnixFileMode.GroupWrite|UnixFileMode.GroupExecute|
             UnixFileMode.OtherRead|UnixFileMode.OtherWrite|UnixFileMode.OtherExecute))!=0)
            throw new InvalidDataException("Controller journal directory must be owner-private.");
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Linked controller journal refused.");
        var options=new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,Options=FileOptions.WriteThrough};
        if(OperatingSystem.IsLinux())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        file=new FileStream(path,options);
        try
        {
            if(file.Length>1024*1024)throw new InvalidDataException("Controller journal exceeds recovery bound.");
            using var reader=new StreamReader(file,new UTF8Encoding(false,true),false,1024,true);
            var raw=reader.ReadToEnd();
            if(raw.Length!=0&&!raw.EndsWith('\n'))throw new InvalidDataException("Interrupted controller journal.");
            foreach(var line in raw.Split('\n',StringSplitOptions.RemoveEmptyEntries))
                Apply(JsonSerializer.Deserialize<Transition>(line)??throw new InvalidDataException("Invalid transition."),false);
            file.Seek(0,SeekOrigin.End);
        }
        catch{file.Dispose();throw;}
    }
    private void Apply(Transition value,bool persist)
    {
        if(value.Scope!=scope||value.OldEpoch<1||value.OldEpoch<LastCompletedEpoch||
            !((value.OldPin==preferred&&value.NewPin==other)||(value.OldPin==other&&value.NewPin==preferred))||
            value.Kind is not ("failover" or "failback")||
            (value.Kind=="failback"&&value.NewPin!=preferred))
            throw new InvalidDataException("Invalid controller journal identity or revision.");
        if(value.FinalEpoch==0)
        {if(Pending is not null)throw new InvalidDataException("Unresolved VIP transition.");}
        else if(Pending is null||value.FinalEpoch<=value.OldEpoch||
            (value with{FinalEpoch=0})!=Pending)
            throw new InvalidDataException("Unrelated controller completion.");
        if(persist)
        {
            var bytes=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(value)+"\n");
            if(file.Length+bytes.Length>1024*1024)throw new InvalidDataException("Controller journal full.");
            file.Write(bytes);file.Flush(true);
        }
        if(value.FinalEpoch==0)Pending=value;
        else{Pending=null;LastCompletedEpoch=value.FinalEpoch;}
    }
    internal void Begin(Transition value)=>Apply(value,true);
    internal void Complete(long epoch)=>Apply((Pending??throw new InvalidOperationException("No pending VIP transition.")) with{FinalEpoch=epoch},true);
    public void Dispose()=>file.Dispose();
}

// Samples must be consecutive at the same exact owner revision. Restart,
// unavailable evidence, epoch change or a non-quiescent provider resets them.
internal sealed class VipAutomaticPolicy
{
    private readonly TimeProvider clock;
    private FleetQuorum.Fence? last;
    private long observedAt,eligibleAt,failingAt;
    private int failures,eligible;
    internal VipAutomaticPolicy(TimeProvider clock){this.clock=clock;}
    internal void Reset(){last=null;failures=eligible=0;}
    internal string? Observe(FleetQuorum.Fence state,VipFenceProvider.NodeEvidence sample,string preferred,bool failback)
    {
        long now=clock.GetTimestamp();
        if(last!=state){Reset();last=state;observedAt=now;}
        if(!sample.Quiescent||!sample.OtherEligible||sample.OwnerDrained){failures=eligible=0;return null;}
        if(!sample.OwnerServing)
        {
            eligible=0;
            if(failures++==0)failingAt=now;
            if(failures>=3&&clock.GetElapsedTime(failingAt,now)>=TimeSpan.FromSeconds(10))return "failover";
            return null;
        }
        failures=0;
        if(!failback||sample.OtherPin!=preferred||sample.OwnerDrained){eligible=0;return null;}
        if(eligible++==0)eligibleAt=now;
        if(eligible>=3&&clock.GetElapsedTime(eligibleAt,now)>=TimeSpan.FromMinutes(2)&&
            clock.GetElapsedTime(observedAt,now)>=TimeSpan.FromMinutes(5))return "failback";
        return null;
    }
}

internal static class VipAutomaticController
{
    internal static async Task ExecuteTransition(string scope,VipAutomaticJournal.Transition intent,VipAutomaticJournal journal,
        Func<CancellationToken,Task<FleetQuorum.Fence?>> observe,
        Func<string,long,CancellationToken,Task<FleetQuorum.Fence>> revoke,
        Func<VipFenceProvider.Request,CancellationToken,Task<(long Expires,byte[] Signature)>> fence,
        Func<string,long,string,long,byte[],CancellationToken,Task<FleetQuorum.Fence>> activate,
        Func<string,string,string,long,string,CancellationToken,Task<VipFenceProvider.NodeEvidence>> nodeAction,
        CancellationToken token)
    {
        if(journal.Pending!=intent||scope!=intent.Scope)
            throw new InvalidDataException("Transition must match the durable pending intent.");
        var state=await observe(token)??throw new InvalidDataException("Owner record missing.");
        var original=new FleetQuorum.Fence("vip_"+intent.OldPin,intent.OldEpoch);
        if(state==original)
        {
            var sample=await nodeAction("node-status",scope,intent.OldPin,intent.OldEpoch,intent.NewPin,token);
            if(!sample.Quiescent||!sample.OtherEligible||
                (intent.Kind=="failover"&&(sample.OwnerServing||sample.OwnerDrained)))
                throw new InvalidDataException("Transition conditions no longer hold; independent recovery required.");
            // A prior drain flag does not prove that all in-flight requests
            // completed, nor that this is not a human maintenance drain.
            if(intent.Kind=="failback")
            {
                sample=await nodeAction("drain-node",scope,intent.OldPin,intent.OldEpoch,intent.NewPin,token);
                if(!sample.Quiescent||!sample.OwnerDrained||!sample.OtherEligible)
                    throw new InvalidDataException("Planned failback drain not confirmed.");
            }
            if(await observe(token)!=original)throw new FleetQuorumContentionException();
            state=await VipFencedTransfer.Run(scope,intent.OldPin,intent.OldEpoch,intent.NewPin,false,
                observe,revoke,fence,activate,token);
        }
        else if(state.Transaction=="vip_revoked_"+intent.OldPin&&state.Epoch>intent.OldEpoch)
        {
            state=await VipFencedTransfer.Run(scope,intent.OldPin,state.Epoch,intent.NewPin,true,
                observe,revoke,fence,activate,token);
        }
        else if(state.Transaction!="vip_"+intent.NewPin||state.Epoch<=intent.OldEpoch)
            throw new InvalidDataException("Unexpected owner revision; preserve transition journal.");
        if(state.Transaction!="vip_"+intent.NewPin||state.Epoch<=intent.OldEpoch||
            await observe(token)!=state)
            throw new InvalidDataException("Successor ownership not confirmed.");
        var activation=await nodeAction("activate-node",scope,intent.NewPin,state.Epoch,intent.OldPin,token);
        if(!activation.Quiescent||!activation.OwnerServing||activation.OwnerDrained||
            await observe(token)!=state)
            throw new InvalidDataException("Successor service or ownership unconfirmed; preserve transition.");
        journal.Complete(state.Epoch);
        Console.WriteLine(JsonSerializer.Serialize(new{decision=intent.Kind,owner=intent.NewPin,epoch=state.Epoch}));
    }
    internal static async Task Run(string scope,string preferred,string other,string providerConfig,string journalPath,
        bool failback,bool recover,FleetQuorum authority,CancellationToken stop)
    {
        using var provider=VipFenceProvider.Open(providerConfig,scope,preferred,other);
        using var journal=new VipAutomaticJournal(journalPath,scope,preferred,other);
        var policy=new VipAutomaticPolicy(TimeProvider.System);
        string Other(string pin)=>pin==preferred?other:pin==other?preferred:throw new InvalidDataException("Unknown VIP owner identity.");
        Task Execute(VipAutomaticJournal.Transition intent,CancellationToken token)=>
            ExecuteTransition(scope,intent,journal,authority.ObserveVip,authority.RevokeVip,
                provider.Fence,authority.ActivateVip,provider.NodeAction,token);
        if(recover)
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop);
            deadline.CancelAfter(TimeSpan.FromSeconds(240));
            await Execute(journal.Pending??throw new InvalidDataException("No pending transition."),deadline.Token);
            return;
        }
        if(journal.Pending is not null)throw new InvalidDataException("Unresolved transition; use explicit recovery.");
        using var timer=new PeriodicTimer(TimeSpan.FromSeconds(5));
        do
        {
            using var deadline=CancellationTokenSource.CreateLinkedTokenSource(stop);
            deadline.CancelAfter(TimeSpan.FromSeconds(20));
            FleetQuorum.Fence? state=null;VipFenceProvider.NodeEvidence? evidence=null;
            try
            {
                state=await authority.ObserveVip(deadline.Token);
                if(state is null||!state.Transaction.StartsWith("vip_",StringComparison.Ordinal)||
                    !VipFenceProvider.Pin(state.Transaction[4..])||
                    (journal.LastCompletedEpoch>0&&state.Epoch!=journal.LastCompletedEpoch))
                    throw new InvalidDataException("No active reviewed owner; independent recovery required.");
                string owner=state.Transaction[4..];
                evidence=await provider.NodeAction("node-status",scope,owner,state.Epoch,Other(owner),deadline.Token);
                if(await authority.ObserveVip(deadline.Token)!=state){policy.Reset();continue;}
            }
            catch(Exception e) when(!stop.IsCancellationRequested&&(e is HttpRequestException or OperationCanceledException or
                FleetQuorumContentionException or InvalidOperationException or InvalidDataException or JsonException))
            {policy.Reset();Console.Error.WriteLine("VIP automatic observation unavailable; no mutation.");continue;}
            string? decision=policy.Observe(state!,evidence!,preferred,failback);
            if(decision is not null)
            {
                var intent=new VipAutomaticJournal.Transition(scope,evidence!.OwnerPin,state!.Epoch,evidence.OtherPin,decision);
                journal.Begin(intent);
                using var transitionDeadline=CancellationTokenSource.CreateLinkedTokenSource(stop);
                transitionDeadline.CancelAfter(TimeSpan.FromSeconds(240));
                await Execute(intent,transitionDeadline.Token);
                policy.Reset();
            }
        }while(await timer.WaitForNextTickAsync(stop));
    }
}
