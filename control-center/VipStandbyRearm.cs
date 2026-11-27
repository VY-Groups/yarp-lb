using System.Text;
using System.Text.Json;

internal sealed class VipProviderRearmJournal:IDisposable
{
    internal sealed record Attempt(string Scope,string OwnerPin,long Epoch,string OtherPin);
    private readonly FileStream file;
    private readonly string scope,first,second;
    private readonly bool readOnly;
    internal long LastEpoch {get;private set;}
    internal VipProviderRearmJournal(string path,string scope,string first,string second,bool readOnly=false)
    {
        VipFenceProvider.ValidatePair(scope,first,second);
        this.scope=scope;this.first=first;this.second=second;this.readOnly=readOnly;
        if(!Path.IsPathFullyQualified(path)||!Directory.Exists(Path.GetDirectoryName(path))||
            (File.GetAttributes(Path.GetDirectoryName(path)!)&FileAttributes.ReparsePoint)!=0||
            (File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0))
            throw new InvalidDataException("Protected provider rearm journal required.");
        var options=readOnly
            ?new FileStreamOptions{Mode=FileMode.Open,Access=FileAccess.Read,Share=FileShare.Read}
            :new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,Options=FileOptions.WriteThrough};
        if(!readOnly&&OperatingSystem.IsLinux())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        file=new FileStream(path,options);
        try
        {
            if(file.Length>1024*1024)throw new InvalidDataException("Provider rearm journal full.");
            using var reader=new StreamReader(file,new UTF8Encoding(false,true),false,1024,true);
            var raw=reader.ReadToEnd();
            if(raw.Length>0&&!raw.EndsWith('\n'))throw new InvalidDataException("Interrupted provider rearm journal.");
            foreach(var line in raw.Split('\n',StringSplitOptions.RemoveEmptyEntries))
                Apply(JsonSerializer.Deserialize<Attempt>(line)??throw new InvalidDataException("Missing rearm attempt."),false);
            file.Seek(0,SeekOrigin.End);
        }
        catch{file.Dispose();throw;}
    }
    private void Apply(Attempt attempt,bool persist)
    {
        if(attempt.Scope!=scope||attempt.Epoch<=LastEpoch||
            !((attempt.OwnerPin==first&&attempt.OtherPin==second)||(attempt.OwnerPin==second&&attempt.OtherPin==first)))
            throw new InvalidDataException("Stale or duplicate provider power-on intent.");
        if(persist)
        {
            if(readOnly)throw new InvalidOperationException("Read-only provider rearm journal.");
            var bytes=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(attempt)+"\n");
            if(file.Length+bytes.Length>1024*1024)throw new InvalidDataException("Provider rearm journal full.");
            file.Write(bytes);file.Flush(true);
        }
        LastEpoch=attempt.Epoch;
    }
    internal void Record(VipFenceProvider.NodeRequest r)=>Apply(new(r.Scope,r.OwnerPin,r.Epoch,r.OtherPin),true);
    public void Dispose()=>file.Dispose();
}

internal static class VipStandbyRearm
{
    internal static async Task<VipFenceProvider.NodeEvidence> Run(VipFenceProvider.NodeRequest r,
        VipProviderRearmJournal journal,Func<Task> assertOwner,Func<CancellationToken,Task<bool>> ownerOff,
        Func<string,bool,CancellationToken,Task<VipRemoteNode.Evidence>> nodeStatus,
        Func<bool,CancellationToken,Task<VipRemoteNode.DrainEvidence>> drain,
        Func<Func<CancellationToken,Task>,CancellationToken,Task> powerOn,CancellationToken token)
    {
        async Task AssertSafe(CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            await assertOwner();
            if(await ownerOff(ct)||!(await nodeStatus(r.OwnerPin,false,ct)).Serving)
                throw new InvalidDataException("Current owner not serving; rearm refused.");
            var d=await drain(false,ct);
            if(d.ManualDrain||d.Draining)throw new InvalidDataException("Owner maintenance drain; rearm refused.");
            await assertOwner();
        }
        await AssertSafe(token);
        journal.Record(r); // durable on the provider as well as the writer
        await powerOn(AssertSafe,token);
        while(true)
        {
            await AssertSafe(token);
            try
            {
                if((await nodeStatus(r.OtherPin,false,token)).Eligible)
                {
                    await AssertSafe(token);
                    return new(r.Scope,r.OwnerPin,r.Epoch,r.OtherPin,r.Nonce,true,true,false,true);
                }
            }
            catch(Exception e) when(e is HttpRequestException or InvalidDataException or OperationCanceledException)
            {token.ThrowIfCancellationRequested();}
            await Task.Delay(TimeSpan.FromSeconds(3),token);
        }
    }
}
