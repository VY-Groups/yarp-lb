using System.Text.Json;
using System.Text;

internal sealed class VipAddressJournal : IDisposable
{
    internal sealed record Entry(string Scope,string InterfaceId,string Address,long Epoch,string Phase);
    private readonly FileStream stream;
    private readonly string scope,interfaceId,address;
    private readonly bool readOnly;
    internal Entry? Last {get;private set;}
    internal VipAddressJournal(string path,string scope,string interfaceId,string address,bool readOnly=false)
    {
        this.scope=scope;this.interfaceId=interfaceId;this.address=address;this.readOnly=readOnly;
        var options=readOnly?new FileStreamOptions{Mode=FileMode.Open,Access=FileAccess.Read,Share=FileShare.Read}:
            new FileStreamOptions{Mode=FileMode.OpenOrCreate,Access=FileAccess.ReadWrite,Share=FileShare.None,Options=FileOptions.WriteThrough};
        if(!readOnly&&OperatingSystem.IsLinux())options.UnixCreateMode=UnixFileMode.UserRead|UnixFileMode.UserWrite;
        if(File.Exists(path)&&(File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)throw new InvalidDataException("Linked VIP journal refused.");
        stream=new FileStream(path,options);
        try
        {
            if(stream.Length>1024*1024)throw new InvalidDataException("VIP journal exceeds bounded recovery size.");
            using var reader=new StreamReader(stream,new UTF8Encoding(false,true),false,1024,true);
            var raw=reader.ReadToEnd();
            if(raw.Length>0&&!raw.EndsWith('\n'))throw new InvalidDataException("Interrupted journal write requires independent recovery.");
            foreach(var line in raw.Split('\n',StringSplitOptions.RemoveEmptyEntries))
            {
                var item=JsonSerializer.Deserialize<Entry>(line)??throw new InvalidDataException("Invalid VIP journal entry.");
                Validate(item);Last=item;
            }
            stream.Seek(0,SeekOrigin.End);
        }
        catch {stream.Dispose();throw;}
    }
    private void Validate(Entry item)
    {
        if(item.Scope!=scope||item.InterfaceId!=interfaceId||item.Address!=address||item.Epoch<1)
            throw new InvalidDataException("VIP journal identity mismatch.");
        bool valid=(Last?.Phase,item.Phase) switch
        {
            (null,"assign-intent")=>true,
            ("withdrawn","assign-intent")=>item.Epoch>Last!.Epoch,
            ("assign-intent","assigned")=>item.Epoch==Last!.Epoch,
            ("assigned","reassign-intent")=>item.Epoch==Last!.Epoch,
            ("reassign-intent","assigned")=>item.Epoch==Last!.Epoch,
            ("assigned","withdraw-intent")=>item.Epoch==Last!.Epoch,
            ("withdraw-intent","withdrawn")=>item.Epoch==Last!.Epoch,
            _=>false
        };
        if(!valid)throw new InvalidDataException("Invalid or stale VIP journal transition.");
    }
    internal void Append(long epoch,string phase)
    {
        if(readOnly)throw new InvalidOperationException("Read-only VIP journal.");
        var item=new Entry(scope,interfaceId,address,epoch,phase);
        Validate(item);
        var bytes=Encoding.UTF8.GetBytes(JsonSerializer.Serialize(item)+"\n");
        if(stream.Length+bytes.Length>1024*1024)throw new InvalidDataException("VIP journal full.");
        stream.Write(bytes);stream.Flush(flushToDisk:true);Last=item;
    }
    public void Dispose()=>stream.Dispose();
}
