using System.Text.Json;
internal static class VipMachineDrainState
{
    internal sealed record Entry(string Scope,long Epoch);
    internal static bool Read(string path,string scope,long epoch)
    {
        if(!File.Exists(path))return false;
        var info=new FileInfo(path);
        if(info.Length is <2 or >512||(info.Attributes&FileAttributes.ReparsePoint)!=0)
            throw new InvalidDataException("Invalid automatic VIP drain state.");
        using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        return Parse(JsonSerializer.Deserialize<Entry>(stream)??throw new InvalidDataException("Missing automatic drain state."),scope,epoch);
    }
    internal static bool Parse(Entry entry,string scope,long epoch)
    {
        if(entry.Scope!=scope||entry.Epoch<1||entry.Epoch>epoch)throw new InvalidDataException("Automatic drain scope or epoch mismatch.");
        return entry.Epoch==epoch;
    }
    internal static byte[] Encode(string scope,long epoch)=>JsonSerializer.SerializeToUtf8Bytes(new Entry(scope,epoch));
}
