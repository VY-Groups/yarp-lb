using System.Text.Json;

internal static class VipDrainState
{
    internal static HashSet<string> Parse(byte[] data,IEnumerable<string> eligible)
    {
        if(data.Length is <2 or >8192)throw new InvalidDataException("Invalid bounded VIP drain state.");
        var values=JsonSerializer.Deserialize<string[]>(data)??throw new InvalidDataException("Missing VIP drain state.");
        var allowed=eligible.ToHashSet(StringComparer.Ordinal);
        var result=new HashSet<string>(StringComparer.Ordinal);
        if(values.Length>32)throw new InvalidDataException("Too many VIP drain records.");
        foreach(var ip in values)
            if(ip is null||!allowed.Contains(ip)||!result.Add(ip))
                throw new InvalidDataException("Unknown or duplicate VIP drain address; refuse unsafe startup.");
        return result;
    }
    internal static HashSet<string> Read(string path,IEnumerable<string> eligible)
    {
        try
        {
            if((File.GetAttributes(path)&FileAttributes.ReparsePoint)!=0)
                throw new InvalidDataException("Linked VIP drain state refused.");
        }
        catch(FileNotFoundException){return new(StringComparer.Ordinal);}
        using var file=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);
        if(file.Length is <2 or >8192)throw new InvalidDataException("Invalid bounded VIP drain state.");
        var bytes=new byte[checked((int)file.Length)];
        file.ReadExactly(bytes);
        if(file.ReadByte()!=-1)throw new InvalidDataException("VIP drain state changed while reading.");
        return Parse(bytes,eligible);
    }
    internal static byte[] Encode(IEnumerable<string> drained)=>JsonSerializer.SerializeToUtf8Bytes(drained.OrderBy(x=>x,StringComparer.Ordinal).ToArray());
}
