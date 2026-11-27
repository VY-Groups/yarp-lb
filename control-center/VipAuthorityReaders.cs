// Lifetime owner of read-only Raft clients. Multiple sockets may share one reader.
internal sealed class VipAuthorityReaders : IDisposable
{
    private readonly Dictionary<(string Path,string Scope),FleetQuorum> clients = new();
    internal Func<CancellationToken,Task<bool>> For(string path,string scope,long epoch,Func<bool>? localBinding=null)
    {
        if(!clients.TryGetValue((path,scope),out var client))
            clients.Add((path,scope),client=FleetQuorum.OpenVip(path,scope));
        return async token=>(localBinding is null||localBinding()) &&
            await client.IsVipOwner(epoch,token) && (localBinding is null||localBinding());
    }
    public void Dispose()
    {
        foreach(var client in clients.Values)client.Dispose();
        clients.Clear();
    }
}
