using System.Net;
using System.Net.Sockets;

// Concurrent session budget, not a SYN flood or upstream bandwidth defense.
// At most 32 active leases, matching the existing global TCP session limit.
internal sealed class DnsTcpPeerAdmission(int perPeer)
{
    private readonly object sync = new();
    private readonly Dictionary<IPAddress, int> active = new();
    private int total;
    internal IDisposable? Acquire(IPAddress peer)
    {
        if (peer.IsIPv4MappedToIPv6) peer = peer.MapToIPv4();
        else if (peer.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var bytes = peer.GetAddressBytes();
            bytes.AsSpan(8).Clear();
            peer = new IPAddress(bytes);
        }
        lock (sync)
        {
            active.TryGetValue(peer, out int count);
            if (total >= 32 || count >= perPeer) return null;
            active[peer] = count + 1;
            total++;
            return new Lease(this, peer);
        }
    }
    private void Release(IPAddress peer)
    {
        lock (sync)
        {
            int count = active[peer];
            if (count == 1) active.Remove(peer);
            else active[peer] = count - 1;
            total--;
        }
    }
    private sealed class Lease(DnsTcpPeerAdmission owner, IPAddress peer) : IDisposable
    {
        private int released;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref released, 1) == 0) owner.Release(peer);
        }
    }
}
