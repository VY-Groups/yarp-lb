using System.Net;

// Fixed one-second per-source UDP work budget, with optional aggregate
// admission and IPv6 /64 grouping. Counts attempts admitted for parsing.
// Deliberately single-threaded: the DNS UDP receive loop is its only caller.
// This is a limited defense-in-depth mechanism, NOT public-internet DDoS protection.
internal sealed class DnsResponseRateLimiter
{
    private sealed class ClientBudget
    {
        public ClientBudget(long startedMs) { StartedMs = startedMs; }
        public long StartedMs;
        public int Count = 1;
    }

    private readonly int perSecond;
    private readonly int maxClients;
    private readonly Dictionary<IPAddress, ClientBudget> clients = new();
    private long nextSweepMs;
    private readonly int totalPerSecond;
    private readonly bool groupIpv6;
    private long? totalStartedMs;
    private int totalCount;

    public DnsResponseRateLimiter(int perSecond, int maxClients = 4096,
        int totalPerSecond = 0, bool groupIpv6 = false)
    {
        if (perSecond < 1 || maxClients < 1 || totalPerSecond < 0)
            throw new ArgumentOutOfRangeException();
        this.perSecond = perSecond;
        this.maxClients = maxClients;
        this.totalPerSecond = totalPerSecond;
        this.groupIpv6 = groupIpv6;
    }

    public bool Allow(IPAddress address, long nowMs)
    {
        // Reject a saturated aggregate budget before allocating a new
        // address key or sweeping the bounded source table.
        if (totalPerSecond > 0)
        {
            if (totalStartedMs is not long started || nowMs < started || nowMs - started >= 1000)
            {
                totalStartedMs = nowMs;
                totalCount = 0;
            }
            if (totalCount >= totalPerSecond) return false;
        }
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        else if (groupIpv6 && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            // The scope interface is intentionally not a separate budget.
            var bytes = address.GetAddressBytes();
            bytes.AsSpan(8).Clear();
            address = new IPAddress(bytes);
        }
        if (!AllowSource(address, nowMs)) return false;
        if (totalPerSecond > 0) totalCount++;
        return true;
    }

    private bool AllowSource(IPAddress address, long nowMs)
    {
        if (clients.TryGetValue(address, out var budget))
        {
            if (nowMs < budget.StartedMs || nowMs - budget.StartedMs >= 1000)
            {
                budget.StartedMs = nowMs;
                budget.Count = 1;
                return true;
            }
            if (budget.Count >= perSecond) return false;
            budget.Count++;
            return true;
        }

        if (clients.Count >= maxClients)
        {
            if (nowMs >= nextSweepMs)
            {
                foreach (var (ip, old) in clients.ToArray())
                    if (nowMs < old.StartedMs || nowMs - old.StartedMs >= 1000)
                        clients.Remove(ip);
                nextSweepMs = nowMs + 1000;
            }
            // A full table refuses unseen sources rather than growing without bounds.
            if (clients.Count >= maxClients) return false;
        }

        clients.Add(address, new ClientBudget(nowMs));
        return true;
    }
}
