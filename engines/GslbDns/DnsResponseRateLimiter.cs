using System.Net;

// Fixed one-second response budget per source IPv4 address.
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

    public DnsResponseRateLimiter(int perSecond, int maxClients = 4096)
    {
        if (perSecond < 1 || maxClients < 1) throw new ArgumentOutOfRangeException();
        this.perSecond = perSecond;
        this.maxClients = maxClients;
    }

    public bool Allow(IPAddress address, long nowMs)
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
