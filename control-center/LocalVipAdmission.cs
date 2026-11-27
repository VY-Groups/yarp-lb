using Microsoft.Extensions.Hosting;
using System.Net.NetworkInformation;
using System.Net.Sockets;

// Local presence is necessary, not proof of distributed VIP ownership.
internal sealed class LocalVipAdmission : BackgroundService
{
    private readonly Dictionary<string,string> required;
    private readonly TimeProvider clock;
    private readonly Dictionary<string, Func<CancellationToken,Task<bool>>> authorities;
    private sealed record Sample(long Started, Dictionary<string,string> Status);
    private Sample? current;
    private readonly object lifecycle=new();
    private readonly Dictionary<string,HashSet<RequestLease>> inFlight=new(StringComparer.Ordinal);
    private const int MaximumRequestsPerSocket=4096;
    private HashSet<string> plannedDrains=new(StringComparer.Ordinal);
    internal bool IsDraining(string id){lock(lifecycle)return plannedDrains.Contains(id);}
    internal void SetPlannedDrains(IEnumerable<string> ids)
    {
        var next=new HashSet<string>(ids,StringComparer.Ordinal);
        if(next.Any(id=>!required.ContainsKey(id)))throw new InvalidDataException("Unknown drained VIP socket.");
        lock(lifecycle)plannedDrains=next;
    }

    private sealed class RequestLease(LocalVipAdmission owner,string id,Action abort):IDisposable
    {
        private readonly object sync=new();
        private bool done,aborted;
        internal void Abort()
        {
            lock(sync)
            {
                if(done||aborted)return;
                aborted=true;
                // Kestrel's abort is thread-safe. Do not hold the admission
                // lock while invoking transport callbacks.
                try {abort();}
                catch(Exception error) when(error is InvalidOperationException or IOException) { }
            }
        }
        public void Dispose()
        {
            lock(sync){if(done)return;done=true;}
            lock(owner.lifecycle)owner.inFlight[id].Remove(this);
        }
    }

    internal int Active(string id)
    {
        lock(lifecycle)return inFlight.TryGetValue(id,out var entries)?entries.Count:0;
    }

    internal bool TryEnter(string? id,Action abort,out IDisposable? lease)
    {
        lease=null;
        if(id is null||!required.ContainsKey(id))return true;
        lock(lifecycle)
        {
            if(plannedDrains.Contains(id)||!Allows(id)||inFlight[id].Count>=MaximumRequestsPerSocket)return false;
            var active=new RequestLease(this,id,abort);
            inFlight[id].Add(active);lease=active;
            return true;
        }
    }

    private RequestLease[] CollectInvalid()=>inFlight.Where(x=>!Allows(x.Key))
        .SelectMany(x=>x.Value).ToArray();
    internal void Sweep()
    {
        RequestLease[] invalid;
        lock(lifecycle)invalid=CollectInvalid();
        foreach(var lease in invalid)lease.Abort();
    }
    private async Task Watch(CancellationToken token)
    {
        using var timer=new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        try {while(await timer.WaitForNextTickAsync(token))Sweep();}
        catch(OperationCanceledException) when(token.IsCancellationRequested){}
    }
    internal LocalVipAdmission(IEnumerable<(string Id,string Ip)> targets, TimeProvider clock,
        Dictionary<string,Func<CancellationToken,Task<bool>>>? authorities = null)
    {
        required = targets.ToDictionary(x => x.Id, x => x.Ip, StringComparer.Ordinal);
        this.clock = clock;
        foreach(var id in required.Keys)inFlight.Add(id,new());
        this.authorities = authorities is null ? new(StringComparer.Ordinal) : new(authorities,StringComparer.Ordinal);
        if(this.authorities.Keys.Any(id=>!required.ContainsKey(id)))throw new InvalidOperationException("Unknown VIP authority target.");
    }
    internal string Status(string? id)
    {
        if (id is null || !required.ContainsKey(id)) return "disabled";
        var observed = Volatile.Read(ref current);
        if (observed is null) return "no-fresh-observation";
        var age = clock.GetElapsedTime(observed.Started);
        if (age < TimeSpan.Zero || age >= TimeSpan.FromSeconds(3)) return "stale-observation";
        return observed.Status[id];
    }
    internal bool Allows(string? id) => Status(id) is "disabled" or "present-interface-up";
    internal void Refresh(long started, LocalNetworkInventory.Snapshot snapshot, IReadOnlyDictionary<string,bool>? confirmed = null)
    {
        var statuses = new Dictionary<string,string>(StringComparer.Ordinal);
        foreach (var (id, ip) in required)
            statuses.Add(id, snapshot.Truncated ? "incomplete-observation" :
                NetworkObservation.ObserveVirtualAddress(id, ip, 0, "", snapshot).Status);
        foreach(var id in authorities.Keys)
            if(statuses[id]=="present-interface-up" && (confirmed is null || !confirmed.TryGetValue(id,out var allowed) || !allowed))
                statuses[id]="quorum-ownership-unconfirmed";
        RequestLease[] invalid;
        lock(lifecycle)
        {
            // Capture requests whose earlier authority had already expired,
            // even if the independent watchdog has not yet swept that gap.
            var expired=CollectInvalid();
            Volatile.Write(ref current,new Sample(started,statuses));
            invalid=expired.Concat(CollectInvalid()).Distinct().ToArray();
        }
        foreach(var lease in invalid)lease.Abort();
    }
    internal void Invalidate()
    {
        RequestLease[] invalid;
        lock(lifecycle){Volatile.Write(ref current,null);invalid=CollectInvalid();}
        foreach(var lease in invalid)lease.Abort();
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var watchStop=CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var watchdog=Watch(watchStop.Token);
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            do
            {
                var started = clock.GetTimestamp();
                try
                {
                    var snapshot = LocalNetworkInventory.Read();
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
                    deadline.CancelAfter(TimeSpan.FromSeconds(2));
                    var results=await Task.WhenAll(authorities.Select(async item=>
                    {
                        try { return (item.Key, Allowed:await item.Value(deadline.Token)); }
                        catch(Exception error) when(error is HttpRequestException or InvalidDataException or InvalidOperationException or
                            System.Text.Json.JsonException or KeyNotFoundException or FormatException or OverflowException or OperationCanceledException)
                        { return (item.Key,Allowed:false); }
                    }));
                    if (stoppingToken.IsCancellationRequested) break;
                    Refresh(started, snapshot, results.ToDictionary(x=>x.Key,x=>x.Allowed,StringComparer.Ordinal));
                }
                catch (Exception error) when (error is NetworkInformationException or SocketException or
                    InvalidOperationException or PlatformNotSupportedException)
                { Invalidate(); }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { Invalidate();watchStop.Cancel();await watchdog; }
    }
}
