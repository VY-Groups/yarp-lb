using Microsoft.Extensions.Hosting;
using System.Net.NetworkInformation;
using System.Net.Sockets;

// Local presence is necessary, not proof of distributed VIP ownership.
internal sealed class LocalVipAdmission : BackgroundService
{
    private readonly Dictionary<string,string> required;
    private readonly TimeProvider clock;
    private sealed record Sample(long Started, Dictionary<string,string> Status);
    private Sample? current;
    internal LocalVipAdmission(IEnumerable<(string Id,string Ip)> targets, TimeProvider clock)
    {
        required = targets.ToDictionary(x => x.Id, x => x.Ip, StringComparer.Ordinal);
        this.clock = clock;
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
    internal void Refresh(long started, LocalNetworkInventory.Snapshot snapshot)
    {
        var statuses = new Dictionary<string,string>(StringComparer.Ordinal);
        foreach (var (id, ip) in required)
            statuses.Add(id, snapshot.Truncated ? "incomplete-observation" :
                NetworkObservation.ObserveVirtualAddress(id, ip, 0, "", snapshot).Status);
        Volatile.Write(ref current, new Sample(started, statuses));
    }
    internal void Invalidate() => Volatile.Write(ref current, null);
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
            do
            {
                var started = clock.GetTimestamp();
                try
                {
                    var snapshot = LocalNetworkInventory.Read();
                    if (stoppingToken.IsCancellationRequested) break;
                    Refresh(started, snapshot);
                }
                catch (Exception error) when (error is NetworkInformationException or SocketException or
                    InvalidOperationException or PlatformNotSupportedException)
                { Invalidate(); }
            } while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
        finally { Invalidate(); }
    }
}
