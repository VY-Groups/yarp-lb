using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Standalone, non-recursive authoritative DNS/GSLB lab engine (UDP and TCP).
// NS/SOA responses require explicit per-zone name server metadata.
// No traffic passes through the YARP HTTP reverse proxy.
if(args.Length != 1 || !File.Exists(args[0]))
{
    Console.Error.WriteLine("Usage: dotnet GslbDns.dll <absolute JSON configuration>");
    return 64;
}
var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var config = JsonSerializer.Deserialize<DnsConfig>(File.ReadAllText(args[0]), options)
    ?? throw new InvalidDataException("Missing DNS config");
if (!IPAddress.TryParse(config.ListenHost, out var listen) ||
    listen.AddressFamily != AddressFamily.InterNetwork ||
    (!config.AllowNonLoopbackListeners && !IPAddress.IsLoopback(listen)) ||
    config.ListenPort is < 1025 or > 65535 ||
    config.ProbeIntervalSeconds is < 1 or > 60 ||
    config.MaxResponsesPerSecondPerClient is < 20 or > 20000 ||
    config.Zones is not { Length: >= 1 and <= 64 })
    throw new InvalidDataException("Invalid DNS listener or zones. Non-loopback binding requires explicit opt-in.");
var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var groups=new Dictionary<string, SiteGroup>(StringComparer.OrdinalIgnoreCase);
foreach(var zone in config.Zones)
{
    if (string.IsNullOrWhiteSpace(zone.Name) || zone.Name.Length > 253 ||
        !names.Add(zone.Name.TrimEnd('.')) || zone.TtlSeconds is < 5 or > 300 ||
        !DnsWireProtocol.ValidName(zone.Name.TrimEnd('.')) ||
        zone.Sites is not {Length: >=1 and <=16} ||
        zone.NameServers is {Length: >4} || zone.SoaSerial == 0 ||
        zone.FailureThreshold is < 1 or > 10 ||
        zone.SuccessThreshold is < 1 or > 10 ||
        zone.RoutingPolicy is not ("Weighted" or "Failover"))
        throw new InvalidDataException("Invalid GSLB zone or TTL");
    var sites=new List<Site>();
    foreach(var site in zone.Sites)
    {
        if(!IPAddress.TryParse(site.Address,out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            site.Weight is < 1 or > 100 ||
            site.Priority is < 0 or > 1000 ||
            !Uri.TryCreate(site.HealthUrl, UriKind.Absolute, out var health) ||
            (health.Scheme != Uri.UriSchemeHttp && health.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrWhiteSpace(health.UserInfo))
            throw new InvalidDataException("Invalid GSLB site address, weight or health probe URL");
        sites.Add(new Site(address,health,site.Weight,site.Priority,
            zone.FailureThreshold,zone.SuccessThreshold));
    }
    var origin = zone.Name.TrimEnd('.').ToLowerInvariant();
    var servers = new List<DnsNameServer>();
    var serverNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var source in zone.NameServers ?? Array.Empty<DnsNameServerConfig>())
    {
        if (source is null || string.IsNullOrWhiteSpace(source.Host) ||
            !DnsWireProtocol.ValidName(source.Host.TrimEnd('.')) ||
            !IPAddress.TryParse(source.Address, out var nsAddress) ||
            nsAddress.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidDataException("Invalid authoritative NS host or IPv4 glue");
        var host = source.Host.TrimEnd('.').ToLowerInvariant();
        if (!serverNames.Add(host))
            throw new InvalidDataException("Duplicate authoritative NS hostname");
        // Explicit out-of-bailiwick servers may be NS targets; their A data is not advertised.
        servers.Add(new DnsNameServer(host, nsAddress));
    }
    var contact = (zone.SoaContact ?? ("hostmaster." + origin)).TrimEnd('.').ToLowerInvariant();
    if (!DnsWireProtocol.ValidName(contact))
        throw new InvalidDataException("Invalid SOA contact name");
    groups.Add(origin, new SiteGroup(sites.ToArray(), zone.TtlSeconds,
        zone.FailClosedWhenAllSitesDown, servers.ToArray(), contact, zone.SoaSerial,
        zone.RoutingPolicy));
}
using var stop=new CancellationTokenSource();
Console.CancelKeyPress += (_, e)=>{e.Cancel=true;stop.Cancel();};
using var sigterm=OperatingSystem.IsLinux()
    ? System.Runtime.InteropServices.PosixSignalRegistration.Create(
        System.Runtime.InteropServices.PosixSignal.SIGTERM, e=>{e.Cancel=true;stop.Cancel();})
    : null;
using var healthClient = new HttpClient(new SocketsHttpHandler { UseProxy=false })
    { Timeout=TimeSpan.FromSeconds(1.5) };
async Task ProbeAll(CancellationToken ct)
{
    foreach(var group in groups.Values)
    foreach(var site in group.Sites)
    {
        var healthy=0;
        try
        {
            using var response=await healthClient.GetAsync(site.HealthUrl,
                HttpCompletionOption.ResponseHeadersRead,ct);
            if(response.IsSuccessStatusCode)healthy=1;
        }
        catch(Exception e) when(e is HttpRequestException or TaskCanceledException) { }
        // Probe results pass through bounded hysteresis before publication.
        // A single probe does not flap DNS when thresholds are configured.
        Volatile.Write(ref site.Healthy, site.Health.Observe(healthy == 1) ? 1 : 0);
    }
}
await ProbeAll(stop.Token);
var probes=Task.Run(async()=>{
    try
    {
        while(!stop.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(config.ProbeIntervalSeconds),stop.Token);
            await ProbeAll(stop.Token);
        }
    }
    catch(OperationCanceledException) when(stop.IsCancellationRequested){}
});
using var dnsSocket=new Socket(AddressFamily.InterNetwork,SocketType.Dgram,ProtocolType.Udp);
dnsSocket.Bind(new IPEndPoint(listen,config.ListenPort));
using var tcpListener = new TcpListener(listen, config.ListenPort);
tcpListener.Start(32);
using var tcpSlots = new SemaphoreSlim(32);
var tcpSessions = new List<Task>();
var tcpAccept = Task.Run(async () =>
{
    while (!stop.IsCancellationRequested)
    {
        TcpClient session;
        try { session = await tcpListener.AcceptTcpClientAsync(stop.Token); }
        catch (OperationCanceledException) when (stop.IsCancellationRequested) { break; }
        catch (SocketException) when (stop.IsCancellationRequested) { break; }
        if (!await tcpSlots.WaitAsync(0, stop.Token))
        {
            session.Dispose(); // bounded concurrency, no unbounded pending requests
            continue;
        }
        var task = Task.Run(async () =>
        {
            using (session)
            using (var deadline = CancellationTokenSource.CreateLinkedTokenSource(stop.Token))
            {
                deadline.CancelAfter(TimeSpan.FromSeconds(5));
                try
                {
                    var stream = session.GetStream();
                    var length = new byte[2];
                    await stream.ReadExactlyAsync(length, deadline.Token);
                    var size = BinaryPrimitives.ReadUInt16BigEndian(length);
                    if (size is < 17 or > 4096) return;
                    var packet = new byte[size];
                    await stream.ReadExactlyAsync(packet, deadline.Token);
                    var response = DnsWireProtocol.Build(packet, groups, tcp: true);
                    if (response is null) return;
                    BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)response.Length));
                    await stream.WriteAsync(length, deadline.Token);
                    await stream.WriteAsync(response, deadline.Token);
                }
                catch (Exception ex) when (ex is IOException or SocketException or
                    OperationCanceledException or ObjectDisposedException) { }
                finally { tcpSlots.Release(); }
            }
        });
        lock (tcpSessions)
        {
            tcpSessions.RemoveAll(t => t.IsCompleted);
            tcpSessions.Add(task);
        }
    }
});
Console.WriteLine($"GSLB_DNS_READY UDP+TCP={config.ListenHost}:{config.ListenPort} zones={groups.Count}");
var buffer=new byte[4096];
var responseLimiter=new DnsResponseRateLimiter(config.MaxResponsesPerSecondPerClient);
try
{
    while(!stop.IsCancellationRequested)
    {
        SocketReceiveFromResult received;
        try { received=await dnsSocket.ReceiveFromAsync(buffer,SocketFlags.None,
            new IPEndPoint(IPAddress.Any,0),stop.Token); }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
        catch(SocketException) when(stop.IsCancellationRequested){break;}
        // IP-keyed response budget. Do not echo arbitrary UDP traffic without limits.
        // Loopback is still the required default deployment boundary.
        var source=((IPEndPoint)received.RemoteEndPoint).Address;
        if(!responseLimiter.Allow(source,Environment.TickCount64))continue;
        var response=DnsWireProtocol.Build(buffer.AsSpan(0,received.ReceivedBytes),groups,tcp:false);
        if(response is null)continue;
        try { await dnsSocket.SendToAsync(response,SocketFlags.None,received.RemoteEndPoint,stop.Token); }
        catch(SocketException) when(stop.IsCancellationRequested){break;}
    }
}
finally
{
    stop.Cancel();
    tcpListener.Stop();
    try { await tcpAccept; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
    Task[] pending;
    lock (tcpSessions) pending = tcpSessions.ToArray();
    await Task.WhenAll(pending);
    try { await probes; } catch (OperationCanceledException) when (stop.IsCancellationRequested) { }
}
return 0;

sealed record DnsConfig(bool AllowNonLoopbackListeners,string ListenHost,int ListenPort,
    int ProbeIntervalSeconds,DnsZone[] Zones)
{
    public int MaxResponsesPerSecondPerClient {get;init;} = 500;
}
sealed record DnsZone(string Name,int TtlSeconds,DnsSite[] Sites,
    bool FailClosedWhenAllSitesDown=false)
{
    public DnsNameServerConfig[]? NameServers { get; init; }
    public string? SoaContact { get; init; }
    public uint SoaSerial { get; init; } = 1;
    public string RoutingPolicy { get; init; } = "Weighted";
    public int FailureThreshold { get; init; } = 1;
    public int SuccessThreshold { get; init; } = 1;
}
sealed record DnsNameServerConfig(string Host,string Address);
sealed record DnsNameServer(string Host,IPAddress Address);
sealed record DnsSite(string Address,string HealthUrl,int Weight,int Priority=0);
sealed class Site
{
    public Site(IPAddress address,Uri healthUrl,int weight,int priority,
        int failureThreshold,int successThreshold)
    {
        Address=address;HealthUrl=healthUrl;Weight=weight;Priority=priority;
        Health=new DnsHealthHysteresis(failureThreshold,successThreshold);
    }
    public IPAddress Address {get;}
    public Uri HealthUrl {get;}
    public int Weight {get;}
    public int Priority {get;}
    public DnsHealthHysteresis Health {get;}
    public int Healthy;
}
sealed class SiteGroup
{
    public SiteGroup(Site[] sites,int ttl,bool failClosedWhenAllSitesDown,
        DnsNameServer[] nameServers,string soaContact,uint soaSerial,string routingPolicy)
        =>(Sites,Ttl,FailClosedWhenAllSitesDown,NameServers,SoaContact,SoaSerial,RoutingPolicy)
        =(sites,ttl,failClosedWhenAllSitesDown,nameServers,soaContact,soaSerial,routingPolicy);
    public string RoutingPolicy { get; }
    public DnsNameServer[] NameServers { get; }
    public string SoaContact { get; }
    public uint SoaSerial { get; }
    public bool FailClosedWhenAllSitesDown {get;}
    public Site[] Sites {get;}
    public int Ttl {get;}
    public long Counter=-1;
}