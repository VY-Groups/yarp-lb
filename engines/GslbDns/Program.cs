using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;

// Standalone, NON-recursive authoritative DNS/GSLB prototype. UDP A queries only.
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
        zone.Sites is not {Length: >=1 and <=16})
        throw new InvalidDataException("Invalid GSLB zone or TTL");
    var sites=new List<Site>();
    foreach(var site in zone.Sites)
    {
        if(!IPAddress.TryParse(site.Address,out var address) ||
            address.AddressFamily != AddressFamily.InterNetwork ||
            site.Weight is < 1 or > 100 ||
            !Uri.TryCreate(site.HealthUrl, UriKind.Absolute, out var health) ||
            (health.Scheme != Uri.UriSchemeHttp && health.Scheme != Uri.UriSchemeHttps) ||
            !string.IsNullOrWhiteSpace(health.UserInfo))
            throw new InvalidDataException("Invalid GSLB site address, weight or health probe URL");
        sites.Add(new Site(address,health,site.Weight));
    }
    groups.Add(zone.Name.TrimEnd('.').ToLowerInvariant(), new SiteGroup(sites.ToArray(),zone.TtlSeconds,zone.FailClosedWhenAllSitesDown));
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
        Volatile.Write(ref site.Healthy, healthy);
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
Console.WriteLine($"GSLB_DNS_READY UDP={config.ListenHost}:{config.ListenPort} zones={groups.Count}");
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
        var response=BuildResponse(buffer.AsSpan(0,received.ReceivedBytes),groups);
        if(response is null)continue;
        try { await dnsSocket.SendToAsync(response,SocketFlags.None,received.RemoteEndPoint,stop.Token); }
        catch(SocketException) when(stop.IsCancellationRequested){break;}
    }
}
finally { stop.Cancel();try{await probes;}catch(OperationCanceledException){} }
return 0;

static byte[]? BuildResponse(ReadOnlySpan<byte> query, Dictionary<string, SiteGroup> zones)
{
    if(query.Length<17 || query.Length>1232)return null;
    var id=BinaryPrimitives.ReadUInt16BigEndian(query);
    var flags=BinaryPrimitives.ReadUInt16BigEndian(query[2..]);
    if((flags & 0x8000)!=0)return null; // reject responses
    if(BinaryPrimitives.ReadUInt16BigEndian(query[4..])!=1)return null;
    var pos=12;
    var labels=new List<string>(12);
    while(true)
    {
        if(pos>=query.Length)return null;
        var n=query[pos++];
        if(n==0)break;
        if(n>63 || labels.Count>=32 || pos+n>query.Length)return null; // reject compressed input
        for(var i=pos;i<pos+n;i++)if(query[i]<33 || query[i]>126)return null;
        labels.Add(Encoding.ASCII.GetString(query.Slice(pos,n)));
        pos+=n;
    }
    if(pos+4>query.Length)return null;
    var type=BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos,2));
    var cls=BinaryPrimitives.ReadUInt16BigEndian(query.Slice(pos+2,2));
    pos+=4;
    var domain=string.Join('.',labels).ToLowerInvariant();
    var code=0; // NOERROR, no recursion
    Site? selected=null;
    SiteGroup? group=null;
    if(!zones.TryGetValue(domain,out group))code=5; // REFUSED; never recurse
    else if(cls==1 && type==1)
    {
        var eligible=group.Sites.Where(x=>Volatile.Read(ref x.Healthy)==1).ToArray();
        var total=eligible.Sum(x=>x.Weight);
        if(total==0)
        {
            if(group.FailClosedWhenAllSitesDown)code=2; // explicit strict policy
            else
            {
                // Probe failures may be regional or systemic: retain DNS availability.
                // This is intentionally NOT a claim that any returned site is healthy.
                eligible=group.Sites;
                total=eligible.Sum(x=>x.Weight);
            }
        }
        if(total>0)
        {
            var ticket=(int)(Interlocked.Increment(ref group.Counter) % total);
            foreach(var site in eligible)
            {
                ticket-=site.Weight;
                if(ticket<0){selected=site;break;}
            }
        }
    }
    var hasAnswer=selected is not null;
    var response=new byte[pos+(hasAnswer?16:0)];
    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(0,2),id);
    // QR=1, AA=1, RA=0. RD echoed, remaining flags zero.
    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2,2),(ushort)(0x8400|(flags&0x0100)|code));
    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4,2),1); // question
    BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(6,2),(ushort)(hasAnswer?1:0));
    query.Slice(12,pos-12).CopyTo(response.AsSpan(12));
    if(hasAnswer)
    {
        var ans=response.AsSpan(pos);
        ans[0]=0xc0;ans[1]=0x0c; // pointer to question name
        BinaryPrimitives.WriteUInt16BigEndian(ans.Slice(2,2),1); // A
        BinaryPrimitives.WriteUInt16BigEndian(ans.Slice(4,2),1); // IN
        BinaryPrimitives.WriteUInt32BigEndian(ans.Slice(6,4),(uint)group!.Ttl);
        BinaryPrimitives.WriteUInt16BigEndian(ans.Slice(10,2),4);
        selected!.Address.GetAddressBytes().CopyTo(ans.Slice(12,4));
    }
    return response;
}
sealed record DnsConfig(bool AllowNonLoopbackListeners,string ListenHost,int ListenPort,
    int ProbeIntervalSeconds,DnsZone[] Zones)
{
    public int MaxResponsesPerSecondPerClient {get;init;} = 500;
}
sealed record DnsZone(string Name,int TtlSeconds,DnsSite[] Sites,
    bool FailClosedWhenAllSitesDown=false);
sealed record DnsSite(string Address,string HealthUrl,int Weight);
sealed class Site
{
    public Site(IPAddress address,Uri healthUrl,int weight)=>(Address,HealthUrl,Weight)=(address,healthUrl,weight);
    public IPAddress Address {get;}
    public Uri HealthUrl {get;}
    public int Weight {get;}
    public int Healthy;
}
sealed class SiteGroup
{
    public SiteGroup(Site[] sites,int ttl,bool failClosedWhenAllSitesDown)
        =>(Sites,Ttl,FailClosedWhenAllSitesDown)=(sites,ttl,failClosedWhenAllSitesDown);
    public bool FailClosedWhenAllSitesDown {get;}
    public Site[] Sites {get;}
    public int Ttl {get;}
    public long Counter=-1;
}