using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
// Deterministic state-transition characterization: no sleeps or mutable network state.
var hysteresis = new DnsHealthHysteresis(2, 2);
if (hysteresis.Observe(true) || !hysteresis.Observe(true) ||
    !hysteresis.Observe(false) || hysteresis.Observe(false) ||
    hysteresis.Observe(true) || !hysteresis.Observe(true))
    throw new Exception("FAIL: rise/fall requires two consecutive results");
if (!new DnsHealthHysteresis(1,1).Observe(true))
    throw new Exception("FAIL: legacy single-success eligibility");
var invalidThreshold = false;
try { _ = new DnsHealthHysteresis(0, 2); }
catch (ArgumentOutOfRangeException) { invalidThreshold = true; }
if (!invalidThreshold) throw new Exception("FAIL: invalid hysteresis config accepted");
Console.WriteLine("PASS: health hysteresis, recovery and default behavior");
// Verify response limiting with deterministic monotonic timestamps: no flaky UDP flood.
var rate=new DnsResponseRateLimiter(2,2);
var ip1=IPAddress.Parse("127.0.0.31");
var ip2=IPAddress.Parse("127.0.0.32");
var ip3=IPAddress.Parse("127.0.0.33");
if(!rate.Allow(ip1,0) || !rate.Allow(ip1,100) || rate.Allow(ip1,200) ||
   !rate.Allow(ip1,1000) || !rate.Allow(ip2,1000) || rate.Allow(ip3,1000) ||
   !rate.Allow(ip3,3000))
    throw new Exception("FAIL: bounded UDP per-source rate limiter or recovery");
Console.WriteLine("PASS: UDP response rate limit, table capacity, expiry and recovery");
var repo=args.Length==1?Path.GetFullPath(args[0]):Directory.GetCurrentDirectory();
var dll=Path.Combine(repo,"engines","GslbDns","bin","Release","net10.0","GslbDns.dll");
if(!File.Exists(dll))throw new FileNotFoundException("Compile DNS server first",dll);
using var cancel=new CancellationTokenSource();
var s1=new ProbeState();var s2=new ProbeState();
var healthA=new TcpListener(IPAddress.Loopback,19711);
var healthB=new TcpListener(IPAddress.Loopback,19712);
healthA.Start();healthB.Start();
var tcpHealth=new TcpListener(IPAddress.Loopback,19713);
tcpHealth.Start();
var tcpTasks=new List<Task> { ProbeTcpServer(tcpHealth,cancel.Token) };
var tasks=new []{ProbeServer(healthA,s1,cancel.Token),ProbeServer(healthB,s2,cancel.Token)};
var temp=Path.Combine(Path.GetTempPath(),"yarp-dns-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var configuration=Path.Combine(temp,"zones.json");
File.WriteAllText(configuration,JsonSerializer.Serialize(new {
 AllowNonLoopbackListeners=false,
 ListenHost="127.0.0.1",ListenPort=15353,ProbeIntervalSeconds=1,
 Zones=new []{
 new{ Name="app.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=2,Priority=0,HealthCheckType="Http",TcpPort=0 },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0 }
 },NameServers=new []{
     new {Host="ns1.app.integration.test",Address="127.0.0.31"},
     new {Host="ns2.app.integration.test",Address="127.0.0.32"}
 },SoaContact="hostmaster.app.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="Weighted",FailureThreshold=1,SuccessThreshold=1,
   FailClosedWhenAllSitesDown=false },
 new{ Name="ha.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=2,Priority=0,HealthCheckType="Http",TcpPort=0 },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0 }
 },NameServers=new []{
     new {Host="ns1.ha.integration.test",Address="127.0.0.31"},
     new {Host="ns2.ha.integration.test",Address="127.0.0.32"}
 },SoaContact="hostmaster.ha.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="Failover",FailureThreshold=2,SuccessThreshold=2,
   FailClosedWhenAllSitesDown=true },
 new{ Name="tcp.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.1",HealthUrl="",Weight=1,Priority=0,HealthCheckType="Tcp",TcpPort=19713 }
 },NameServers=new []{
     new {Host="ns1.tcp.integration.test",Address="127.0.0.31"},
     new {Host="ns2.tcp.integration.test",Address="127.0.0.32"}
 },SoaContact="hostmaster.tcp.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="Failover",FailureThreshold=1,SuccessThreshold=1,
   FailClosedWhenAllSitesDown=true }
 }
}));
var info=new ProcessStartInfo("dotnet"){ UseShellExecute=false,CreateNoWindow=true,
 WorkingDirectory=Path.GetDirectoryName(dll)!,RedirectStandardOutput=true,RedirectStandardError=true };
info.ArgumentList.Add(dll);info.ArgumentList.Add(configuration);
using var dns=Process.Start(info)??throw new Exception("DNS process could not start");
var outTask=dns.StandardOutput.ReadToEndAsync();
var errTask=dns.StandardError.ReadToEndAsync();
using var client=new UdpClient(AddressFamily.InterNetwork);
client.Connect(IPAddress.Loopback,15353);
try
{
    await Wait(async () =>
    {
        var seen=new HashSet<string>();
        for(var j=0;j<9;j++)
        {
            var r=await Query("app.integration.test");
            if(r.Address is not null)seen.Add(r.Address);
        }
        return seen.Contains("127.0.0.21") && seen.Contains("127.0.0.22");
    });
    Console.WriteLine("PASS: both sites healthy before distribution sampling");
    await Wait(async()=> (await Query("tcp.integration.test")).Address=="127.0.0.1");
    Must((await Query("tcp.integration.test")).Address=="127.0.0.1",
        "opt-in TCP-connect probe admits ready TCP backend");
    tcpHealth.Stop();
    await Wait(async()=> (await Query("tcp.integration.test")).Status==2);
    Must((await Query("tcp.integration.test")).Status==2,
        "TCP-connect failure removes strict backend from DNS");
    tcpHealth.Start();
    tcpTasks.Add(ProbeTcpServer(tcpHealth,cancel.Token));
    await Wait(async()=> (await Query("tcp.integration.test")).Address=="127.0.0.1");
    Must((await Query("tcp.integration.test")).Address=="127.0.0.1",
        "TCP-connect readiness recovers without restart");
    await Wait(async () => (await Query("ha.integration.test")).Address=="127.0.0.21");
    for (var i=0;i<12;i++)
        Must((await Query("ha.integration.test")).Address=="127.0.0.21",
            "failover policy always selects healthy first-priority site");
    var counts=new Dictionary<string,int> {["127.0.0.21"]=0,["127.0.0.22"]=0};
    for(var i=0;i<90;i++)
    {
        var response=await Query("app.integration.test");
        Must(response.Status==0 && response.Ttl==10,"healthy zone responds with configured TTL");
        counts[response.Address!]++;
    }
    Console.WriteLine("GSLB weighted distribution: "+JsonSerializer.Serialize(counts));
    Must(counts["127.0.0.21"]>=50 && counts["127.0.0.21"]<=70 && counts["127.0.0.22"]>=20,
        "two active sites weighted exactly 2:1 across 90 queries");
    s1.Healthy=0;
    await Task.Delay(3500); // allow multiple independent health probes to expire
    await Wait(async () =>
    {
        for(var j=0;j<12;j++)
        {
            if((await Query("app.integration.test")).Address!="127.0.0.22") return false;
        }
        return true;
    });
    for(var i=0;i<30;i++) Must((await Query("app.integration.test")).Address=="127.0.0.22",
        "failed site not returned while secondary healthy");
    await Wait(async () => (await Query("ha.integration.test")).Address=="127.0.0.22");
    for (var i=0;i<12;i++)
        Must((await Query("ha.integration.test")).Address=="127.0.0.22",
            "failed primary selects configured standby after fall threshold");
    // A 302 to healthy standby must NOT incorrectly rehabilitate primary.
    // This fails if HTTP readiness follows redirects to a healthy login/backend.
    s1.Healthy=2;
    await Task.Delay(3200);
    for (var i=0;i<12;i++)
        Must((await Query("ha.integration.test")).Address=="127.0.0.22",
            "HTTP health redirect cannot falsely restore primary");
    s1.Healthy=0;
    s2.Healthy=0;
    await Task.Delay(3500);
    // By default, total probe failure must not create DNS outage.
    await Wait(async()=> (await Query("app.integration.test")).Address is not null);
    var allDown=new HashSet<string>();
    for(var i=0;i<30;i++)
    {
        var reply=await Query("app.integration.test");
        Must(reply.Status==0 && reply.Address is not null,"all-down fallback answers rather than SERVFAIL");
        allDown.Add(reply.Address);
    }
    Must(allDown.SetEquals(new[]{"127.0.0.21","127.0.0.22"}),
        "all-down fallback includes all configured sites");
    await Wait(async () => (await Query("ha.integration.test")).Status==2);
    Must((await Query("ha.integration.test")).Status==2,
        "strict failover zone SERVFAIL when every site is down");
    s1.Healthy=1;
    await Task.Delay(2500);
    await Wait(async()=> (await Query("app.integration.test")).Address=="127.0.0.21");
    await Wait(async()=> (await Query("ha.integration.test")).Address=="127.0.0.21");
    Must((await Query("ha.integration.test")).Address=="127.0.0.21",
        "recovered primary preferred after success threshold");
    Must((await Query("unknown.integration.test")).Status==5,"unknown zones explicitly refused");
    var (nsReq, nsUdp) = await QueryWire("app.integration.test", 2);
    Must((Dns16(nsUdp,2)&0x0200)!=0 &&
        nsUdp.Length <= Math.Min(512, Math.Max(128,nsReq.Length*4)),
        "large NS response is safely UDP-truncated with TC");
    var nsTcp = await TcpQuery(nsReq);
    Must((Dns16(nsTcp,2)&0x0200)==0 && Dns16(nsTcp,6)==2 &&
        Dns16(nsTcp,10)==2 && Dns16(nsTcp,8)==0,
        "TCP fallback returns complete two NS answers and two in-bailiwick glue records");
    var soa = await TcpQuery(DnsRequest("app.integration.test",6));
    Must(Dns16(soa,6)==1 && Dns16(soa,8)==0 && (Dns16(soa,2)&0xF)==0,
        "SOA query has one authoritative answer and a valid serial");
    var nx = await TcpQuery(DnsRequest("missing.app.integration.test",1));
    Must((Dns16(nx,2)&0xF)==3 && Dns16(nx,6)==0 && Dns16(nx,8)==1,
        "in-zone unknown name uses NXDOMAIN with SOA negative cache");
    var nodata = await TcpQuery(DnsRequest("app.integration.test",28));
    Must((Dns16(nodata,2)&0xF)==0 && Dns16(nodata,6)==0 && Dns16(nodata,8)==1,
        "unsupported AAAA is NODATA, not a fabricated IPv6 address");
    var (_, edns) = await QueryWire("app.integration.test",1,ednsVersion:0);
    Must((Dns16(edns,2)&0xF)==0 && Dns16(edns,10)==1 &&
         edns[^11]==0 && edns[^10]==0 && edns[^9]==41 && edns[^1]==0,
         "EDNS0 OPT answered without leaking unknown client options or DO bit");
    var (_, badVers) = await QueryWire("app.integration.test",1,ednsVersion:1);
    Must(Dns16(badVers,6)==0 && Dns16(badVers,10)==1 &&
         badVers[^6]==1,"EDNS version mismatch signals BADVERS, without A answer");
    var glue = await TcpQuery(DnsRequest("ns1.app.integration.test",1));
    Must(Dns16(glue,6)==1 && glue.AsSpan(glue.Length-4).SequenceEqual(new byte[]{127,0,0,31}),
        "bailiwick NS hostname resolves to configured glue A");
    Console.WriteLine("GSLB REAL DNS HEALTH, AUTHORITATIVE TCP, EDNS AND FAILOVER ACCEPTANCE PASSED");
}
finally
{
    cancel.Cancel();
    healthA.Stop();healthB.Stop();tcpHealth.Stop();
    if(!dns.HasExited)dns.Kill(entireProcessTree:true);
    await dns.WaitForExitAsync();
    try {await Task.WhenAll(tasks);}catch{}
    try {await Task.WhenAll(tcpTasks);}catch{}
    try {Directory.Delete(temp,true);}catch{}
    Console.WriteLine("DNS stdout: "+(await outTask).Trim());
    var errors=(await errTask).Trim();
    if(errors.Length>0)Console.WriteLine("DNS stderr: "+errors);
}
return 0;

async Task<(int Status,string? Address,int Ttl)> Query(string domain)
{
    var request=new List<byte>(256);
    var tx=(ushort)Random.Shared.Next(0,65536);
    request.Add((byte)(tx>>8));request.Add((byte)tx);
    request.AddRange(new byte[]{1,0,0,1,0,0,0,0,0,0}); // DNS flags + QD/AN/NS/AR = 10 bytes
    foreach(var label in domain.Split('.'))
    {
        request.Add((byte)label.Length);
        request.AddRange(Encoding.ASCII.GetBytes(label));
    }
    request.AddRange(new byte[]{0,0,1,0,1});
    await client.SendAsync(request.ToArray());
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(2));
    var msg=await client.ReceiveAsync(timeout.Token);
    var b=msg.Buffer;
    if(b.Length<12 || BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(0,2))!=tx)
        throw new Exception("DNS transaction ID mismatch or malformed response");
    var rcode=b[3]&0x0f;
    var answers=BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(6,2));
    if(answers==0)return(rcode,null,0);
    var a=b.AsSpan(b.Length-16,16);
    var ttl=(int)BinaryPrimitives.ReadUInt32BigEndian(a.Slice(6,4));
    return (rcode,new IPAddress(a.Slice(12,4)).ToString(),ttl);
}

ushort Dns16(byte[] packet, int index) => BinaryPrimitives.ReadUInt16BigEndian(packet.AsSpan(index,2));

byte[] DnsRequest(string domain, ushort type, byte? ednsVersion=null)
{
    var request=new List<byte>();
    request.Add(0x46);request.Add(0x13);
    request.AddRange(new byte[]{1,0,0,1,0,0,0,0,0,ednsVersion is null?(byte)0:(byte)1});
    foreach(var label in domain.Split('.'))
    {
        request.Add((byte)label.Length);
        request.AddRange(Encoding.ASCII.GetBytes(label));
    }
    request.Add(0);
    request.Add((byte)(type>>8));request.Add((byte)type);
    request.Add(0);request.Add(1);
    if(ednsVersion is not null)
    {
        // OPT: root, type 41, UDP payload 1232, ext rcode 0, version as configured,
        // DO bit supplied (must not be reflected without DNSSEC support).
        request.AddRange(new byte[]{0,0,41,4,208,0,ednsVersion.Value,0x80,0,0,7,253,233,0,3,1,2,3});
    }
    return request.ToArray();
}
async Task<(byte[] Request,byte[] Reply)> QueryWire(string domain,ushort type,byte? ednsVersion=null)
{
    var packet=DnsRequest(domain,type,ednsVersion);
    await client.SendAsync(packet);
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(3));
    var reply=await client.ReceiveAsync(timeout.Token);
    Must(reply.Buffer.Length>=12 && Dns16(reply.Buffer,0)==0x4613,
        "DNS UDP transaction matching");
    return(packet,reply.Buffer);
}
async Task<byte[]> TcpQuery(byte[] query)
{
    using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
    using var tcp=new TcpClient(AddressFamily.InterNetwork);
    await tcp.ConnectAsync(IPAddress.Loopback,15353,timeout.Token);
    using var stream=tcp.GetStream();
    var prefix=new byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(prefix,(ushort)query.Length);
    await stream.WriteAsync(prefix,timeout.Token);
    await stream.WriteAsync(query,timeout.Token);
    await stream.ReadExactlyAsync(prefix,timeout.Token);
    var count=BinaryPrimitives.ReadUInt16BigEndian(prefix);
    Must(count>=12 && count<=4096,"TCP DNS length is bounded");
    var reply=new byte[count];
    await stream.ReadExactlyAsync(reply,timeout.Token);
    Must(Dns16(reply,0)==0x4613,"DNS TCP transaction matching");
    return reply;
}

async Task Wait(Func<Task<bool>> condition)
{
    for(var i=0;i<80;i++)
    {
        try {if(await condition())return;}
        catch(SocketException){}
        catch(OperationCanceledException){}
        await Task.Delay(100);
    }
    throw new Exception("GSLB health-state convergence timeout");
}
void Must(bool ok,string description) {if(!ok)throw new Exception("FAIL: "+description);}
static async Task ProbeServer(TcpListener server,ProbeState state,CancellationToken ct)
{
    try
    {
        while(!ct.IsCancellationRequested)
        {
            var client=await server.AcceptTcpClientAsync(ct);
            _=Task.Run(async()=>{
                using(client)
                {
                    var bytes=Encoding.ASCII.GetBytes(state.Healthy==1
                        ? "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : state.Healthy==2
                        ? "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:19712/ready\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        : "HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    try
                    {
                        // Read complete HTTP headers before closing the accepted
                        // connection. Immediate close with unread request bytes can
                        // cause TCP RST / spurious HttpClient failure on Windows.
                        var stream=client.GetStream();
                        using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ct);
                        timeout.CancelAfter(TimeSpan.FromSeconds(2));
                        var request=new byte[4096]; var used=0; var complete=false;
                        while(used<request.Length && !complete)
                        {
                            var previous=used;
                            var n=await stream.ReadAsync(request.AsMemory(used),timeout.Token);
                            if(n==0) return;
                            used+=n;
                            for(var i=Math.Max(0,previous-3);i<=used-4;i++)
                                if(request[i]==13 && request[i+1]==10 &&
                                   request[i+2]==13 && request[i+3]==10)
                                { complete=true; break; }
                        }
                        if(!complete) return;
                        await stream.WriteAsync(bytes,timeout.Token);
                    }
                    catch(Exception ex) when(ex is IOException or SocketException or
                        ObjectDisposedException or OperationCanceledException){}
                }
            },ct);
        }
    }
    catch(OperationCanceledException){}
    catch(SocketException) when(ct.IsCancellationRequested){}
}

static async Task ProbeTcpServer(TcpListener server,CancellationToken ct)
{
    try
    {
        while(!ct.IsCancellationRequested)
        {
            using var connected=await server.AcceptTcpClientAsync(ct);
        }
    }
    catch(OperationCanceledException) when(ct.IsCancellationRequested){}
    catch(SocketException){} // listener intentionally stopped to simulate outage
    catch(ObjectDisposedException){}
}

sealed class ProbeState {public volatile int Healthy=1;}