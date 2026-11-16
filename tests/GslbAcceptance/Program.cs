using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
LatencyRoutingTests.Run();
// Exercise opt-in probe-latency state with deterministic monotonic timestamps.
var latency = new DnsProbeLatency();
latency.ObserveSuccess(TimeSpan.FromMilliseconds(40), 1000);
latency.ObserveSuccess(TimeSpan.FromMilliseconds(20), 2000);
if (latency.TryRead(2000,3,15000,out _))
    throw new Exception("FAIL: insufficient latency samples admitted");
latency.ObserveSuccess(TimeSpan.FromMilliseconds(10), 3000);
if (!latency.TryRead(3000,3,15000,out var ewma) ||
    Math.Abs(ewma - 28.75) > 0.001)
    throw new Exception("FAIL: observed latency EWMA wrong");
if (latency.TryRead(18001,3,15000,out _) ||
    latency.TryRead(2999,3,15000,out _))
    throw new Exception("FAIL: expired or clock-rolled-back latency admitted");
latency.ObserveFailure();
if (latency.TryRead(3001,3,15000,out _))
    throw new Exception("FAIL: failed probe must invalidate old latency");
latency.ObserveSuccess(TimeSpan.FromMilliseconds(60), 4000);
if (latency.TryRead(4000,3,15000,out _))
    throw new Exception("FAIL: recovered backend requires new sample floor");
Console.WriteLine("PASS: observed latency EWMA, sample floor, expiry and failover invalidation");
// Deterministic state-transition characterization: no sleeps or mutable network state.
var hysteresis = new DnsHealthHysteresis(2, 2);
if (hysteresis.Observe(true) || !hysteresis.Observe(true) ||
    !hysteresis.Observe(false) || hysteresis.Observe(false) ||
    hysteresis.Observe(true) || !hysteresis.Observe(true))
    throw new Exception("FAIL: rise/fall requires two consecutive results");
if (!new DnsHealthHysteresis(1,1).Observe(true))
    throw new Exception("FAIL: legacy single-success eligibility");
hysteresis.Invalidate();
if (hysteresis.IsHealthy || hysteresis.Observe(true) || !hysteresis.Observe(true))
    throw new Exception("FAIL: withdrawn authority requires the full recovery threshold");
hysteresis.Invalidate();
hysteresis.Observe(true);
hysteresis.Invalidate();
if (hysteresis.Observe(true))
    throw new Exception("FAIL: expiry during recovery discards partial rise evidence");
var invalidThreshold = false;
try { _ = new DnsHealthHysteresis(0, 2); }
catch (ArgumentOutOfRangeException) { invalidThreshold = true; }
if (!invalidThreshold) throw new Exception("FAIL: invalid hysteresis config accepted");
Console.WriteLine("PASS: health hysteresis, recovery and default behavior");
// Prove max in-flight health checks and eventual completion without timing races.
var releaseChecks = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var twoChecksRunning = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
var startedChecks=0; var activeChecks=0; var maxChecks=0; var completedChecks=0;
var checksGate=new object();
var probeBatch=BoundedDnsProbes.RunAsync(Enumerable.Range(0,6),2,async (_,ct)=>
{
    var active=Interlocked.Increment(ref activeChecks);
    lock(checksGate) maxChecks=Math.Max(maxChecks,active);
    if(Interlocked.Increment(ref startedChecks)==2) twoChecksRunning.TrySetResult();
    try { await releaseChecks.Task.WaitAsync(ct); }
    finally
    {
        Interlocked.Decrement(ref activeChecks);
        Interlocked.Increment(ref completedChecks);
    }
},CancellationToken.None);
try
{
    await twoChecksRunning.Task.WaitAsync(TimeSpan.FromSeconds(10));
    if(startedChecks!=2 || maxChecks!=2)
        throw new Exception("FAIL: DNS probe concurrency exceeded configured cap");
}
finally {releaseChecks.TrySetResult();}
await probeBatch;
if(startedChecks!=6 || completedChecks!=6 || maxChecks!=2 || activeChecks!=0)
    throw new Exception("FAIL: bounded DNS probe batch did not drain and finish all sites");
var invalidParallelism=false;
try
{
    await BoundedDnsProbes.RunAsync(Array.Empty<int>(),0,
        (_,__)=>ValueTask.CompletedTask,CancellationToken.None);
}
catch(ArgumentOutOfRangeException){invalidParallelism=true;}
if(!invalidParallelism) throw new Exception("FAIL: unsafe DNS probe concurrency accepted");
Console.WriteLine("PASS: DNS health probe concurrency hard cap, drain and validation");
var cidrTable = new DnsCidrRegionTable(new[]{
    new DnsCidrRegionRule("127.0.0.0/8","regional"),
    new DnsCidrRegionRule("127.0.0.1/32","local"),
    new DnsCidrRegionRule("2001:db8::/32","ipv6")
});
if(cidrTable.RegionFor(IPAddress.Parse("127.0.0.1"))!="local" ||
   cidrTable.RegionFor(IPAddress.Parse("127.0.0.7"))!="regional" ||
   cidrTable.RegionFor(IPAddress.Parse("2001:db8::beef"))!="ipv6" ||
   cidrTable.RegionFor(IPAddress.Parse("203.0.113.2")) is not null ||
   cidrTable.RegionFor(IPAddress.Parse("127.0.0.1").MapToIPv6())!="local")
    throw new Exception("FAIL: canonical longest-prefix region selection");
foreach(var bad in new[]{"127.0.0.9/24","127.0.0.0/33","not-an-address",
                        "2001:db8::1/32"})
{
    var rejected=false;
    try { _=new DnsCidrRegionTable(new[]{new DnsCidrRegionRule(bad,"local")}); }
    catch(ArgumentException){rejected=true;}
    if(!rejected)throw new Exception("FAIL: malformed or noncanonical CIDR accepted: "+bad);
}
var duplicateRejected=false;
try { _=new DnsCidrRegionTable(new[]{
    new DnsCidrRegionRule("127.0.0.0/8","local"),
    new DnsCidrRegionRule("127.0.0.0/8","other")}); }
catch(ArgumentException){duplicateRejected=true;}
if(!duplicateRejected)throw new Exception("FAIL: conflicting duplicate CIDR accepted");
Console.WriteLine("PASS: IPv4/IPv6 longest prefix, resolver-IP mapping and CIDR validation");
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
var s1=new ProbeState { DelayMs=180 };var s2=new ProbeState();var s3=new ProbeState();
var healthA=new TcpListener(IPAddress.Loopback,19711);
var healthB=new TcpListener(IPAddress.Loopback,19712);
var healthC=new TcpListener(IPAddress.Loopback,19714);
healthA.Start();healthB.Start();healthC.Start();
var tcpHealth=new TcpListener(IPAddress.Loopback,19713);
tcpHealth.Start();
// TCP readiness probes connect to the advertised address (unlike HTTP URLs).
// Bind each disposable loopback backend to its actual advertised address.
var chainTcpA=new TcpListener(IPAddress.Parse("127.0.0.43"),19713);
var chainTcpB=new TcpListener(IPAddress.Parse("127.0.0.44"),19713);
chainTcpA.Start();chainTcpB.Start();
var tcpTasks=new List<Task> { ProbeTcpServer(tcpHealth,cancel.Token),
    ProbeTcpServer(chainTcpA,cancel.Token),ProbeTcpServer(chainTcpB,cancel.Token) };
var tasks=new []{ProbeServer(healthA,s1,cancel.Token),ProbeServer(healthB,s2,cancel.Token),
    ProbeServer(healthC,s3,cancel.Token)};
var temp=Path.Combine(Path.GetTempPath(),"yarp-dns-"+Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temp);
var configuration=Path.Combine(temp,"zones.json");
// Three independently probed priority groups; IPv6 has a separate pool.
var chainSites=new[]{
    new {Address="127.0.0.41",HealthUrl="http://127.0.0.1:19711/ready",Weight=2,Priority=0,HealthCheckType="Http",TcpPort=0},
    new {Address="127.0.0.42",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0},
    new {Address="127.0.0.43",HealthUrl="",Weight=1,Priority=10,HealthCheckType="Tcp",TcpPort=19713},
    new {Address="127.0.0.44",HealthUrl="",Weight=3,Priority=10,HealthCheckType="Tcp",TcpPort=19713},
    new {Address="127.0.0.45",HealthUrl="http://127.0.0.1:19714/ready",Weight=1,Priority=20,HealthCheckType="Http",TcpPort=0},
    new {Address="2001:db8::41",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0}
};
File.WriteAllText(configuration,JsonSerializer.Serialize(new {
 AllowNonLoopbackListeners=false,
 ListenHost="127.0.0.1",ListenPort=15353,ProbeIntervalSeconds=1,
 Zones=new object[]{
 new {Name="chain.integration.test",TtlSeconds=10,Sites=chainSites,
      NameServers=new[]{new {Host="ns.chain.integration.test",Address="127.0.0.31"}},
      RoutingPolicy="WeightedFailover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=true},
 new {Name="chain-open.integration.test",TtlSeconds=10,Sites=chainSites,
      RoutingPolicy="WeightedFailover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=false},
 new{ Name="app.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=2,Priority=0,HealthCheckType="Http",TcpPort=0 },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0 },
    new { Address="2001:db8::99",HealthUrl="http://127.0.0.1:19711/ready",Weight=1,Priority=20,HealthCheckType="Http",TcpPort=0 }
 },NameServers=new []{
     new {Host="ns1.app.integration.test",Address="127.0.0.31"},
     new {Host="ns2.edge.app.integration.test",Address="127.0.0.32"}
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
   FailClosedWhenAllSitesDown=true },
 new{ Name="geo.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",
          Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0,Region="local" },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",
          Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0,Region="dr" }
 },NameServers=new []{
     new {Host="ns1.geo.integration.test",Address="127.0.0.31"},
     new {Host="ns2.geo.integration.test",Address="127.0.0.32"}
 },SoaContact="hostmaster.geo.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="CidrRegion",FailureThreshold=1,SuccessThreshold=1,
   FailClosedWhenAllSitesDown=true,
   CidrRoutes=new[]{
       new {Cidr="127.0.0.0/8",Region="dr"},
       new {Cidr="127.0.0.1/32",Region="local"}
   }},
 new{ Name="latency.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",
          Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0 },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",
          Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0 }
 },NameServers=new []{
     new {Host="ns1.latency.integration.test",Address="127.0.0.31"},
     new {Host="ns2.latency.integration.test",Address="127.0.0.32"}
 },SoaContact="hostmaster.latency.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="ObservedLatency",FailureThreshold=1,SuccessThreshold=1,
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
        if(dns.HasExited) throw new Exception("DNS exited before readiness: "+await errTask);
        var seen=new HashSet<string>();
        for(var j=0;j<9;j++)
        {
            var r=await Query("app.integration.test");
            if(r.Address is not null)seen.Add(r.Address);
        }
        return seen.Contains("127.0.0.21") && seen.Contains("127.0.0.22");
    });
    Console.WriteLine("PASS: both IPv4 sites healthy before distribution sampling");
    // The policy deliberately falls back to weighted while samples accumulate.
    // Wait for three independently scheduled one-second probe cycles before
    // asserting a deterministic winner; a single weighted reply is not proof.
    await Task.Delay(4200);
    await Wait(async()=> (await Query("latency.integration.test")).Address=="127.0.0.22");
    for(var i=0;i<12;i++)
        Must((await Query("latency.integration.test")).Address=="127.0.0.22",
            "locally faster probe endpoint wins only after sample floor");

    // Remove the measured winner, then prove real DNS chooses the slower
    // healthy backend; restore it and wait for a stable measured winner.
    s2.Healthy=0;
    await Wait(async()=> (await Query("latency.integration.test")).Address=="127.0.0.21");
    for(var i=0;i<12;i++)
        Must((await Query("latency.integration.test")).Address=="127.0.0.21",
            "failed faster endpoint must not win based on old latency");
    s2.Healthy=1;
    await Wait(async()=>{
        for(var i=0;i<12;i++)
            if((await Query("latency.integration.test")).Address!="127.0.0.22")return false;
        return true;
    });
    // An NS address below edge makes edge an empty non-terminal, not a missing
    // subtree (RFC 8020 section 3.1). Test both transports and several QTYPEs.
    foreach (var type in new ushort[] { 1, 28, 2, 16 })
    {
        var (_, entUdp) = await QueryWire("edge.app.integration.test", type);
        var entTcp = await TcpQuery(DnsRequest("edge.app.integration.test", type));
        foreach (var packet in new[] { entUdp, entTcp })
            Must((Dns16(packet,2)&0x040F)==0x0400 &&
                Dns16(packet,6)==0 && Dns16(packet,8)==1,
                "empty non-terminal is authoritative NODATA with negative SOA");
    }
    var nestedNs = await TcpQuery(DnsRequest("ns2.edge.app.integration.test",1));
    Must(Dns16(nestedNs,6)==1 &&
         nestedNs.AsSpan(nestedNs.Length-4).SequenceEqual(new byte[]{127,0,0,32}),
         "descendant NS address remains resolvable after empty-parent queries");
    foreach (var missing in new[] { "xedge.app.integration.test",
                                  "missing.edge.app.integration.test" })
    {
        var packet = await TcpQuery(DnsRequest(missing,1));
        Must((Dns16(packet,2)&0x040F)==0x0403 &&
             Dns16(packet,6)==0 && Dns16(packet,8)==1,
             "absent sibling or descendant remains authoritative NXDOMAIN");
    }
    Console.WriteLine("PASS: empty non-terminal NODATA, descendant address and true NXDOMAIN");
    await Wait(async () => {
        var seen=new HashSet<string>();
        for(var i=0;i<6;i++) {
            var reply=await Query("chain.integration.test");
            if(reply.Address is not null) seen.Add(reply.Address);
        }
        return seen.SetEquals(new[]{"127.0.0.41","127.0.0.42"});
    });
    await CheckChainWeights("chain.integration.test",90,"127.0.0.41",60,"127.0.0.42",30);
    var chainV6=await TcpQuery(DnsRequest("chain.integration.test",28));
    Must(Dns16(chainV6,6)==1 &&
         chainV6.AsSpan(chainV6.Length-16).SequenceEqual(IPAddress.Parse("2001:db8::41").GetAddressBytes()),
         "IPv6 priority pool is independent of better-priority IPv4 sites");

    await Wait(async()=> (await Query("geo.integration.test")).Address=="127.0.0.21");
    var geoTcp=await TcpQuery(DnsRequest("geo.integration.test",1));
    Must(Dns16(geoTcp,6)==1 &&
         geoTcp.AsSpan(geoTcp.Length-4,4).SequenceEqual(new byte[]{127,0,0,21}),
         "TCP queries use actual resolver source IP for CIDR region");
    for(var i=0;i<12;i++)
        Must((await Query("geo.integration.test")).Address=="127.0.0.21",
            "IPv4 resolver /32 specific region beats broader /8 mapping");
    var aaaa = await TcpQuery(DnsRequest("app.integration.test",28));
    Must((Dns16(aaaa,2)&0x0F)==0 && Dns16(aaaa,6)==1 &&
         Dns16(aaaa,aaaa.Length-18)==16 &&
         aaaa.AsSpan(aaaa.Length-16,16).SequenceEqual(IPAddress.Parse("2001:db8::99").GetAddressBytes()),
         "health-aware AAAA returns configured IPv6 address with 16-byte RDATA");
    var aaaUdp = await QueryWire("app.integration.test",28);
    Must(Dns16(aaaUdp.Reply,6)==1 && (Dns16(aaaUdp.Reply,2)&0x0F)==0 &&
        aaaUdp.Reply.AsSpan(aaaUdp.Reply.Length-16).SequenceEqual(IPAddress.Parse("2001:db8::99").GetAddressBytes()),
        "UDP AAAA record is valid and family-correct");
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
    await Wait(async()=> (await Query("geo.integration.test")).Address=="127.0.0.22");
    Must((await Query("geo.integration.test")).Address=="127.0.0.22",
        "no healthy preferred-region site falls back to healthy DR region");
    await Wait(async()=> (await Query("chain.integration.test")).Address=="127.0.0.42");
    for(var i=0;i<12;i++)
        Must((await Query("chain.integration.test")).Address=="127.0.0.42",
            "partial primary group failure does not spill into backup groups");
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
    await Wait(async()=> (await Query("latency.integration.test")).Status==2);
    Must((await Query("latency.integration.test")).Status==2,
        "strict observed-latency zone SERVFAIL when every site is down");
    await Wait(async()=> (await Query("geo.integration.test")).Status==2);
    Must((await Query("geo.integration.test")).Status==2,
        "strict CIDR region zone returns SERVFAIL when all sites down");
    await CheckChainWeights("chain.integration.test",40,"127.0.0.43",10,"127.0.0.44",30);
    chainTcpA.Stop();chainTcpB.Stop();
    await Wait(async()=> (await Query("chain.integration.test")).Address=="127.0.0.45");
    for(var i=0;i<12;i++)
        Must((await Query("chain.integration.test")).Address=="127.0.0.45",
            "second failed group advances to healthy tertiary only");
    s3.Healthy=0;
    await Wait(async()=> (await Query("chain.integration.test")).Status==2);
    Must((await Query("chain.integration.test")).Status==2,
         "strict weighted chain returns SERVFAIL after all groups fail");
    await CheckChainWeights("chain-open.integration.test",90,"127.0.0.41",60,"127.0.0.42",30);
    Console.WriteLine("PASS: weighted priority groups, partial outage, tertiary and all-down policies");
    s1.Healthy=1;
    await Task.Delay(2500);
    await Wait(async()=> (await Query("app.integration.test")).Address=="127.0.0.21");
    await Wait(async()=> (await Query("ha.integration.test")).Address=="127.0.0.21");
    Must((await Query("ha.integration.test")).Address=="127.0.0.21",
        "recovered primary preferred after success threshold");
    await Wait(async()=> (await Query("latency.integration.test")).Address=="127.0.0.21");
    Must((await Query("latency.integration.test")).Address=="127.0.0.21",
        "sole recovered slow backend is eligible without stale fast-site data");
    await Wait(async()=> (await Query("chain.integration.test")).Address=="127.0.0.41");
    for(var i=0;i<12;i++)
        Must((await Query("chain.integration.test")).Address=="127.0.0.41",
            "recovered primary preempts failed backup groups without restart");

    await Wait(async()=> (await Query("geo.integration.test")).Address=="127.0.0.21");
    Must((await Query("geo.integration.test")).Address=="127.0.0.21",
        "recovered preferred-region site selected again");
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
    var nodata = await TcpQuery(DnsRequest("ha.integration.test",28));
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
    healthA.Stop();healthB.Stop();healthC.Stop();tcpHealth.Stop();
    chainTcpA.Stop();chainTcpB.Stop();
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

async Task CheckChainWeights(string zone,int queries,string first,int firstCount,string second,int secondCount)
{
    var counts=new Dictionary<string,int>{{first,0},{second,0}};
    for(var i=0;i<queries;i++)
    {
        var response=await Query(zone);
        Must(response.Status==0 && response.Ttl==10 &&
             response.Address is not null && counts.ContainsKey(response.Address),
             "weighted chain answers only from selected priority group with original TTL");
        counts[response.Address!]++;
    }
    Must(counts[first]==firstCount && counts[second]==secondCount,
         "weighted chain preserves exact proportional distribution within selected group");
}
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
                        var delay=Volatile.Read(ref state.DelayMs);
                        if(delay>0) await Task.Delay(delay,timeout.Token);
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

sealed class ProbeState {public volatile int Healthy=1;public int DelayMs;}