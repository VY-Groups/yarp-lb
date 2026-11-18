using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.AccessControl;
using System.Security.Principal;
using GatewayCore.Gslb.Contracts;

// A malformed, altered or overlong report must never verify as signed agent evidence.
using (var agentKey = ECDsa.Create(ECCurve.NamedCurves.nistP256))
using (var verifierKey = ECDsa.Create(agentKey.ExportParameters(false)))
{
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    var unsigned = new AgentHealthReport(1, "region-agent-1", AgentHealthReportContract.KeyId(agentKey), "lab.example.test.",
        "mumbai", 4, 19, now, now + 10, "http", "healthy", 1000, 41, "pending");
    var signed = unsigned with { Signature = AgentHealthReportContract.Sign(unsigned, agentKey) };
    if (!AgentHealthReportContract.Verify(signed, verifierKey, 10))
        throw new Exception("FAIL: valid signed agent health report rejected");
    if (AgentHealthReportContract.Verify(signed with { Verdict = "unhealthy", LatencyMilliseconds = null }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { KeyId = new string('0', 64) }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { SiteId = "osaka" }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { Sequence = 20 }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { ExpiresAtUnixSeconds = now + 11 }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { AgentId = "../agent" }, verifierKey, 10) ||
        AgentHealthReportContract.Verify(signed with { Version = 2 }, verifierKey, 10))
        throw new Exception("FAIL: altered, stale-contract or overlong agent report accepted");
    var unsignedFailure = unsigned with { Verdict = "unhealthy", LatencyMilliseconds = null };
    var failure = unsignedFailure with { Signature = AgentHealthReportContract.Sign(unsignedFailure, agentKey) };
    if (!AgentHealthReportContract.Verify(failure, verifierKey, 10))
        throw new Exception("FAIL: signed negative health evidence rejected");
    var unknown = unsigned with { Verdict = "unknown", ConfidencePermille = 0, LatencyMilliseconds = null };
    unknown = unknown with { Signature = AgentHealthReportContract.Sign(unknown, agentKey) };
    if (!AgentHealthReportContract.Verify(unknown, verifierKey, 10) ||
        AgentHealthReportContract.IsValid(unknown with { ConfidencePermille = 1 }, 10))
        throw new Exception("FAIL: explicit unknown health evidence or confidence bounds invalid");
}
Console.WriteLine("PASS: signed agent health report schema, canonical signature and tamper rejection");
var reportRoot = Path.Combine(Path.GetTempPath(), "gslb-agent-contract-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(reportRoot);
if (!OperatingSystem.IsWindows())
    File.SetUnixFileMode(reportRoot, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
else
{
    var identity = WindowsIdentity.GetCurrent().User
        ?? throw new InvalidOperationException("Windows test identity has no SID");
    var security = new DirectoryInfo(reportRoot).GetAccessControl();
    security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
    security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None, AccessControlType.Allow));
    security.AddAccessRule(new FileSystemAccessRule(
        new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None, AccessControlType.Allow));
    security.AddAccessRule(new FileSystemAccessRule(
        new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
        PropagationFlags.None, AccessControlType.Allow));
    new DirectoryInfo(reportRoot).SetAccessControl(security);
}
try
{
    using var signing1 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var signing1Rotated = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var signing2 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var signing3 = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var client1Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var client1RotatedKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var client2Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    using var client3Key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    var client1Request = new CertificateRequest("CN=agent-1", client1Key, HashAlgorithmName.SHA256);
    var client1RotatedRequest = new CertificateRequest("CN=agent-1-rotated", client1RotatedKey, HashAlgorithmName.SHA256);
    var client2Request = new CertificateRequest("CN=agent-2", client2Key, HashAlgorithmName.SHA256);
    var client3Request = new CertificateRequest("CN=agent-3", client3Key, HashAlgorithmName.SHA256);
    foreach (var request in new[] { client1Request, client1RotatedRequest, client2Request, client3Request })
    {
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var eku = new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") };
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
    }
    using var client1 = client1Request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    using var client1Rotated = client1RotatedRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    using var client2 = client2Request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    using var client3 = client3Request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddHours(1));
    var key1Path = Path.Combine(reportRoot, "agent-1.pem");
    var key1RotatedPath = Path.Combine(reportRoot, "agent-1-rotated.pem");
    var key2Path = Path.Combine(reportRoot, "agent-2.pem");
    var key3Path = Path.Combine(reportRoot, "agent-3.pem");
    File.WriteAllText(key1Path, signing1.ExportSubjectPublicKeyInfoPem());
    File.WriteAllText(key1RotatedPath, signing1Rotated.ExportSubjectPublicKeyInfoPem());
    File.WriteAllText(key2Path, signing2.ExportSubjectPublicKeyInfoPem());
    File.WriteAllText(key3Path, signing3.ExportSubjectPublicKeyInfoPem());
    var agents = new[] {
        new AgentTrust("agent-1", "vantage-mumbai", [Convert.ToHexString(client1.GetCertHash(HashAlgorithmName.SHA256)),
            Convert.ToHexString(client1Rotated.GetCertHash(HashAlgorithmName.SHA256))], [key1Path, key1RotatedPath]),
        new AgentTrust("agent-2", "vantage-osaka", [Convert.ToHexString(client2.GetCertHash(HashAlgorithmName.SHA256))], [key2Path]),
        new AgentTrust("agent-3", "vantage-singapore", [Convert.ToHexString(client3.GetCertHash(HashAlgorithmName.SHA256))], [key3Path])
    };
    var targets = new[] { new AgentReportTarget("lab.example.test", "mumbai",
        ["agent-1", "agent-2", "agent-3"], MinimumHealthyVantageGroups: 2) };
    var statePath = Path.Combine(reportRoot, "replay-state.json");
    if (OperatingSystem.IsWindows())
    {
        var broadAclDirectory = Path.Combine(reportRoot, "broad-replay-acl");
        Directory.CreateDirectory(broadAclDirectory);
        var security = new DirectoryInfo(broadAclDirectory).GetAccessControl();
        var everyone = new SecurityIdentifier(WellKnownSidType.WorldSid, null);
        security.AddAccessRule(new FileSystemAccessRule(everyone,
            FileSystemRights.Modify | FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(broadAclDirectory).SetAccessControl(security);
        var broadAclRejected = false;
        try
        {
            using var invalidReports = new AgentHealthReportStore(agents, targets,
                Path.Combine(broadAclDirectory, "replay-state.json"), 10, 5, 2);
        }
        catch (InvalidDataException) { broadAclRejected = true; }
        if (!broadAclRejected)
            throw new Exception("FAIL: Windows replay-state directory with Everyone access was accepted");
        Console.WriteLine("PASS: broadly accessible Windows replay-state ACL rejected");

        using var testIdentity = WindowsIdentity.GetCurrent();
        var trustedPrincipals = AgentHealthReportStore.AllowedWindowsPrincipals(testIdentity);
        if (!AgentHealthReportStore.IsAllowedWindowsOwner(testIdentity.User, trustedPrincipals) ||
            AgentHealthReportStore.IsAllowedWindowsOwner(
                new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null), trustedPrincipals) ||
            !AgentHealthReportStore.IsWindowsServiceSid(new SecurityIdentifier("S-1-5-80-1-2-3-4-5")))
            throw new Exception("FAIL: Windows replay-state owner/service SID trust policy is incorrect");
        Console.WriteLine("PASS: untrusted Windows replay-state owner rejected");

        var serviceSid = testIdentity.Groups?.Cast<IdentityReference>().OfType<SecurityIdentifier>()
            .FirstOrDefault(AgentHealthReportStore.IsWindowsServiceSid);
        if (serviceSid is not null)
        {
            var serviceSidDirectory = Path.Combine(reportRoot, "service-sid-replay-state");
            Directory.CreateDirectory(serviceSidDirectory);
            var serviceSidSecurity = new DirectoryInfo(serviceSidDirectory).GetAccessControl();
            serviceSidSecurity.AddAccessRule(new FileSystemAccessRule(serviceSid,
                FileSystemRights.Modify | FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(serviceSidDirectory).SetAccessControl(serviceSidSecurity);
            using var serviceSidReports = new AgentHealthReportStore(agents, targets,
                Path.Combine(serviceSidDirectory, "replay-state.json"), 10, 5, 2);
            Console.WriteLine("PASS: current Windows service SID is allowed by replay-state ACL policy");
        }
    }
    var duplicateVantageRejected = false;
    try
    {
        using var invalidReports = new AgentHealthReportStore(
            [agents[0], agents[1] with { VantageGroup = agents[0].VantageGroup }],
            [new AgentReportTarget("lab.example.test", "duplicate-vantage", ["agent-1", "agent-2"], 2)],
            Path.Combine(reportRoot, "duplicate-vantage-state.json"), 10, 5, 2);
    }
    catch (InvalidDataException) { duplicateVantageRejected = true; }
    if (!duplicateVantageRejected)
        throw new Exception("FAIL: two agent identities from the same declared vantage group were counted as independent votes");
    var observed = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    AgentHealthReport Report(string agent, long sequence, string verdict, int confidence, int? latency, ECDsa signer) {
        var unsigned = new AgentHealthReport(1, agent, AgentHealthReportContract.KeyId(signer),
            "lab.example.test", "mumbai", 3,
            sequence, observed, observed + 10, "http", verdict, confidence, latency, "pending");
        return unsigned with { Signature = AgentHealthReportContract.Sign(unsigned, signer) };
    }
    using (var reports = new AgentHealthReportStore(agents, targets, statePath, 10, 5, 2))
    {
        if (!reports.TryReserveRequest("agent-1", 100, 1) ||
            reports.TryReserveRequest("agent-1", 101, 1) ||
            !reports.TryReserveRequest("agent-1", 60_100, 1))
            throw new Exception("FAIL: authenticated per-agent request budget is not bounded");
        if (reports.IsHealthy("lab.example.test", "mumbai", 100))
            throw new Exception("FAIL: missing multi-vantage evidence admitted a target");
        if (!reports.TryAccept(Report("agent-1", 1, "healthy", 1000, 12, signing1), client1,
                DateTimeOffset.FromUnixTimeSeconds(observed), 100) ||
            reports.IsHealthy("lab.example.test", "mumbai", 101))
            throw new Exception("FAIL: one vantage group satisfied a two-group threshold");
        if (!reports.TryAccept(Report("agent-2", 1, "healthy", 1000, 20, signing2), client2,
                DateTimeOffset.FromUnixTimeSeconds(observed), 100) ||
            !reports.IsHealthy("lab.example.test", "mumbai", 101))
            throw new Exception("FAIL: two fresh independent reports did not satisfy 2-of-3 policy");
        var unknown = Report("agent-3", 1, "unknown", 0, null, signing3);
        if (!reports.TryAccept(unknown, client3, DateTimeOffset.FromUnixTimeSeconds(observed), 100) ||
            !reports.IsHealthy("lab.example.test", "mumbai", 101))
            throw new Exception("FAIL: unknown evidence incorrectly counted as a negative quorum vote");
        if (reports.TryAccept(Report("agent-1", 1, "healthy", 1000, 12, signing1), client1,
                DateTimeOffset.FromUnixTimeSeconds(observed), 100) ||
            reports.TryAccept(Report("agent-1", 2, "healthy", 1000, 12, signing1), client2,
                DateTimeOffset.FromUnixTimeSeconds(observed), 100))
            throw new Exception("FAIL: replay or certificate/report identity mismatch accepted");
        if (!reports.TryAccept(Report("agent-3", 2, "unhealthy", 1000, null, signing3), client3,
                DateTimeOffset.FromUnixTimeSeconds(observed), 100) ||
            reports.IsHealthy("lab.example.test", "mumbai", 101))
            throw new Exception("FAIL: fresh negative evidence did not veto positive quorum reports");
    }
    using (var recovered = new AgentHealthReportStore(agents, targets, statePath, 10, 5, 2))
    {
        if (recovered.IsHealthy("lab.example.test", "mumbai", 101) ||
            recovered.TryAccept(Report("agent-1", 1, "healthy", 1000, 12, signing1), client1,
                DateTimeOffset.FromUnixTimeSeconds(observed), 101) ||
            !recovered.TryAccept(Report("agent-1", 2, "healthy", 1000, 12, signing1), client1,
                DateTimeOffset.FromUnixTimeSeconds(observed), 101) ||
            !recovered.TryAccept(Report("agent-2", 2, "healthy", 1000, 20, signing2), client2,
                DateTimeOffset.FromUnixTimeSeconds(observed), 101) ||
            !recovered.IsHealthy("lab.example.test", "mumbai", 102) ||
            recovered.IsHealthy("lab.example.test", "mumbai", 10_101))
            throw new Exception("FAIL: replay protection or monotonic expiry failed across restart");
        if (recovered.TryAccept(Report("agent-2", 3, "healthy", 1000, 20, signing2), client2,
                DateTimeOffset.FromUnixTimeSeconds(observed + 6), 103))
            throw new Exception("FAIL: stale observer report accepted");
        if (!recovered.TryAccept(Report("agent-1", 3, "healthy", 1000, 14, signing1Rotated), client1Rotated,
                DateTimeOffset.FromUnixTimeSeconds(observed), 104))
            throw new Exception("FAIL: overlapping client certificate and signing-key rotation rejected");
    }
}
finally { Directory.Delete(reportRoot, recursive: true); }
Console.WriteLine("PASS: agent identity, 2-of-3 vantage quorum, negative veto, replay persistence, expiry and recovery");
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
var ecsTable = new DnsCidrRegionTable(new[] {
    new DnsCidrRegionRule("198.51.100.0/24", "dr"),
    new DnsCidrRegionRule("198.51.100.128/25", "local")
});
if (ecsTable.RegionForEcs(IPAddress.Parse("198.51.100.42"), 24) is not null ||
    ecsTable.RegionForEcs(IPAddress.Parse("198.51.100.200"), 25) is not
        { Region: "local", PrefixLength: 25 })
    throw new Exception("FAIL: ECS crossed a more-specific region boundary");
var simpleEcsTable = new DnsCidrRegionTable(new[] {
    new DnsCidrRegionRule("198.51.100.0/24", "dr")
});
if (simpleEcsTable.RegionForEcs(IPAddress.Parse("198.51.100.42"), 24) is not
    { Region: "dr", PrefixLength: 24 })
    throw new Exception("FAIL: ECS network was not normalized before region matching");
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
Console.WriteLine("PASS: IPv4/IPv6 resolver CIDR mapping, ECS prefix boundaries and validation");
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
var countryFixture = Path.Combine(repo, "tests", "GslbAcceptance", "testdata", "GeoIP2-Country-Test.mmdb");
var asnFixture = Path.Combine(repo, "tests", "GslbAcceptance", "testdata", "GeoLite2-ASN-Test.mmdb");
if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(countryFixture))) !=
        "FC12D6470B35B70BD3E4534DD433D3E262A6C73F7682F85C344E832D4190F02B" ||
    Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(asnFixture))) !=
        "A0F9E8614AD582BA1AF3EEB18EAD666F73AD6E4CBD5280F80D5D4D95BBE6C3F1")
    throw new Exception("FAIL: upstream synthetic MaxMind fixture digest changed");
using (var geoDatabase = new GeoIpEcsDatabase(countryFixture, asnFixture, 0))
{
    var routes = geoDatabase.CreateTable(
        [new GeoCountryRoute("GB", "uk")], [new GeoAsnRoute(15169, "mumbai")]);
    if (routes.RegionForEcs(IPAddress.Parse("1.0.0.1"), 24) is not
        { Region: "mumbai", PrefixLength: 24 })
        throw new Exception("FAIL: bounded MaxMind ASN MMDB lookup did not select the explicitly mapped region");
    if (routes.RegionForEcs(IPAddress.Parse("81.2.69.160"), 24) is not null)
        throw new Exception("FAIL: country MMDB record more specific than privacy-limited ECS incorrectly routed");
    if (routes.RegionForEcs(IPAddress.Parse("81.2.69.160"), 27) is not
        { Region: "uk", PrefixLength: 27 })
        throw new Exception("FAIL: explicit country ISO route did not map the synthetic fixture");
    if (GeoIpEcsRegionTable.ResolveConfiguredRegions("osaka", "mumbai", 24) is not null ||
        GeoIpEcsRegionTable.ResolveConfiguredRegions(null, "mumbai", 24) is not
            { Region: "mumbai", PrefixLength: 24 })
        throw new Exception("FAIL: conflicting country/ASN routes did not fail closed or single-source route failed");
}
Console.WriteLine("PASS: MaxMind MMDB route mapping, privacy-boundary fallback, and unknown-country handling");
var staleGeoDatabaseRejected = false;
try { using var _ = new GeoIpEcsDatabase(countryFixture, null, 1); }
catch (InvalidDataException) { staleGeoDatabaseRejected = true; }
if (!staleGeoDatabaseRejected)
    throw new Exception("FAIL: a GeoIP database outside the configured freshness window was accepted");
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
using var metricsReservation = new TcpListener(IPAddress.Loopback, 0);
metricsReservation.Start();
var metricsPort = ((IPEndPoint)metricsReservation.LocalEndpoint).Port;
metricsReservation.Stop();
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
 MetricsListenHost="127.0.0.1",MetricsListenPort=metricsPort,
 GeoIpCountryDatabasePath=countryFixture,GeoIpAsnDatabasePath=asnFixture,
 GeoIpMaxDatabaseAgeDays=0,
 Zones=new object[]{
 new {Name="chain.integration.test",TtlSeconds=10,Sites=chainSites,
      NameServers=new[]{new {Host="ns.chain.integration.test",Address="127.0.0.31"}},
      RoutingPolicy="WeightedFailover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=true},
 new {Name="chain-open.integration.test",TtlSeconds=10,Sites=chainSites,
      RoutingPolicy="WeightedFailover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=false},
 new {Name="quarantine.integration.test",TtlSeconds=10,
      Sites=new[]{
        new {Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0,AdministrativelyQuarantined=true},
        new {Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",Weight=1,Priority=10,HealthCheckType="Http",TcpPort=0,AdministrativelyQuarantined=false}},
      RoutingPolicy="Failover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=true},
 new {Name="quarantine-open.integration.test",TtlSeconds=10,
      Sites=new[]{new {Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0,AdministrativelyQuarantined=true}},
      RoutingPolicy="Weighted",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=false},
 new {Name="delegated.integration.test",TtlSeconds=10,
      Sites=new[]{new {Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0}},
      NameServers=new[]{new {Host="ns1.delegated.integration.test",Address="127.0.0.31"}},
      Delegations=new[]{new {Name="child.delegated.integration.test",
        NameServers=new[]{
          new {Host="ns.child.delegated.integration.test",Address="127.0.0.61"},
          new {Host="ns.other.example.net",Address="192.0.2.53"}}}},
      RoutingPolicy="Failover",FailureThreshold=1,SuccessThreshold=1,
      FailClosedWhenAllSitesDown=true},
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
   EnableEcsGeoRouting=true,
   TrustedEcsResolverCidrs=new[]{"127.0.0.1/32"},
   CidrRoutes=new[]{
       new {Cidr="127.0.0.0/8",Region="dr"},
       new {Cidr="127.0.0.1/32",Region="local"},
       new {Cidr="198.51.100.0/24",Region="dr"},
       new {Cidr="198.51.101.0/24",Region="local"},
       new {Cidr="2001:db8:abcd::/56",Region="dr"}
   }},
 new{ Name="geoip.integration.test",TtlSeconds=10,Sites=new []{
    new { Address="127.0.0.21",HealthUrl="http://127.0.0.1:19711/ready",
          Weight=1,Priority=0,HealthCheckType="Http",TcpPort=0,Region="mumbai" },
    new { Address="127.0.0.22",HealthUrl="http://127.0.0.1:19712/ready",
          Weight=1,Priority=1,HealthCheckType="Http",TcpPort=0,Region="osaka" }
 },NameServers=new []{
     new {Host="ns1.geoip.integration.test",Address="127.0.0.31"}
 },SoaContact="hostmaster.geoip.integration.test",SoaSerial=2026111601u,
   RoutingPolicy="GeoIpEcs",FailureThreshold=1,SuccessThreshold=1,
   FailClosedWhenAllSitesDown=true,EnableEcsGeoRouting=true,
   TrustedEcsResolverCidrs=new[]{"127.0.0.1/32"},
   GeoCountryRoutes=new[]{new {CountryCode="GB",Region="osaka"}},
   GeoAsnRoutes=new[]{new {Asn=15169L,Region="mumbai"}}},
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
    using var metricsClient = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
    var metricsText = await metricsClient.GetStringAsync($"http://127.0.0.1:{metricsPort}/metrics");
    Must(metricsText.Contains("# TYPE gatewaycore_gslb_dns_queries_total counter", StringComparison.Ordinal) &&
         metricsText.Contains("gatewaycore_gslb_dns_queries_total{transport=\"udp\"} ", StringComparison.Ordinal) &&
         metricsText.Contains("gatewaycore_gslb_dns_responses_total{transport=\"udp\",rcode=\"NOERROR\"} ", StringComparison.Ordinal) &&
         metricsText.Contains("gatewaycore_gslb_configured_zones 11", StringComparison.Ordinal) &&
         metricsText.Contains("gatewaycore_gslb_administratively_quarantined_sites 2", StringComparison.Ordinal) &&
         !metricsText.Contains("app.integration.test", StringComparison.Ordinal) &&
         !metricsText.Contains("127.0.0.21", StringComparison.Ordinal),
         "loopback-only GSLB exporter reports bounded runtime series without zone names or backend addresses");
    _ = await TcpQuery(DnsRequest("app.integration.test", 1));
    metricsText = await metricsClient.GetStringAsync($"http://127.0.0.1:{metricsPort}/metrics");
    Must(metricsText.Contains("gatewaycore_gslb_dns_queries_total{transport=\"tcp\"} 1", StringComparison.Ordinal) &&
         metricsText.Contains("gatewaycore_gslb_dns_responses_total{transport=\"tcp\",rcode=\"NOERROR\"} 1", StringComparison.Ordinal),
         "GSLB exporter counts an actual DNS-over-TCP query and response");
    await Wait(async () =>
    {
        var response = await Query("quarantine.integration.test");
        return response.Status == 0 && response.Address == "127.0.0.22";
    });
    for (var i = 0; i < 5; i++)
    {
        var response = await Query("quarantine.integration.test");
        Must(response.Status == 0 && response.Address == "127.0.0.22",
            "manual maintenance quarantine outranks healthy local probes and routes to the next failover site");
    }
    var fullyQuarantined = await Query("quarantine-open.integration.test");
    Must(fullyQuarantined.Status == 2 && fullyQuarantined.Address is null,
        "availability-first fallback never selects an administratively quarantined site");
    Console.WriteLine("PASS: operator quarantine keeps a healthy primary out of DNS failover selection");
    var delegatedNs = await TcpQuery(DnsRequest("child.delegated.integration.test", 2));
    Must((Dns16(delegatedNs, 2) & 0x0400) == 0 && (Dns16(delegatedNs, 2) & 0x000f) == 0 &&
         Dns16(delegatedNs, 6) == 0 && Dns16(delegatedNs, 8) == 2 && Dns16(delegatedNs, 10) == 1 &&
         DnsRecordTypes(delegatedNs, 1).SequenceEqual(new ushort[] { 2, 2 }) &&
         DnsRecordTypes(delegatedNs, 2).SequenceEqual(new ushort[] { 1 }),
         "delegation apex returns non-authoritative NS referral and in-bailiwick glue only");
    var delegatedChild = await TcpQuery(DnsRequest("www.child.delegated.integration.test", 1));
    Must((Dns16(delegatedChild, 2) & 0x0400) == 0 && Dns16(delegatedChild, 6) == 0 &&
         Dns16(delegatedChild, 8) == 2 && Dns16(delegatedChild, 10) == 1,
         "names beneath a delegation receive the nearest referral instead of parent-zone answers");
    var delegatedDs = await TcpQuery(DnsRequest("child.delegated.integration.test", 43));
    Must((Dns16(delegatedDs, 2) & 0x0400) != 0 && (Dns16(delegatedDs, 2) & 0x000f) == 0 &&
         Dns16(delegatedDs, 6) == 0 && Dns16(delegatedDs, 8) == 1 &&
         DnsRecordTypes(delegatedDs, 1).SequenceEqual(new ushort[] { 6 }),
         "unsigned-parent DS absence returns authoritative negative SOA instead of referral");
    Console.WriteLine("PASS: DNS child-zone referrals, authority flags, in-bailiwick glue and DS absence");
    Console.WriteLine("PASS: loopback GSLB runtime metrics, transport counters and low-cardinality privacy contract");
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
    var (ecsRequest, ecsReply) = await QueryEcsWire("geo.integration.test", 1,
        IPAddress.Parse("198.51.100.42"), 32);
    Must((Dns16(ecsReply,2)&0x0F)==0 && Dns16(ecsReply,6)==1 &&
         Dns16(ecsReply,ecsReply.Length-11)==8 &&
         Dns16(ecsReply,ecsReply.Length-9)==7 &&
         Dns16(ecsReply,ecsReply.Length-7)==1 &&
         ecsReply[ecsReply.Length-5]==24 && ecsReply[ecsReply.Length-4]==24 &&
         ecsReply.AsSpan(ecsReply.Length-3,3).SequenceEqual(new byte[]{198,51,100}) &&
         ecsReply.AsSpan(ecsReply.Length-26,4).SequenceEqual(new byte[]{127,0,0,22}),
         "opt-in ECS caps /32 to /24, selects its configured region and returns matching cache scope");
    Must(Dns16(ecsRequest,10)==1,"ECS request contains one EDNS OPT record");
    var (_, ecsV6Reply) = await QueryEcsWire("geo.integration.test", 1,
        IPAddress.Parse("2001:db8:abcd::1234"), 128);
    var v6Prefix = IPAddress.Parse("2001:db8:abcd::").GetAddressBytes().Take(7).ToArray();
    Must(Dns16(ecsV6Reply,ecsV6Reply.Length-15)==8 &&
         Dns16(ecsV6Reply,ecsV6Reply.Length-11)==2 &&
         ecsV6Reply[ecsV6Reply.Length-9]==56 && ecsV6Reply[ecsV6Reply.Length-8]==56 &&
         ecsV6Reply.AsSpan(ecsV6Reply.Length-7,7).SequenceEqual(v6Prefix),
         "IPv6 ECS caps /128 to /56 and returns the normalized cache scope");
    var (_, ambiguousEcsReply) = await QueryEcsWire("geo.integration.test", 1,
        IPAddress.Parse("198.51.100.42"), 16);
    Must(ambiguousEcsReply.AsSpan(ambiguousEcsReply.Length-11,11).SequenceEqual(
             new byte[]{0,0,41,4,208,0,0,0,0,0,0}) &&
         ambiguousEcsReply.AsSpan(ambiguousEcsReply.Length-15,4)
             .SequenceEqual(new byte[]{127,0,0,21}),
         "ambiguous coarse ECS subnet is ignored and not reflected");
    var (_, disabledEcsReply) = await QueryEcsWire("app.integration.test", 1,
        IPAddress.Parse("198.51.100.42"), 24);
    Must(disabledEcsReply.AsSpan(disabledEcsReply.Length-11,11).SequenceEqual(
             new byte[]{0,0,41,4,208,0,0,0,0,0,0}),
         "ECS is not reflected by zones without explicit opt-in");
    var (_, untrustedEcsReply) = await QueryEcsWire("geo.integration.test", 1,
        IPAddress.Parse("198.51.101.42"), 24, IPAddress.Parse("127.0.0.2"));
    Must(untrustedEcsReply.AsSpan(untrustedEcsReply.Length-11,11).SequenceEqual(
             new byte[]{0,0,41,4,208,0,0,0,0,0,0}) &&
         untrustedEcsReply.AsSpan(untrustedEcsReply.Length-15,4)
             .SequenceEqual(new byte[]{127,0,0,22}),
         "untrusted DNS resolver cannot steer or receive ECS-based answers");
    for(var i=0;i<12;i++)
        Must((await Query("geo.integration.test")).Address=="127.0.0.21",
            "IPv4 resolver /32 specific region beats broader /8 mapping");
    var (_, geoIpReply) = await QueryEcsWire("geoip.integration.test", 1,
        IPAddress.Parse("1.0.0.1"), 32);
    Must(Dns16(geoIpReply, 6) == 1 &&
         geoIpReply.AsSpan(geoIpReply.Length - 26, 4).SequenceEqual(new byte[] {127,0,0,21}) &&
         geoIpReply.AsSpan(geoIpReply.Length - 3, 3).SequenceEqual(new byte[] {1,0,0}),
         "trusted privacy-capped ECS uses the explicit MaxMind ASN-to-region map and returns only /24 cache scope");
    var (_, narrowGeoReply) = await QueryEcsWire("geoip.integration.test", 1,
        IPAddress.Parse("81.2.69.160"), 32);
    Must(narrowGeoReply.AsSpan(narrowGeoReply.Length - 11, 11).SequenceEqual(
             new byte[] {0,0,41,4,208,0,0,0,0,0,0}),
         "more-specific country MMDB data falls back without echoing a misleading /24 ECS scope");
    var (_, untrustedGeoReply) = await QueryEcsWire("geoip.integration.test", 1,
        IPAddress.Parse("1.0.0.1"), 32, IPAddress.Parse("127.0.0.2"));
    Must(untrustedGeoReply.AsSpan(untrustedGeoReply.Length - 11, 11).SequenceEqual(
             new byte[] {0,0,41,4,208,0,0,0,0,0,0}),
         "untrusted resolver cannot use MaxMind ECS routing or receive an ECS echo");
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
        allDown.Add(reply.Address!);
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
    foreach (var dnssecType in new ushort[] { 43, 46, 48 }) // DS, RRSIG, DNSKEY
    {
        var dnssecReply = await TcpQuery(DnsRequest("app.integration.test", dnssecType, ednsVersion: 0));
        Must((Dns16(dnssecReply,2)&0x0020)==0 && (Dns16(dnssecReply,2)&0xF)==0 &&
             Dns16(dnssecReply,6)==0 && Dns16(dnssecReply,8)==1 &&
             Dns16(dnssecReply,10)==1 && dnssecReply[^1]==0,
             $"DNSSEC type {dnssecType} with DO=1 receives unsigned NODATA, no AD claim and no DO advertisement");
    }
    Console.WriteLine("PASS: unsigned zones do not claim DNSSEC; DO queries receive no fabricated signatures or AD bit");
    var (_, badVers) = await QueryWire("app.integration.test",1,ednsVersion:1);
    Must(Dns16(badVers,6)==0 && Dns16(badVers,10)==1 &&
         badVers[^6]==1,"EDNS version mismatch signals BADVERS, without A answer");
    var malformedBase = DnsRequest("app.integration.test",1);
    var noQuestions = (byte[])malformedBase.Clone();
    BinaryPrimitives.WriteUInt16BigEndian(noQuestions.AsSpan(4,2),0);
    var multipleQuestions = (byte[])malformedBase.Clone();
    BinaryPrimitives.WriteUInt16BigEndian(multipleQuestions.AsSpan(4,2),2);
    var badLabel = (byte[])malformedBase.Clone();
    badLabel[12]=64;
    var compressedQuestion = (byte[])malformedBase.Clone();
    compressedQuestion[12]=0xC0;
    var trailingData = malformedBase.Concat(new byte[]{0}).ToArray();
    var multipleAdditionals = (byte[])malformedBase.Clone();
    BinaryPrimitives.WriteUInt16BigEndian(multipleAdditionals.AsSpan(10,2),2);
    var truncatedOpt = DnsRequest("app.integration.test",1,ednsVersion:0)[..^1];
    var malformedPackets = new (byte[] Packet,string Case)[] {
        (malformedBase[..12],"short DNS header"),
        (noQuestions,"zero-question frame"),
        (multipleQuestions,"multiple-question frame"),
        (badLabel,"oversized DNS label"),
        (compressedQuestion,"compressed question name"),
        (trailingData,"unaccounted trailing byte"),
        (multipleAdditionals,"multiple additional records"),
        (truncatedOpt,"truncated EDNS OPT")
    };
    foreach (var malformed in malformedPackets)
        await ExpectUdpDrop(malformed.Packet,malformed.Case);
    foreach (var malformed in malformedPackets)
        await ExpectTcpDrop(malformed.Packet,malformed.Case);
    var fuzzRandom = new Random(0x47534C42);
    var fuzzIds = new Dictionary<ushort,int>();
    var fuzzReplies = 0;
    using (var fuzzSocket = new UdpClient(AddressFamily.InterNetwork))
    {
        fuzzSocket.Connect(IPAddress.Loopback,15353);
        for (var i=0;i<256;i++)
        {
            var packet = new byte[fuzzRandom.Next(0,257)];
            fuzzRandom.NextBytes(packet);
            if (packet.Length >= 2)
                fuzzIds[BinaryPrimitives.ReadUInt16BigEndian(packet)] = packet.Length;
            await fuzzSocket.SendAsync(packet,CancellationToken.None);
            using var replyTimeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(10));
            try
            {
                var fuzzReply = await fuzzSocket.ReceiveAsync(replyTimeout.Token);
                Must(fuzzReply.Buffer.Length >= 12 &&
                     fuzzIds.TryGetValue(Dns16(fuzzReply.Buffer,0),out var originalLength) &&
                     fuzzReply.Buffer.Length <= Math.Min(1232,Math.Max(128,originalLength*4)),
                     "deterministic DNS parser fuzz reply is correlated and amplification-bounded");
                fuzzReplies++;
            }
            catch (OperationCanceledException) { }
        }
    }
    Must(!dns.HasExited && (await Query("app.integration.test")).Address is not null,
        "DNS listener remains healthy after malformed and randomized packet corpus");
    Console.WriteLine($"PASS: malformed DNS/EDNS UDP/TCP corpus and 256 seeded UDP parser inputs; listener healthy, bounded replies={fuzzReplies}");
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

ushort[] DnsRecordTypes(byte[] packet, int section)
{
    if (section is < 0 or > 2) throw new ArgumentOutOfRangeException(nameof(section));
    var counts = new[] { Dns16(packet, 6), Dns16(packet, 8), Dns16(packet, 10) };
    var offset = 12;
    SkipDnsName(packet, ref offset);
    offset += 4;
    var types = new List<ushort>();
    for (var currentSection = 0; currentSection <= section; currentSection++)
    {
        for (var record = 0; record < counts[currentSection]; record++)
        {
            SkipDnsName(packet, ref offset);
            if (offset + 10 > packet.Length) throw new InvalidDataException("Truncated DNS resource record");
            var type = Dns16(packet, offset);
            var dataLength = Dns16(packet, offset + 8);
            offset += 10;
            if (offset + dataLength > packet.Length) throw new InvalidDataException("Truncated DNS RDATA");
            if (currentSection == section) types.Add(type);
            offset += dataLength;
        }
    }
    return types.ToArray();
}

void SkipDnsName(byte[] packet, ref int offset)
{
    while (offset < packet.Length)
    {
        var labelLength = packet[offset++];
        if (labelLength == 0) return;
        if ((labelLength & 0xC0) == 0xC0)
        {
            if (offset >= packet.Length) throw new InvalidDataException("Truncated DNS name pointer");
            offset++;
            return;
        }
        if (labelLength > 63 || offset + labelLength > packet.Length)
            throw new InvalidDataException("Invalid DNS name in response");
        offset += labelLength;
    }
    throw new InvalidDataException("Unterminated DNS name in response");
}

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
async Task ExpectUdpDrop(byte[] packet,string scenario)
{
    using var sender = new UdpClient(AddressFamily.InterNetwork);
    sender.Connect(IPAddress.Loopback,15353);
    await sender.SendAsync(packet,CancellationToken.None);
    using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
    try
    {
        _ = await sender.ReceiveAsync(timeout.Token);
        throw new Exception("FAIL: malformed DNS packet received a response: "+scenario);
    }
    catch (OperationCanceledException) when (timeout.IsCancellationRequested) { }
}
async Task ExpectTcpDrop(byte[] packet,string scenario)
{
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    using var client = new TcpClient(AddressFamily.InterNetwork);
    await client.ConnectAsync(IPAddress.Loopback,15353,timeout.Token);
    var stream = client.GetStream();
    var prefix = new byte[2];
    BinaryPrimitives.WriteUInt16BigEndian(prefix,checked((ushort)packet.Length));
    await stream.WriteAsync(prefix,timeout.Token);
    await stream.WriteAsync(packet,timeout.Token);
    // RST is a normal way for a peer to discard a malformed frame with no DNS
    // response; Windows reports it as IOException wrapping SocketException.
    // Any payload still fails above, and unrelated I/O errors remain failures.
    // (The read can throw before returning zero on this close path.)
    var response = new byte[1];
    try
    {
        var received = await stream.ReadAsync(response,timeout.Token);
        Must(received==0,"malformed TCP DNS packet must close without a response: "+scenario);
    }
    catch (IOException ex) when (ex.InnerException is SocketException socket &&
        socket.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted) { }
}
async Task<(byte[] Request,byte[] Reply)> QueryEcsWire(
    string domain, ushort type, IPAddress clientAddress, int sourcePrefix, IPAddress? resolverSource = null)
{
    var request = new List<byte>(DnsRequest(domain, type));
    request[10] = 0;
    request[11] = 1;
    var addressBytes = clientAddress.GetAddressBytes();
    var family = clientAddress.AddressFamily == AddressFamily.InterNetwork ? (ushort)1 : (ushort)2;
    var optionLength = 4 + (sourcePrefix + 7) / 8;
    var optionAndHeaderLength = 4 + optionLength;
    request.AddRange(new byte[] { 0, 0, 41, 4, 208, 0, 0, 0, 0,
        (byte)(optionAndHeaderLength >> 8), (byte)optionAndHeaderLength,
        0, 8, (byte)(optionLength >> 8), (byte)optionLength,
        (byte)(family >> 8), (byte)family, (byte)sourcePrefix, 0 });
    request.AddRange(addressBytes.Take((sourcePrefix + 7) / 8));
    using var alternateClient = resolverSource is null
        ? null : new UdpClient(new IPEndPoint(resolverSource, 0));
    var sender = alternateClient ?? client;
    if (alternateClient is not null) sender.Connect(IPAddress.Loopback, 15353);
    await sender.SendAsync(request.ToArray());
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
    var reply = await sender.ReceiveAsync(timeout.Token);
    Must(reply.Buffer.Length >= 12 && Dns16(reply.Buffer, 0) == 0x4613,
        "ECS DNS UDP transaction matching");
    return (request.ToArray(), reply.Buffer);
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
