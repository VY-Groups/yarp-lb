using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;

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
using var geoIpDatabase = new GeoIpEcsDatabase(config.GeoIpCountryDatabasePath,
    config.GeoIpAsnDatabasePath, config.GeoIpMaxDatabaseAgeDays,
    bindAuthorityIdentity: config.AuthorityFence is not null &&
        config.Zones?.Any(zone => zone.RoutingPolicy == "GeoIpEcs") == true);
if (!IPAddress.TryParse(config.ListenHost, out var listen) ||
    listen.IsIPv4MappedToIPv6 ||
    listen.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
    (!config.AllowNonLoopbackListeners && !IPAddress.IsLoopback(listen)) ||
    (config.ListenPort is < 1025 or > 65535) &&
        !(config.ListenPort == 53 && config.AllowNonLoopbackListeners && !IPAddress.IsLoopback(listen)) ||
    config.ProbeIntervalSeconds is < 1 or > 60 ||
    config.MaxResponsesPerSecondPerClient is < 20 or > 20000 ||
    config.MaxConcurrentHealthProbes is < 1 or > 128 ||
    config.MetricsListenPort is < 0 or > 65535 ||
    config.Zones is not { Length: >= 1 and <= 64 })
    throw new InvalidDataException("Invalid DNS listener or zones. Non-loopback binding requires explicit opt-in.");
DnsListenerValidation.ValidateAuthoritativeZones(listen, config.Zones);
if (config.MetricsListenPort != 0)
{
    if (!IPAddress.TryParse(config.MetricsListenHost, out var metricsListen) ||
        !IPAddress.IsLoopback(metricsListen) || metricsListen.IsIPv4MappedToIPv6)
        throw new InvalidDataException("GSLB metrics must use an IPv4 or IPv6 loopback address.");
    if (metricsListen.Equals(listen) && config.MetricsListenPort == config.ListenPort ||
        config.AgentReports is { } reports &&
        IPAddress.TryParse(reports.ListenAddress, out var reportListen) &&
        metricsListen.Equals(reportListen) && config.MetricsListenPort == reports.ListenPort)
        throw new InvalidDataException("GSLB DNS, metrics and agent-report listeners must use distinct address/port pairs.");
}
var names=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
var groups=new Dictionary<string, SiteGroup>(StringComparer.OrdinalIgnoreCase);
var reportTargets = new List<AgentReportTarget>();
foreach(var zone in config.Zones)
{
    if (string.IsNullOrWhiteSpace(zone.Name) || zone.Name.Length > 253 ||
        !names.Add(zone.Name.TrimEnd('.')) || zone.TtlSeconds is < 5 or > 300 ||
        !DnsWireProtocol.ValidName(zone.Name.TrimEnd('.')) ||
        zone.Sites is not {Length: >=1 and <=16} ||
        zone.NameServers is {Length: >4} || zone.SoaSerial == 0 ||
        zone.FailureThreshold is < 1 or > 10 ||
        zone.SuccessThreshold is < 1 or > 10 ||
        zone.RoutingPolicy is not ("Weighted" or "Failover" or "CidrRegion" or "GeoIpEcs" or "ObservedLatency" or "WeightedFailover") ||
        (zone.RoutingPolicy == "CidrRegion" &&
             zone.CidrRoutes is not { Length: >= 1 and <= 256 }) ||
        (zone.EnableEcsGeoRouting &&
            (zone.RoutingPolicy is not ("CidrRegion" or "GeoIpEcs") ||
             zone.TrustedEcsResolverCidrs is not { Length: >= 1 and <= 256 })) ||
        (!zone.EnableEcsGeoRouting && zone.TrustedEcsResolverCidrs is { Length: > 0 }) ||
        (zone.RoutingPolicy != "CidrRegion" && zone.CidrRoutes is { Length: > 0 }) ||
        (zone.RoutingPolicy == "GeoIpEcs" &&
            (!zone.EnableEcsGeoRouting ||
             (zone.GeoCountryRoutes is not { Length: > 0 } && zone.GeoAsnRoutes is not { Length: > 0 }))) ||
        (zone.RoutingPolicy != "GeoIpEcs" &&
            (zone.GeoCountryRoutes is { Length: > 0 } || zone.GeoAsnRoutes is { Length: > 0 })))
        throw new InvalidDataException("Invalid GSLB zone, policy, CIDR or TTL");
    // GeoIP and ECS are opt-in. The DNS resolver source must match the trusted
    // resolver allowlist before a privacy-masked client subnet reaches MMDB.
    var cidrTable = zone.RoutingPolicy == "CidrRegion"
        ? new DnsCidrRegionTable(zone.CidrRoutes!) : null;
    var trustedEcsResolvers = zone.EnableEcsGeoRouting
        ? new DnsCidrRegionTable(zone.TrustedEcsResolverCidrs!
            .Select(cidr => new DnsCidrRegionRule(cidr, "trusted")))
        : null;
    var geoIpTable = zone.RoutingPolicy == "GeoIpEcs"
        ? geoIpDatabase.CreateTable(zone.GeoCountryRoutes, zone.GeoAsnRoutes) : null;
    var sites=new List<Site>();
    foreach(var site in zone.Sites)
    {
        if (site is null)
            throw new InvalidDataException("Null GSLB site");
        if (config.AuthorityFence is not null &&
            !AgentHealthReportContract.IsValidIdentifier(site.AuthorityFenceSiteId))
            throw new InvalidDataException("Authority fencing requires an explicit stable site ID for every backend");
        var validHttpUrl = Uri.TryCreate(site.HealthUrl, UriKind.Absolute, out var health) &&
            (health.Scheme == Uri.UriSchemeHttp || health.Scheme == Uri.UriSchemeHttps) &&
            string.IsNullOrWhiteSpace(health.UserInfo);
        if(!IPAddress.TryParse(site.Address,out var address) ||
            address.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6) ||
            site.Weight is < 1 or > 100 ||
            site.Priority is < 0 or > 1000 ||
            (site.Region is not null && !DnsCidrRegionTable.ValidRegion(site.Region)) ||
            ((cidrTable is not null || geoIpTable is not null) && !DnsCidrRegionTable.ValidRegion(site.Region)) ||
            (site.RequiredAgentIds is not null &&
                (!zone.FailClosedWhenAllSitesDown ||
                 !AgentHealthReportContract.IsValidIdentifier(site.AgentSiteId) ||
                 site.RequiredAgentIds.Length is < 2 or > 16 ||
                 (site.MinimumHealthyAgentReports is int minimumReports &&
                    (minimumReports < 2 || minimumReports > site.RequiredAgentIds.Length)) ||
                 site.RequiredAgentIds.Distinct(StringComparer.Ordinal).Count() != site.RequiredAgentIds.Length)) ||
            (site.RequiredAgentIds is null &&
                (site.AgentSiteId is not null || site.MinimumHealthyAgentReports is not null)) ||
            site.HealthCheckType is not ("Http" or "Tcp") ||
            (site.HealthCheckType == "Http" && (!validHttpUrl || site.TcpPort != 0)) ||
            (site.HealthCheckType == "Tcp" &&
                (site.TcpPort is < 1 or > 65535 || !string.IsNullOrWhiteSpace(site.HealthUrl))))
            throw new InvalidDataException("Invalid GSLB site address, weight, probe type, URL or port");
        var observers = ExternalValidation.Parse(site.ValidatorUrls);
        if (observers.Length != 0 && !zone.FailClosedWhenAllSitesDown)
            throw new InvalidDataException("External validation requires strict all-down behavior");
        sites.Add(new Site(address!,site.HealthCheckType == "Http" ? health : null,
            site.Weight,site.Priority,zone.FailureThreshold,zone.SuccessThreshold,
            site.HealthCheckType,site.TcpPort,site.Region,site.AgentSiteId,site.RequiredAgentIds ?? [],
            site.AuthorityFenceSiteId)
            { Validators = observers, AdministrativelyQuarantined = site.AdministrativelyQuarantined });
        if (site.RequiredAgentIds is { Length: > 0 })
            reportTargets.Add(new AgentReportTarget(zone.Name.TrimEnd('.').ToLowerInvariant(),
                site.AgentSiteId!, site.RequiredAgentIds,
                site.MinimumHealthyAgentReports ?? site.RequiredAgentIds.Length));
    }
    if (sites.Any(site => site.RequiredAgentIds.Length > 0) &&
        sites.Any(site => site.RequiredAgentIds.Length == 0))
        throw new InvalidDataException("All sites in an agent-report zone must use an explicit report quorum");
    var hasDnssecKeyConfig = !string.IsNullOrWhiteSpace(zone.DnssecPrivateKeyPath) ||
        zone.DnssecPrepublishPublicKeyPaths is { Length: > 0 } ||
        zone.DnssecAdditionalSigningKeyPaths is { Length: > 0 };
    var denialMode = zone.DnssecDenialMode ?? "Nsec";
    if (!string.Equals(denialMode, "Nsec", StringComparison.OrdinalIgnoreCase) &&
        !string.Equals(denialMode, "Nsec3", StringComparison.OrdinalIgnoreCase))
        throw new InvalidDataException("DnssecDenialMode must be Nsec or Nsec3");
    if (string.Equals(denialMode, "Nsec3", StringComparison.OrdinalIgnoreCase) && !hasDnssecKeyConfig)
        throw new InvalidDataException("NSEC3 mode requires DNSSEC signing to be enabled");
    if (string.Equals(denialMode, "Nsec", StringComparison.OrdinalIgnoreCase) &&
        (zone.DnssecNsec3SaltHex is not null || zone.DnssecNsec3Iterations is not null))
        throw new InvalidDataException("NSEC3 salt and iterations require DnssecDenialMode=Nsec3");
    if (string.Equals(denialMode, "Nsec3", StringComparison.OrdinalIgnoreCase) &&
        (zone.DnssecNsec3SaltHex is null || zone.DnssecNsec3Iterations is null or < 0 or > 50 ||
         zone.DnssecNsec3SaltHex.Length is < 16 or > 64 || zone.DnssecNsec3SaltHex.Length % 2 != 0 ||
         !zone.DnssecNsec3SaltHex.All(Uri.IsHexDigit)))
        throw new InvalidDataException("NSEC3 requires an explicit 8..32 byte hex salt and 0..50 iterations");
    if (string.Equals(denialMode, "Nsec3", StringComparison.OrdinalIgnoreCase) &&
        (zone.Name.EndsWith("..", StringComparison.Ordinal) ||
         zone.SoaContact?.EndsWith("..", StringComparison.Ordinal) == true ||
         (zone.NameServers ?? []).Any(server => server is not null &&
             server.Host.EndsWith("..", StringComparison.Ordinal)) ||
         (zone.Delegations ?? []).Any(cut => cut is not null &&
             (cut.Name.EndsWith("..", StringComparison.Ordinal) ||
              (cut.NameServers ?? []).Any(server => server is not null &&
                  server.Host.EndsWith("..", StringComparison.Ordinal))))))
        throw new InvalidDataException("NSEC3 names may have at most one terminal root dot");
    if ((zone.DnssecPrepublishPublicKeyPaths?.Length ?? 0) > 2 ||
        (zone.DnssecAdditionalSigningKeyPaths?.Length ?? 0) > 2 ||
        (hasDnssecKeyConfig && string.IsNullOrWhiteSpace(zone.DnssecPrivateKeyPath)))
        throw new InvalidDataException("DNSSEC rollover keys require an active private key and at most two keys per rollover role");
    if ((zone.DnssecPrepublishPublicKeyPaths ?? []).Any(string.IsNullOrWhiteSpace) ||
        (zone.DnssecAdditionalSigningKeyPaths ?? []).Any(string.IsNullOrWhiteSpace))
        throw new InvalidDataException("DNSSEC rollover key paths must not be empty");
    var dnssecPaths = new[] { zone.DnssecPrivateKeyPath }
        .Concat(zone.DnssecPrepublishPublicKeyPaths ?? [])
        .Concat(zone.DnssecAdditionalSigningKeyPaths ?? [])
        .Where(path => !string.IsNullOrWhiteSpace(path)).Select(path => path!).ToArray();
    if (dnssecPaths.Any(path => string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path)) ||
        dnssecPaths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != dnssecPaths.Length)
        throw new InvalidDataException("DNSSEC active, rollover and prepublish key paths must be unique absolute paths");
    if (hasDnssecKeyConfig &&
        (zone.NameServers is not { Length: > 0 } || zone.SoaSerial == 0))
        throw new InvalidDataException("DNSSEC requires authoritative NS records and a nonzero SOA serial");
    var origin = zone.Name.TrimEnd('.').ToLowerInvariant();
    var servers = new List<DnsNameServer>();
    var serverNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var source in zone.NameServers ?? Array.Empty<DnsNameServerConfig>())
    {
        if (source is null || string.IsNullOrWhiteSpace(source.Host) ||
            !DnsWireProtocol.ValidName(source.Host.TrimEnd('.')) ||
            !IPAddress.TryParse(source.Address, out var nsAddress) ||
            nsAddress.IsIPv4MappedToIPv6 || nsAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            throw new InvalidDataException("Invalid authoritative NS hostname or address");
        var host = source.Host.TrimEnd('.').ToLowerInvariant();
        if (!serverNames.Add(host))
            throw new InvalidDataException("Duplicate authoritative NS hostname");
        // Explicit out-of-bailiwick servers may be NS targets; their A data is not advertised.
        servers.Add(new DnsNameServer(host, nsAddress));
    }
    var delegationRows = zone.Delegations ?? Array.Empty<DnsDelegationConfig>();
    if (delegationRows.Length > 256)
        throw new InvalidDataException("A zone may configure at most 256 delegation cuts");
    var delegations = new List<DnsDelegation>();
    var delegationNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
    foreach (var source in delegationRows)
    {
        if (source is null || string.IsNullOrWhiteSpace(source.Name) ||
            !DnsWireProtocol.ValidName(source.Name.TrimEnd('.')) ||
            source.Name.TrimEnd('.').Equals(origin, StringComparison.OrdinalIgnoreCase) ||
            !source.Name.TrimEnd('.').EndsWith("." + origin, StringComparison.OrdinalIgnoreCase) ||
            source.NameServers is not { Length: >= 1 and <= 8 })
            throw new InvalidDataException("Delegation must be a strict child of the hosted zone with 1..4 unique name servers (at most one A and one AAAA address each)");
        var cut = source.Name.TrimEnd('.').ToLowerInvariant();
        if (!delegationNames.Add(cut))
            throw new InvalidDataException("Duplicate delegation cut");
        var dsRows = source.DsRecords ?? [];
        if (dsRows.Length > 8 || (dsRows.Length > 0 && !hasDnssecKeyConfig))
            throw new InvalidDataException("Delegation DS records require a signed parent zone and are limited to 8 per cut");
        var dsRecords = new List<DnsDsRecord>();
        var dsRdata = new HashSet<string>(StringComparer.Ordinal);
        foreach (var ds in dsRows)
        {
            var expectedHexLength = ds?.DigestType switch { 2 => 64, 4 => 96, _ => 0 };
            if (ds is null || ds.Algorithm is not (1 or 3 or 5 or 6 or 7 or 8 or 10 or 12 or 13 or 14 or 15 or 16) ||
                expectedHexLength == 0 ||
                ds.DigestHex is null || ds.DigestHex.Length != expectedHexLength ||
                !ds.DigestHex.All(Uri.IsHexDigit))
                throw new InvalidDataException("Delegation DS requires a recognized DNSKEY algorithm and SHA-256 or SHA-384 digest of the exact length");
            var rdata = new byte[4 + expectedHexLength / 2];
            BinaryPrimitives.WriteUInt16BigEndian(rdata, ds.KeyTag);
            rdata[2] = ds.Algorithm;
            rdata[3] = ds.DigestType;
            Convert.FromHexString(ds.DigestHex).CopyTo(rdata, 4);
            if (!dsRdata.Add(Convert.ToHexString(rdata)))
                throw new InvalidDataException("Duplicate delegation DS record");
            dsRecords.Add(new DnsDsRecord(rdata));
        }
        var childServers = new List<DnsNameServer>();
        var childServerNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var childServerAddressFamilies = new HashSet<(string Host, AddressFamily Family)>();
        foreach (var child in source.NameServers)
        {
            if (child is null || string.IsNullOrWhiteSpace(child.Host) ||
                !DnsWireProtocol.ValidName(child.Host.TrimEnd('.')) ||
                !IPAddress.TryParse(child.Address, out var childAddress) ||
                childAddress.IsIPv4MappedToIPv6 ||
                childAddress.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                throw new InvalidDataException("Invalid delegated name-server hostname or address");
            var host = child.Host.TrimEnd('.').ToLowerInvariant();
            childServerNames.Add(host);
            if (!childServerAddressFamilies.Add((host, childAddress.AddressFamily)))
                throw new InvalidDataException("Duplicate delegated name-server address family");
            childServers.Add(new DnsNameServer(host, childAddress));
        }
        if (childServerNames.Count > 4)
            throw new InvalidDataException("A delegation may configure at most four unique name servers");
        delegations.Add(new DnsDelegation(cut, childServers.ToArray(), dsRecords.ToArray()));
    }
    if (delegations.Any(cut => delegations.Any(other =>
            !ReferenceEquals(cut, other) && cut.Name.EndsWith("." + other.Name, StringComparison.OrdinalIgnoreCase))) ||
        servers.Any(server => delegations.Any(cut => server.Host.Equals(cut.Name, StringComparison.OrdinalIgnoreCase) ||
            server.Host.EndsWith("." + cut.Name, StringComparison.OrdinalIgnoreCase))))
        throw new InvalidDataException("Nested cuts and parent name servers below a child delegation are unsupported");
    var contact = (zone.SoaContact ?? ("hostmaster." + origin)).TrimEnd('.').ToLowerInvariant();
    if (!DnsWireProtocol.ValidName(contact))
        throw new InvalidDataException("Invalid SOA contact name");
    if(cidrTable is not null)
    {
        var siteRegions=sites.Select(site => site.Region!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if(cidrTable.Regions.Any(region => !siteRegions.Contains(region)))
            throw new InvalidDataException("CIDR route references undefined backend region");
    }
    if (geoIpTable is not null)
    {
        var siteRegions = sites.Select(site => site.Region!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (geoIpTable.Regions.Any(region => !siteRegions.Contains(region)))
            throw new InvalidDataException("GeoIP route references undefined backend region");
    }
    groups.Add(origin, new SiteGroup(sites.ToArray(), zone.TtlSeconds,
        zone.FailClosedWhenAllSitesDown, servers.ToArray(), contact, zone.SoaSerial,
        zone.RoutingPolicy,cidrTable,zone.EnableEcsGeoRouting,trustedEcsResolvers,geoIpTable,
        delegations.ToArray(), zone.DnssecPrivateKeyPath, origin,
        zone.DnssecPrepublishPublicKeyPaths, zone.DnssecAdditionalSigningKeyPaths,
        denialMode, zone.DnssecNsec3SaltHex, zone.DnssecNsec3Iterations ?? 0));
    if (groups[origin].Dnssec is { } dnssec)
    {
        foreach (var entry in dnssec.ParentDsMaterial)
        {
            var dsText = $"{entry.KeyTag} 13 2 {Convert.ToHexString(entry.Ds.Rdata[4..])}";
            Console.WriteLine($"GSLB_DNSSEC zone={origin} phase={entry.Phase} algorithm=13 keyTag={entry.KeyTag} DS=\"{dsText}\"");
        }
    }
}
if (config.AuthorityFence is not null)
{
    if (config.Zones.Any(zone => !zone.FailClosedWhenAllSitesDown))
        throw new InvalidDataException("Authority fencing requires fail-closed DNS policy in every zone");
    foreach (var zone in config.Zones)
        if (zone.Sites.Select(site => site.AuthorityFenceSiteId).Distinct(StringComparer.Ordinal).Count() != zone.Sites.Length)
            throw new InvalidDataException("Authority fence site IDs must be unique within each zone");
}
using var dnssecLifetime = new DnssecSignerLifetime(groups.Values);
if ((reportTargets.Count > 0) != (config.AgentReports is not null))
    throw new InvalidDataException("Agent report listener and report-gated sites must be configured together");
using var reportStore = config.AgentReports is null ? null : new AgentHealthReportStore(
    config.AgentReports.Agents, reportTargets, config.AgentReports.ReplayStatePath,
    config.AgentReports.MaxTtlSeconds, config.AgentReports.MaxAgeSeconds,
    config.AgentReports.MaxClockSkewSeconds);
if (config.AuthorityFence is { } fenceConfig &&
    (fenceConfig.ListenPort == config.ListenPort || fenceConfig.ListenPort == config.MetricsListenPort ||
     (config.AgentReports is { } reportSettings && fenceConfig.ListenPort == reportSettings.ListenPort)))
    throw new InvalidDataException("Authority-fence, DNS, metrics and agent-report listeners must use distinct ports");
var authorityTargets = config.AuthorityFence is null ? [] : groups.SelectMany(zone => zone.Value.Sites.Select(site =>
    new AuthorityFenceTarget(zone.Key, site.AuthorityFenceSiteId!, nowTick =>
        !site.AdministrativelyQuarantined && Volatile.Read(ref site.Healthy) == 1 &&
        (site.Validators.Length == 0 || nowTick < Volatile.Read(ref site.ValidatorDeadline)) &&
        (site.RequiredAgentIds.Length == 0 ||
         (reportStore?.IsHealthy(zone.Key, site.AgentSiteId!, nowTick) ?? false))))).ToArray();
var authorityFenceStore = config.AuthorityFence is null ? null : new AuthorityFenceStore(
    config.AuthorityFence, AuthorityFenceFingerprint.Compute(config.Zones, config.AgentReports,
        config.ProbeIntervalSeconds, config.MaxConcurrentHealthProbes,
        groups.Where(pair => pair.Value.Dnssec is not null)
            .ToDictionary(pair => pair.Key, pair => pair.Value.Dnssec!, StringComparer.OrdinalIgnoreCase),
        geoIpIdentity: geoIpDatabase.AuthorityIdentity, loadedAgentStore: reportStore),
    authorityTargets);
using var authorityFenceStoreLifetime = authorityFenceStore;
await using var authorityFenceRuntime = authorityFenceStore is null || config.AuthorityFence is null
    ? null : new AuthorityFenceRuntime(config.AuthorityFence, authorityFenceStore);
var runtimeMetrics = new DnsRuntimeMetrics();
await using var reportServer = config.AgentReports is null || reportStore is null
    ? null : new AgentHealthReportServer(config.AgentReports, reportStore, runtimeMetrics);
await using var metricsServer = config.MetricsListenPort == 0 ? null : new DnsMetricsServer(
    config.MetricsListenHost, config.MetricsListenPort, runtimeMetrics,
    groups.Values.ToArray(), reportStore, reportTargets);
using var validation = groups.Values.SelectMany(group => group.Sites).Any(site => site.Validators.Length > 0)
    ? new ExternalValidation(groups.Values.SelectMany(group => group.Sites).SelectMany(site => site.Validators)) : null;
using var stop=new CancellationTokenSource();
Console.CancelKeyPress += (_, e)=>{e.Cancel=true;stop.Cancel();};
using var sigterm=OperatingSystem.IsLinux()
    ? System.Runtime.InteropServices.PosixSignalRegistration.Create(
        System.Runtime.InteropServices.PosixSignal.SIGTERM, e=>{e.Cancel=true;stop.Cancel();})
    : null;
if (reportServer is not null) await reportServer.StartAsync(stop.Token);
if (metricsServer is not null) await metricsServer.StartAsync(stop.Token);
// A 301/302/307/308 must NOT become healthy by redirecting readiness to a
// login page, another server or a public site. Require direct HTTP 2xx.
using var healthClient = new HttpClient(new SocketsHttpHandler {
    UseProxy=false, AllowAutoRedirect=false })
    { Timeout=TimeSpan.FromSeconds(1.5) };
async Task ProbeAll(CancellationToken ct)
{
    // Per-cycle bounded parallelism avoids N * 1.5s serial timeouts across
    // many zones. The existing outer loop always awaits this entire batch;
    // no new cycle can mutate a Site before its previous probe completes.
    await BoundedDnsProbes.RunAsync(
        groups.Values.SelectMany(group => group.Sites),
        config.MaxConcurrentHealthProbes,
        async (site, token) =>
        {
            var started = System.Diagnostics.Stopwatch.GetTimestamp();
            var healthy = false;
            try
            {
                if (site.HealthCheckType == "Tcp")
                {
                    // Connection alone is not an application/transaction health check.
                    using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
                    deadline.CancelAfter(TimeSpan.FromSeconds(1.5));
                    using var tcp = new TcpClient(site.Address.AddressFamily);
                    await tcp.ConnectAsync(site.Address, site.TcpPort, deadline.Token);
                    healthy = tcp.Connected;
                }
                else
                {
                    using var response = await healthClient.GetAsync(site.HealthUrl!,
                        HttpCompletionOption.ResponseHeadersRead, token);
                    healthy = response.IsSuccessStatusCode;
                }
            }
            catch (Exception e) when (e is HttpRequestException or SocketException or
                OperationCanceledException) { }
            // Only a successful real probe advances the latency estimator.
            // Failed probes invalidate the previously measured performance.
            if (healthy)
                site.Latency.ObserveSuccess(System.Diagnostics.Stopwatch.GetElapsedTime(started),
                    Environment.TickCount64);
            else
                site.Latency.ObserveFailure();
            if (site.Validators.Length != 0)
            {
                var observedAt = Environment.TickCount64;
                var confirmed = healthy && await validation!.ConfirmAsync(site.Validators, token);
                // A lost or expired authority lease starts a new recovery sequence.
                var previousDeadline = Volatile.Read(ref site.ValidatorDeadline);
                if (!confirmed || Environment.TickCount64 >= previousDeadline)
                    site.Health.Invalidate();
                var eligible = confirmed && site.Health.Observe(true);
                Volatile.Write(ref site.Healthy, eligible ? 1 : 0);
                Volatile.Write(ref site.ValidatorDeadline, confirmed ? observedAt + 10_000 : 0);
                return;
            }
            // Publish a single verdict for each distinct zone/site per cycle.
            Volatile.Write(ref site.Healthy, site.Health.Observe(healthy) ? 1 : 0);
        }, ct);
}
await ProbeAll(stop.Token);
if (authorityFenceRuntime is not null) await authorityFenceRuntime.StartAsync(stop.Token);
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
using var dnsSocket=new Socket(listen.AddressFamily,SocketType.Dgram,ProtocolType.Udp);
var ipv6 = listen.AddressFamily == AddressFamily.InterNetworkV6;
if (ipv6) dnsSocket.DualMode = false;
var receiveEndpoint = new IPEndPoint(ipv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
dnsSocket.Bind(new IPEndPoint(listen,config.ListenPort));
using var tcpListener = new TcpListener(listen, config.ListenPort);
if (ipv6) tcpListener.Server.DualMode = false;
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
                    if (size is < 17 or > 4096)
                    {
                        runtimeMetrics.QueryReceived(tcp: true);
                        runtimeMetrics.RequestDropped(tcp: true);
                        return;
                    }
                    var packet = new byte[size];
                    await stream.ReadExactlyAsync(packet, deadline.Token);
                    runtimeMetrics.QueryReceived(tcp: true);
                    var resolverIp=(session.Client.RemoteEndPoint as IPEndPoint)?.Address;
                    var response = DnsWireProtocol.Build(packet, groups, tcp: true,
                        resolverIp:resolverIp, agentReports:reportStore, authorityFence:authorityFenceStore);
                    if (response is null)
                    {
                        runtimeMetrics.RequestDropped(tcp: true);
                        return;
                    }
                    BinaryPrimitives.WriteUInt16BigEndian(length, checked((ushort)response.Length));
                    await stream.WriteAsync(length, deadline.Token);
                    await stream.WriteAsync(response, deadline.Token);
                    runtimeMetrics.ResponseSent(tcp: true, response);
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
            receiveEndpoint,stop.Token); }
        catch(OperationCanceledException) when(stop.IsCancellationRequested){break;}
        catch(SocketException) when(stop.IsCancellationRequested){break;}
        runtimeMetrics.QueryReceived(tcp: false);
        // IP-keyed response budget. Do not echo arbitrary UDP traffic without limits.
        // Loopback is still the required default deployment boundary.
        var source=((IPEndPoint)received.RemoteEndPoint).Address;
        if(!responseLimiter.Allow(source,Environment.TickCount64))
        {
            runtimeMetrics.RequestDropped(tcp: false);
            continue;
        }
        var response=DnsWireProtocol.Build(buffer.AsSpan(0,received.ReceivedBytes),groups,
            tcp:false,resolverIp:source,agentReports:reportStore,authorityFence:authorityFenceStore);
        if(response is null)
        {
            runtimeMetrics.RequestDropped(tcp: false);
            continue;
        }
        try
        {
            await dnsSocket.SendToAsync(response,SocketFlags.None,received.RemoteEndPoint,stop.Token);
            runtimeMetrics.ResponseSent(tcp: false, response);
        }
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
    public int MaxConcurrentHealthProbes {get;init;} = 32;
    public string MetricsListenHost { get; init; } = "127.0.0.1";
    public int MetricsListenPort { get; init; }
    public string? GeoIpCountryDatabasePath { get; init; }
    public string? GeoIpAsnDatabasePath { get; init; }
    public int GeoIpMaxDatabaseAgeDays { get; init; } = 45;
    public AgentReportServerConfig? AgentReports { get; init; }
    public AuthorityFenceConfig? AuthorityFence { get; init; }
}
sealed record DnsZone(string Name,int TtlSeconds,DnsSite[] Sites,
    bool FailClosedWhenAllSitesDown=false)
{
    public DnsNameServerConfig[]? NameServers { get; init; }
    public string? SoaContact { get; init; }
    public uint SoaSerial { get; init; } = 1;
    public string RoutingPolicy { get; init; } = "Weighted";
    public bool EnableEcsGeoRouting { get; init; }
    public string[]? TrustedEcsResolverCidrs { get; init; }
    public int FailureThreshold { get; init; } = 1;
    public int SuccessThreshold { get; init; } = 1;
    public DnsCidrRegionRule[]? CidrRoutes { get; init; }
    public GeoCountryRoute[]? GeoCountryRoutes { get; init; }
    public GeoAsnRoute[]? GeoAsnRoutes { get; init; }
    public DnsDelegationConfig[]? Delegations { get; init; }
    public string? DnssecPrivateKeyPath { get; init; }
    public string[]? DnssecPrepublishPublicKeyPaths { get; init; }
    public string[]? DnssecAdditionalSigningKeyPaths { get; init; }
    public string? DnssecDenialMode { get; init; }
    public string? DnssecNsec3SaltHex { get; init; }
    public int? DnssecNsec3Iterations { get; init; }
}
sealed record DnsNameServerConfig(string Host,string Address);
sealed record DnsNameServer(string Host,IPAddress Address)
{
    public ushort RecordType => Address.AddressFamily == AddressFamily.InterNetwork ? (ushort)1 : (ushort)28;
}
sealed record DnsDelegationConfig(string Name,DnsNameServerConfig[] NameServers)
{
    public DnsDsRecordConfig[]? DsRecords { get; init; }
}
sealed record DnsDsRecordConfig(ushort KeyTag, byte Algorithm, byte DigestType, string DigestHex);
sealed record DnsDsRecord(byte[] Rdata);
sealed record DnsDelegation(string Name,DnsNameServer[] NameServers,DnsDsRecord[] DsRecords);
sealed record DnsSite(string Address,string? HealthUrl,int Weight,int Priority=0)
{
    public string[]? ValidatorUrls { get; init; }
    public string HealthCheckType { get; init; } = "Http";
    public int TcpPort { get; init; }
    public string? Region { get; init; }
    public string? AgentSiteId { get; init; }
    public string[]? RequiredAgentIds { get; init; }
    public int? MinimumHealthyAgentReports { get; init; }
    public string? AuthorityFenceSiteId { get; init; }
    public bool AdministrativelyQuarantined { get; init; }
}
sealed class Site
{
    public Site(IPAddress address,Uri? healthUrl,int weight,int priority,
        int failureThreshold,int successThreshold,string healthCheckType,int tcpPort,
        string? region,string? agentSiteId,string[] requiredAgentIds,string? authorityFenceSiteId = null)
    {
        Address=address;HealthUrl=healthUrl;Weight=weight;Priority=priority;
        HealthCheckType=healthCheckType;TcpPort=tcpPort;Region=region;
        AgentSiteId=agentSiteId;RequiredAgentIds=requiredAgentIds;
        AuthorityFenceSiteId=authorityFenceSiteId;
        Health=new DnsHealthHysteresis(failureThreshold,successThreshold);
    }
    public IPAddress Address {get;}
    public Uri? HealthUrl {get;}
    public string HealthCheckType {get;}
    public int TcpPort {get;}
    public string? Region {get;}
    public string? AgentSiteId { get; }
    public string[] RequiredAgentIds { get; }
    public string? AuthorityFenceSiteId { get; }
    public int Weight {get;}
    public int Priority {get;}
    public DnsHealthHysteresis Health {get;}
    public Uri[] Validators { get; init; } = [];
    public bool AdministrativelyQuarantined { get; init; }
    public long ValidatorDeadline;
    public DnsProbeLatency Latency {get;} = new();
    public int Healthy;
}
sealed class SiteGroup
{
    public SiteGroup(Site[] sites,int ttl,bool failClosedWhenAllSitesDown,
        DnsNameServer[] nameServers,string soaContact,uint soaSerial,string routingPolicy,
        DnsCidrRegionTable? cidrTable,bool enableEcsGeoRouting,
        DnsCidrRegionTable? trustedEcsResolvers,GeoIpEcsRegionTable? geoIpTable = null,
        DnsDelegation[]? delegations = null,
        string? dnssecPrivateKeyPath = null, string? zoneName = null,
        IReadOnlyList<string>? dnssecPrepublishPublicKeyPaths = null,
        IReadOnlyList<string>? dnssecAdditionalSigningKeyPaths = null,
        string dnssecDenialMode = "Nsec", string? dnssecNsec3SaltHex = null,
        int dnssecNsec3Iterations = 0)
    {
        (Sites,Ttl,FailClosedWhenAllSitesDown,NameServers,SoaContact,SoaSerial,RoutingPolicy,CidrTable)
            =(sites,ttl,failClosedWhenAllSitesDown,nameServers,soaContact,soaSerial,routingPolicy,cidrTable);
        EnableEcsGeoRouting=enableEcsGeoRouting;
        TrustedEcsResolvers=trustedEcsResolvers;
        GeoIpTable=geoIpTable;
        Delegations=delegations ?? [];
        if (!string.IsNullOrWhiteSpace(dnssecPrivateKeyPath))
            Dnssec = new DnssecZoneSigner(zoneName ?? throw new InvalidDataException("DNSSEC zone name is required"),
                (uint)ttl, dnssecPrivateKeyPath, soaContact, soaSerial, nameServers,
                Delegations, sites.Any(s => s.Address.AddressFamily == AddressFamily.InterNetwork),
                sites.Any(s => s.Address.AddressFamily == AddressFamily.InterNetworkV6),
                dnssecPrepublishPublicKeyPaths, dnssecAdditionalSigningKeyPaths,
                dnssecDenialMode, dnssecNsec3SaltHex, dnssecNsec3Iterations);
    }
    public string RoutingPolicy { get; }
    // 3 local successful measurements; at most 3 probe periods, clamped 6..60s.
    public const int LatencyMinimumSamples = 3;
    public const int LatencyMaximumAgeMs = 15_000;
    public DnsCidrRegionTable? CidrTable { get; }
    public bool EnableEcsGeoRouting { get; }
    public DnsCidrRegionTable? TrustedEcsResolvers { get; }
    public GeoIpEcsRegionTable? GeoIpTable { get; }
    public DnsNameServer[] NameServers { get; }
    public DnsDelegation[] Delegations { get; }
    public DnssecZoneSigner? Dnssec { get; }
    public string SoaContact { get; }
    public uint SoaSerial { get; }
    public bool FailClosedWhenAllSitesDown {get;}
    public Site[] Sites {get;}
    public int Ttl {get;}
    public long Counter=-1;
}
sealed class DnssecSignerLifetime(IEnumerable<SiteGroup> groups) : IDisposable
{
    public void Dispose()
    {
        foreach (var signer in groups.Select(group => group.Dnssec).OfType<DnssecZoneSigner>())
            signer.Dispose();
    }
}
