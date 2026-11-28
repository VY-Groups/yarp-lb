using System.Net;
using System.Net.Mail;
using System.Net.Http.Json;
using System.DirectoryServices.Protocols;
using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.Health;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.LoadBalancing;
#if GATEWAYCORE_COMMERCIAL
using GatewayCore.Licensing;
#endif

#if GATEWAYCORE_COMMERCIAL && GATEWAYCORE_RELEASE_PACKAGE
// Release package inventory is checked before any local command, service,
// listener, licensing state or other mutable runtime state is opened.
try
{
    var verifiedSource = CommercialReleaseIntegrity.Verify();
    if (args.Length == 1 && args[0] == "--verify-release")
    {
        Console.WriteLine("COMMERCIAL_RELEASE_INTEGRITY_PASS " + verifiedSource);
        return;
    }
}
catch (Exception ex) when (ex is IOException or CryptographicException or
    InvalidDataException or JsonException or FormatException or ArgumentException or
    InvalidOperationException or UnauthorizedAccessException)
{
    Console.Error.WriteLine("Commercial package integrity rejected: " + ex.GetType().Name);
    Environment.ExitCode = 78;
    return;
}
#endif

// Independent local VIP authority administration, not a gateway service action.
if(args.Length>0 && args[0]=="--vip-owner")
{
    if(args.Length is (7 or 8)&&args[3]=="inspect-policy")
    {
        Environment.ExitCode=VipServiceSecurity.InspectController(args);
        return;
    }
    if(args.Length is (7 or 8)&&args[3]=="recover-policy")
    {
        try{VipServiceSecurity.Controller(args);}
        catch(Exception e) when(e is IOException or InvalidDataException or InvalidOperationException or UnauthorizedAccessException or ArgumentException or JsonException)
        {Console.Error.WriteLine("VIP recovery configuration refused: "+e.GetType().Name);Environment.ExitCode=78;return;}
    }
    Environment.ExitCode=args.Length is (7 or 8)&&args[3]=="automatic-policy"
        ?await VipControllerService.Run(args):await VipOwnershipCommand.Run(args);
    return;
}

// Independent hardware fencing authority, not the gateway management plane.
if(args.Length>0 && args[0]=="--vip-redfish-provider")
{
    Environment.ExitCode=await VipRedfishProvider.Run(args);
    return;
}

if(args.Length>0 && args[0]=="--vip-node-agent")
{
    Environment.ExitCode=await VipNodeAgent.Run(args);
    return;
}

// Privileged independent node lifecycle; not callable from traffic listeners.
if(args.Length>0 && args[0]=="--vip-node")
{
    Environment.ExitCode=await VipNodeSupervisor.Run(args);
    return;
}

// Privileged local host administration, never an HTTP management endpoint.
if(args.Length>0 && args[0]=="--vip-address")
{
    Environment.ExitCode=await VipHostAddressCommand.Run(args);
    return;
}

// Initial TLS cannot depend on a web dashboard that has not started yet.
// This local command validates existing host-provisioned credentials and
// writes only a new configuration file; no listeners or runtime state start.
if (args.Length > 0 && args[0] == "--listener-bootstrap-wizard")
{
    Environment.ExitCode = GatewayListenerIsolation.RunBootstrapWizard(args);
    return;
}

// Explicit local operator command, never a remote management endpoint.
// Handle before constructing any listener, audit worker or other hosted service.
if(args.Length>0 && args[0]=="--linux-dp-key-issue")
{
    Environment.ExitCode=LinuxDistributedKeyIssue.Run(args);
    return;
}

// Windows neutral-identity deployments use a new ProgramData root. Refuse
// silent re-bootstrap when another YARP control plane already has identities.
// Disposable EC2 CI uses a private workspace; production Linux state is
// explicitly selected and owned through YARP_CONTROL_PLANE_DIR.
var ec2Lab = Ec2WorkflowLab.Enabled;
var privateDir = ec2Lab ? Ec2WorkflowLab.PrivateDirectory()
    : OperatingSystem.IsLinux() ? LinuxKeyProtection.InitializeStateDirectory()
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "GatewayCoreYarp", "ControlPlane");
#if !GATEWAYCORE_COMMERCIAL
// Read-only local installer preflight, before touching any state or keys.
if (args.Length == 1 && args[0] == "--windows-lab-check-residual-state")
{
    if (!OperatingSystem.IsWindows() || ec2Lab)
    {
        Environment.ExitCode = 78;
        return;
    }
    try
    {
        Console.WriteLine(JsonSerializer.Serialize(LegacyStateGuard.ClassifyResidualWindowsStores(privateDir)));
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
    {
        Console.Error.WriteLine(ex.Message);
        Environment.ExitCode = 78;
    }
    return;
}
#endif
if (OperatingSystem.IsWindows() && !ec2Lab)
{
    IReadOnlyCollection<string>? approvedResidualStores = null;
#if !GATEWAYCORE_COMMERCIAL
    // The ordinary lab installer places an exact, administrator-authorized
    // isolation list in SCM's service environment. It is not a migration,
    // global ignore switch, or commercial/production startup exemption.
    if (Microsoft.Extensions.Hosting.WindowsServices.WindowsServiceHelpers.IsWindowsService())
    {
        var approved = Environment.GetEnvironmentVariable("GATEWAYCORE_LAB_RESIDUAL_STORES");
        if (!string.IsNullOrEmpty(approved))
            approvedResidualStores = JsonSerializer.Deserialize<string[]>(Convert.FromBase64String(approved))
                ?? throw new InvalidOperationException("Invalid lab residual-store authorization");
    }
#endif
    LegacyStateGuard.RejectUnmigratedWindowsState(privateDir, approvedResidualStores);
}
if (OperatingSystem.IsWindows() && !ec2Lab)
    WindowsStateProtection.InitializeStateDirectory(Path.GetDirectoryName(privateDir)!, privateDir,
        installerLocalSystem: args.Length == 1 && args[0] == "--windows-prepare-state");
// Local installer provisioning uses the same fail-closed state checks above.
if (args.Length == 1 && args[0] == "--windows-prepare-state")
{
    if (!OperatingSystem.IsWindows() || ec2Lab)
        throw new InvalidOperationException("Windows state provisioning requires native Windows");
    Console.WriteLine("WINDOWS_STATE_READY");
    return;
}
if (!OperatingSystem.IsLinux() || ec2Lab)
    Directory.CreateDirectory(privateDir);
#if GATEWAYCORE_COMMERCIAL
var commercialLicense = new CommercialLicenseRuntime(Path.Combine(privateDir, "commercial-license"));
if (args.Length == 1 && args[0] == "--license-init")
{
    commercialLicense.Initialize();
    Console.WriteLine("Commercial installation identity provisioned. Sign in to export an activation request.");
    return;
}
commercialLicense.Refresh();
using var fleetQuorum=FleetQuorum.Open(Environment.GetEnvironmentVariable("GATEWAYCORE_FLEET_QUORUM_CONFIG"),true);
if (args.Length > 0 && args[0] == "--fleet-tls-lock")
{
    Environment.ExitCode = await FleetTlsOperator.RunAsync(args, privateDir, commercialLicense, fleetQuorum);
    return;
}
#endif
var keyDir = Path.Combine(privateDir, "data-protection-keys");
if (!OperatingSystem.IsLinux() || ec2Lab)
    Directory.CreateDirectory(keyDir);
var oidcPolicy = EnterpriseOidcPolicy.FromFile(Environment.GetEnvironmentVariable("GATEWAY_OIDC_CONFIG_FILE"));
using var sharedOidcRevocation = SharedOidcRevocation.FromFile(
    Environment.GetEnvironmentVariable("GATEWAY_OIDC_REVOCATION_REDIS_FILE"), oidcPolicy);
using var externalAuditIntent = ExternalAuditIntent.FromEnvironment(
    Environment.GetEnvironmentVariable("GATEWAY_AUDIT_INTENT_URL"),
    Environment.GetEnvironmentVariable("GATEWAY_AUDIT_NODE_ID"),
    Environment.GetEnvironmentVariable("GATEWAY_AUDIT_SENDER_KEY_FILE"),
    Environment.GetEnvironmentVariable("GATEWAY_AUDIT_COLLECTOR_PUBLIC_KEY_FILE"));
var auditOutboxPath = Environment.GetEnvironmentVariable("GATEWAY_AUDIT_OUTBOX_DIR");
if (auditOutboxPath is not null && externalAuditIntent is null)
    throw new InvalidOperationException("Audit outbox requires the external audit collector configuration");
using var auditOutbox = auditOutboxPath is null ? null : new DurableAuditOutbox(auditOutboxPath, externalAuditIntent!);
var localAudit = new LocalAdminAudit(Path.Combine(privateDir, "admin-audit.jsonl"), auditOutbox);
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddResponseCompression(options =>
{
    options.EnableForHttps = false;
    options.Providers.Add<Microsoft.AspNetCore.ResponseCompression.BrotliCompressionProvider>();
    options.Providers.Add<Microsoft.AspNetCore.ResponseCompression.GzipCompressionProvider>();
    options.MimeTypes = new[] { "text/css", "text/javascript", "application/javascript", "image/svg+xml" };
});
#if GATEWAYCORE_COMMERCIAL
builder.Services.AddHostedService<CommercialLicenseRuntime>(_ => commercialLicense);
#endif
// The SCM lifetime is activated only for a real Windows Service process.
// Interactive/CI console runs retain their prior lifetime and startup path.
// Do not alter DPAPI LocalMachine protection or create/migrate state here.
if (OperatingSystem.IsWindows())
    builder.Services.AddWindowsService(options => options.ServiceName = "GatewayCoreYarp");
if (auditOutbox is not null)
    builder.Services.AddHostedService(sp => new AuditOutboxWorker(auditOutbox, sp.GetRequiredService<ILogger<AuditOutboxWorker>>()));
var otlpConfigured = GatewayOpenTelemetry.Configure(builder.Services);
// Seed audit metrics before the first export: an unconfigured external audit
// path is explicitly disabled, not a successful empty/delivered queue.
if (auditOutbox is { } configuredAuditOutbox)
{
    var status = configuredAuditOutbox.Status();
    GatewayOpenTelemetry.ReportAuditOutboxStatus(
        true, status.Pending, status.StorageFault, status.DeliveryBlocked);
}
else GatewayOpenTelemetry.ReportAuditOutboxStatus(false, 0, false, false);
// Explicit v0.1 multi-socket mode; legacy loopback remains CI migration-only.
var isolatedListeners = GatewayListenerIsolation.FromEnvironment();
var guardedVirtualServices = isolatedListeners?.VirtualServices.Where(s => s.RequireLocalAddressPresence).ToArray();
// Readers have no write or lease capability; the node identity is its pinned client certificate.
using var vipAuthorityReaders = new VipAuthorityReaders();
var vipAuthorityChecks = new Dictionary<string,Func<CancellationToken,Task<bool>>>(StringComparer.Ordinal);
var vipEpochs=new Dictionary<string,long>(StringComparer.Ordinal);
if(guardedVirtualServices is not null)
    foreach(var group in guardedVirtualServices.Where(s=>s.VipQuorumConfigPath is not null)
        .GroupBy(s=>s.Ip,StringComparer.Ordinal))
    {
        // GatewayListenerIsolation validates that every socket on the same IP
        // uses identical authority, epoch and journal binding. Share only that
        // exact probe, and only inside the current bounded observation cycle.
        var service=group.First();
        var binding=service.VipJournalDirectory is null?null:new VipJournalBinding(service,IPAddress.Parse(isolatedListeners!.Config.ManagementIp));
        Func<bool>? localCheck=binding is null?null:binding.Current;
        var probe=vipAuthorityReaders.For(service.VipQuorumConfigPath!,
            FleetQuorum.VipScope(service.VipFleetId!,service.Ip),binding?.Epoch??service.VipOwnershipEpoch!.Value,localCheck);
        foreach(var socket in group)
        {
            vipAuthorityChecks.Add(socket.Id,probe);
            vipEpochs.Add(socket.Id,binding?.Epoch??service.VipOwnershipEpoch!.Value);
        }
    }
LocalVipAdmission? localVipAdmission = guardedVirtualServices is { Length: > 0 }
    ? new LocalVipAdmission(guardedVirtualServices.Select(s => (s.Id, s.Ip)), TimeProvider.System,vipAuthorityChecks) : null;
// Planned drain is address-wide and excludes any shared primary/unguarded socket.
var vipDrainPath=Path.Combine(privateDir,"vip-drain.json");
var vipDrainGroups=(isolatedListeners?.VirtualServices??Array.Empty<GatewayListenerIsolation.VirtualSocket>())
    .GroupBy(s=>IPAddress.Parse(s.Ip).ToString(),StringComparer.Ordinal)
    .Where(group=>group.All(s=>s.RequireLocalAddressPresence) &&
        isolatedListeners is not null && !IPAddress.Parse(group.Key).Equals(IPAddress.Parse(isolatedListeners.Config.TrafficIp)) &&
        !IPAddress.Parse(group.Key).Equals(IPAddress.Parse(isolatedListeners.Config.ManagementIp)))
    .ToDictionary(group=>group.Key,group=>group.Select(s=>s.Id).ToArray(),StringComparer.Ordinal);
var persistedVipDrains=VipDrainState.Read(vipDrainPath,vipDrainGroups.Keys);
// Dedicated machine identity, never a cookie administrator or general API principal.
var vipMachinePin=Environment.GetEnvironmentVariable("GATEWAYCORE_VIP_DRAIN_CLIENT_SHA256");
var vipMachineScope=Environment.GetEnvironmentVariable("GATEWAYCORE_VIP_DRAIN_SCOPE");
var vipMachineService=guardedVirtualServices?.FirstOrDefault(s=>s.VipJournalDirectory is not null &&
    FleetQuorum.VipScope(s.VipFleetId!,s.Ip)==vipMachineScope);
if((vipMachinePin is not null||vipMachineScope is not null)&&
    (!VipFenceProvider.Pin(vipMachinePin)||!VipFenceProvider.Pin(vipMachineScope)||vipMachineService is null))
    throw new InvalidDataException("Automatic drain requires an exact independent client pin and journal-bound VIP scope.");
var vipMachineEpoch=vipMachineService is null?0:vipEpochs[vipMachineService.Id];
var vipMachineAddress=vipMachineService is null?null:IPAddress.Parse(vipMachineService.Ip).ToString();
var vipMachinePath=vipMachineService is null?null:Path.Combine(privateDir,"vip-auto-drain-"+vipMachineScope+".json");
var activeAutomaticDrains=new HashSet<string>(StringComparer.Ordinal);
foreach(var service in (guardedVirtualServices??[]).Where(s=>s.VipJournalDirectory is not null))
{
    var scope=FleetQuorum.VipScope(service.VipFleetId!,service.Ip);
    var path=Path.Combine(privateDir,"vip-auto-drain-"+scope+".json");
    if(VipMachineDrainState.Read(path,scope,vipEpochs[service.Id]))activeAutomaticDrains.Add(service.Id);
}
var vipMachineDrained=vipMachineService is not null&&activeAutomaticDrains.Contains(vipMachineService.Id);
var vipMachineAuthKey=new object();
if (localVipAdmission is not null)
{
    localVipAdmission.SetPlannedDrains(persistedVipDrains.SelectMany(ip=>vipDrainGroups[ip]));
    localVipAdmission.SetAutomaticDrains(activeAutomaticDrains);
    builder.Services.AddHostedService<LocalVipAdmission>(_ => localVipAdmission);
}
var acmeChallengeSetting = Environment.GetEnvironmentVariable("YARP_ACME_HTTP01_PUBLIC_ENTRYPOINT");
if (acmeChallengeSetting is not null && !bool.TryParse(acmeChallengeSetting, out _))
    throw new InvalidOperationException("YARP_ACME_HTTP01_PUBLIC_ENTRYPOINT must be true or false");
var acmeHttp01PublicEntrypointEnabled = string.Equals(acmeChallengeSetting, "true", StringComparison.OrdinalIgnoreCase);
if (acmeHttp01PublicEntrypointEnabled && isolatedListeners is null)
    throw new InvalidOperationException("ACME HTTP-01 requires the explicitly configured isolated traffic listener");
var acmeConfigurationPath = Environment.GetEnvironmentVariable("YARP_ACME_CONFIG_FILE");
AcmeRenewalSettings? acmeRenewalSettings = null;
if (!string.IsNullOrWhiteSpace(acmeConfigurationPath))
{
    if (ec2Lab || isolatedListeners is null)
        throw new InvalidOperationException(
            "ACME renewal requires production Data Protection and isolated traffic TLS listeners");
    acmeRenewalSettings = AcmeRenewalSettings.Load(acmeConfigurationPath,
        isolatedListeners.Config.TrafficPfxPath, isolatedListeners.Config.TrafficPfxPasswordFile,
        isolatedListeners.Config.TrafficCertificateDnsNames);
    if (!acmeRenewalSettings.EnableDns01Renewal && !acmeHttp01PublicEntrypointEnabled)
        throw new InvalidOperationException(
            "HTTP-01 renewal requires an explicitly enabled public challenge listener");
    // DNS-01 startup does not require TCP/80. It requires a separately
    // pinned TSIG update authority plus independent authoritative probes.
}
builder.Services.AddSingleton<AcmeHttp01ChallengeStore>();
isolatedListeners?.Configure(builder.WebHost);
if (isolatedListeners is not null)
    // Register through a factory so the host owns and disposes the listener's
    // certificate rotation watcher and its temporary persisted key material.
    builder.Services.AddSingleton<GatewayListenerIsolation>(_ => isolatedListeners);
// Production and the GatewayLab use the same nonblocking registration.
var boundedConsole = GatewayLoggingConfiguration.Install(builder.Logging, Console.Out);
var dataProtection = builder.Services.AddDataProtection()
    .SetApplicationName("GatewayCoreYarpControlCenter")
    .PersistKeysToFileSystem(new DirectoryInfo(keyDir));
if (OperatingSystem.IsWindows())
{
    // Preserve DPAPI LocalMachine for the standard local-node install.
    // The explicitly selected single-tenant fleet mode wraps portable keys
    // with a pinned, independently provisioned LocalMachine RSA certificate.
    // An invalid fleet configuration fails startup; NEVER silently falls
    // back to local DPAPI or unencrypted persistent key storage.
    if (!WindowsFleetKeyProtection.TryConfigure(dataProtection, keyDir))
        dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);
}
else if (OperatingSystem.IsLinux() && !ec2Lab)
    LinuxKeyProtection.Configure(dataProtection, privateDir);
else if (ec2Lab)
    Console.Error.WriteLine("WARNING: CI-only EC2 lab uses temporary, unencrypted local Data Protection keys. Never use in production.");
else
    throw new PlatformNotSupportedException("Unsupported OS Data Protection mode");
var stagedImportEnabled = !ec2Lab && isolatedListeners?.Config.TrafficCertificateDnsNames is { Length: > 0 } &&
    string.Equals(Environment.GetEnvironmentVariable("YARP_STAGED_TRAFFIC_CERTIFICATE_IMPORT"), "true", StringComparison.OrdinalIgnoreCase);
if (stagedImportEnabled || acmeRenewalSettings is not null)
    builder.Services.AddSingleton<AcmeCertificateLifecycleGate>();
if (stagedImportEnabled)
{
    var settings = isolatedListeners!.Config;
    builder.Services.AddSingleton(services => new StagedTrafficCertificate(settings.TrafficPfxPath,
        settings.TrafficPfxPasswordFile, settings.TrafficCertificateDnsNames!,
        isolatedListeners.IsTrafficCertificateActive, services.GetRequiredService<AcmeCertificateLifecycleGate>()));
}
if (acmeRenewalSettings is { } renewalSettings)
{
    var activeListeners = isolatedListeners ?? throw new InvalidOperationException(
        "ACME requires the isolated traffic listener certificate rotator.");
    // Fail startup *before* creating a renewal worker if the DNS-01
    // update executable, private TSIG, zone or pinned authorities are
    // unavailable. Never send DNS credentials through a management API.
    IAcmeDns01Publisher? dns01Publisher = renewalSettings.EnableDns01Renewal
        ? renewalSettings.Dns01Publisher!.CreateVerifiedPublisher()
        : null;
    var accountKeyPath = Path.Combine(privateDir, "acme-account.encrypted");
    builder.Services.AddSingleton<IAcmeCertificateIssuer>(services => new CertesAcmeCertificateIssuer(
        new AcmeAccountKeyStore(accountKeyPath,
            services.GetRequiredService<IDataProtectionProvider>().CreateProtector("GatewayCore.AcmeAccountKeyProtector.v1")),
        renewalSettings.AgreeToTermsOfService));
    builder.Services.AddSingleton<AcmeRenewalCoordinator>(services => new AcmeRenewalCoordinator(
        services.GetRequiredService<IAcmeCertificateIssuer>(),
        services.GetRequiredService<AcmeHttp01ChallengeStore>(),
        isCertificateActive: activeListeners.IsTrafficCertificateActive,
        lifecycleGate: services.GetRequiredService<AcmeCertificateLifecycleGate>()));
    builder.Services.AddSingleton<AcmeRevocationCoordinator>(services => new AcmeRevocationCoordinator(
        services.GetRequiredService<IAcmeCertificateIssuer>(), renewalSettings.DirectoryUrl,
        renewalSettings.DnsName, renewalSettings.ContactEmail, activeListeners.IsTrafficCertificateActive,
        services.GetRequiredService<AcmeCertificateLifecycleGate>()));
    builder.Services.AddSingleton<AcmeRenewalBackgroundService>(services => new AcmeRenewalBackgroundService(renewalSettings,
        services.GetRequiredService<AcmeRenewalCoordinator>(), null,
        services.GetRequiredService<ILogger<AcmeRenewalBackgroundService>>(),
        dns01Publisher));
    builder.Services.AddHostedService<AcmeRenewalBackgroundService>(services =>
        services.GetRequiredService<AcmeRenewalBackgroundService>());
}
// Keep executable/static assets read-only under /opt on hardened Linux.
// Management may atomically update ONLY a private state-directory config.
var runtimeConfig = Environment.GetEnvironmentVariable("YARP_RUNTIME_CONFIG_PATH");
var applicationConfigPath = string.IsNullOrWhiteSpace(runtimeConfig)
    ? Path.Combine(builder.Environment.ContentRootPath,"appsettings.json")
    : runtimeConfig;
if (OperatingSystem.IsLinux() && !ec2Lab)
{
    if (string.IsNullOrWhiteSpace(runtimeConfig) || !Path.IsPathFullyQualified(runtimeConfig))
        throw new InvalidOperationException("Linux requires absolute YARP_RUNTIME_CONFIG_PATH under the private state directory");
    applicationConfigPath = Path.GetFullPath(applicationConfigPath);
    var rel = Path.GetRelativePath(privateDir, applicationConfigPath);
    if (rel.StartsWith("..", StringComparison.Ordinal) || Path.IsPathRooted(rel) ||
        !rel.Equals(Path.Combine("config","appsettings.json"),StringComparison.Ordinal))
        throw new InvalidOperationException("Linux YARP runtime config must be state/config/appsettings.json");
    if (!File.Exists(applicationConfigPath) ||
        (File.GetAttributes(applicationConfigPath) & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Linux runtime config must exist and must not be a symlink");
}
builder.Configuration.AddJsonFile(applicationConfigPath, optional: false, reloadOnChange: true);
builder.Services.AddSingleton<ExpiringAffinityTokens>();
builder.Services.AddSingleton<Yarp.ReverseProxy.SessionAffinity.ISessionAffinityPolicy>(sp =>
    new ExpiringCookieAffinityPolicy(sp.GetRequiredService<ExpiringAffinityTokens>(), TimeProvider.System));
builder.Services.AddSingleton<Microsoft.AspNetCore.Routing.MatcherPolicy>(new VirtualServiceMatcherPolicy(isolatedListeners));
builder.Services.AddSingleton<Yarp.ReverseProxy.Configuration.IProxyConfigFilter>(new VirtualServiceRouteFilter(isolatedListeners));
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .AddConfigFilter<DestinationAdmissionConfigFilter>()
    .AddConfigFilter<ActiveCompoundConfigFilter>()
    .AddConfigFilter<SecureAffinityContract>()
    .AddConfigFilter<ApplicationAccessFilter>();
builder.Services.AddSingleton<Yarp.ReverseProxy.Forwarder.IForwarderHttpClientFactory, CompoundForwarderFactory>();
CompoundProbingRequestFactory.Register(builder.Services);
builder.Services.AddSingleton<DestinationAdmissionManager>();
builder.Services.AddHostedService<DestinationAdmissionRegistryReconciler>();
// Custom policies are registered on every serving YARP instance, never on the UI alone.
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedLeastRequestsPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRoundRobinPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, FastestResponsePolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, PrimaryBackupPolicy>();
// Poll YARP active-health state independently of incoming requests.
builder.Services.AddHostedService<AutonomousRecoveryObserver>();
// Opt-in by cluster.HealthCheck.Passive.Policy only. No request replay.
builder.Services.AddSingleton<IPassiveHealthCheckPolicy, BoundedTransportFailureHealthPolicy>();
builder.Services.AddSingleton<IActiveHealthCheckPolicy, RiseFallActiveHealthPolicy>();
var adminAuthentication = builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "GatewayCoreYarpAdmin";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = oidcPolicy is null ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always; // OIDC never permits HTTP
        // Inactivity timeout for interactive local administration. Renew only on
        // authenticated user requests (never via background polling).
        options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        options.SlidingExpiration = true;
        options.Events.OnValidatePrincipal = async ctx =>
        {
            try
            {
                var path = Path.Combine(privateDir, "admin-users.json");
                var users = JsonSerializer.Deserialize<List<AdminUser>>(await File.ReadAllTextAsync(path)) ?? new();
                var active = users.FirstOrDefault(u => u.Username.Equals(ctx.Principal?.Identity?.Name, StringComparison.OrdinalIgnoreCase));
                var role = ctx.Principal?.FindFirst(ClaimTypes.Role)?.Value;
                if (active is null || !active.Enabled || active.Role != role ||
                    active.SecurityStamp != ctx.Principal?.FindFirst("stamp")?.Value)
                { ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return; }
                var principal = ctx.Principal!;
                var oidcSubject = principal.FindFirst(EnterpriseOidcPolicy.SubjectClaim)?.Value;
                if (oidcPolicy is not null)
                {
                    var allowed = active.Provider == "Local" && (oidcSubject is not null
                        ? oidcPolicy.SessionValid(principal, active.Username, active.Role, DateTimeOffset.UtcNow) &&
                          EnterpriseOidcPolicy.AfterRevocation(principal, active.OidcRevokedBefore)
                        : oidcPolicy.RecoverySessionValid(principal, active.Username, active.Role, active.Provider));
                    if (allowed && sharedOidcRevocation is not null && oidcSubject is not null)
                        allowed = long.TryParse(EnterpriseOidcPolicy.Single(principal, EnterpriseOidcPolicy.AuthTimeClaim),
                            System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var authTime) &&
                            await sharedOidcRevocation.AllowsAsync(oidcSubject, authTime, active.OidcRevokedBefore);
                    if (!allowed)
                    { ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return; }
                }
                else if (oidcSubject is not null || principal.HasClaim(c => c.Type == EnterpriseOidcPolicy.RecoveryClaim))
                { ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); return; }
                // Fail closed if the AD account is disabled, its group membership changes, or LDAPS is unreachable.
                if (active.Provider == "AD" && !ctx.HttpContext.RequestServices.GetRequiredService<DirectoryAuthService>()
                    .StillAuthorized(active.Username, active.DistinguishedName, role ?? ""))
                { ctx.RejectPrincipal(); await ctx.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme); }
            }
            catch { ctx.RejectPrincipal(); }
        };
        options.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
        options.Events.OnRedirectToAccessDenied = ctx => { ctx.Response.StatusCode = 403; return Task.CompletedTask; };
    });
if (oidcPolicy is not null)
    EnterpriseOidcAuthentication.Configure(adminAuthentication, oidcPolicy,
        Path.Combine(privateDir, "admin-users.json"), localAudit, sharedOidcRevocation);
builder.Services.AddAuthorization();
builder.Services.AddSingleton<DirectoryAuthService>(sp =>
    new DirectoryAuthService(sp.GetRequiredService<IDataProtectionProvider>(), privateDir));
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    var proxyBounds = ProxyConcurrencySettings.FromEnvironment(
        Environment.GetEnvironmentVariable("GATEWAY_PROXY_CONCURRENCY"),
        Environment.GetEnvironmentVariable("GATEWAY_PROXY_QUEUE_LIMIT"));
    options.AddConcurrencyLimiter("proxy-concurrency", cfg =>
    {
        cfg.PermitLimit = proxyBounds.PermitLimit;
        cfg.QueueLimit = proxyBounds.QueueLimit;
        cfg.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
    });
    options.AddFixedWindowLimiter("oidc-logout", cfg =>
    { cfg.PermitLimit = 32; cfg.Window = TimeSpan.FromMinutes(1); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("mailtest", cfg => { cfg.PermitLimit = 3; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("ldaptest", cfg => { cfg.PermitLimit = 4; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("acme-revoke", cfg => { cfg.PermitLimit = 2; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("waf-dashboard-deployment", cfg => { cfg.PermitLimit = 2; cfg.Window = TimeSpan.FromMinutes(1); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("tls-stage-import", cfg => { cfg.PermitLimit = 4; cfg.Window = TimeSpan.FromMinutes(1); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("acme-renew-due", cfg => { cfg.PermitLimit = 1; cfg.Window = TimeSpan.FromMinutes(10); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("employee-invite-issue", cfg =>
    { cfg.PermitLimit = 8; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("employee-invite-redeem", cfg =>
    { cfg.PermitLimit = 24; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("first-run", cfg =>
    { cfg.PermitLimit = 24; cfg.Window = TimeSpan.FromMinutes(5); cfg.QueueLimit = 0; });
    options.AddFixedWindowLimiter("login", cfg =>
    {
        cfg.PermitLimit = 8;
        cfg.Window = TimeSpan.FromMinutes(5);
        cfg.QueueLimit = 0;
        cfg.AutoReplenishment = true;
    });
});
builder.Services.AddHttpClient("probe").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false, UseCookies = false });
var sharedPeerLimiter = SharedPeerRateLimiter.FromEnvironment(
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_SHARED_REDIS"),
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_SHARED_HMAC_KEY"),
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_IP_RATE_PER_MINUTE"),
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_IP_TABLE_CAPACITY"),
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_SHARED_NAMESPACE"));
var peerRateTable = sharedPeerLimiter is null ? BoundedPeerRateTable.FromEnvironment(
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_IP_RATE_PER_MINUTE"),
    Environment.GetEnvironmentVariable("GATEWAY_PROXY_IP_TABLE_CAPACITY")) : null;
var peerSyncSettings = PeerSyncSettings.FromEnvironment(
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_NODE_ID"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_REMOTE_ID"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_REMOTE_URL"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_SECRET"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_CAPACITY"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_INTERVAL_SECONDS"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_SIGNING_SECRET"),
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_PREVIOUS_SIGNING_SECRET"));
if (peerSyncSettings is not null)
{
    builder.Services.AddSingleton(peerSyncSettings);
    builder.Services.AddSingleton(sp => new PeerStateJournal(peerSyncSettings.NodeId,
        peerSyncSettings.RemoteId, peerSyncSettings.Secret, peerSyncSettings.Capacity,
        TimeSpan.FromSeconds(Math.Clamp(peerSyncSettings.IntervalSeconds * 3, 6, 60))));
    builder.Services.AddSingleton(sp => new PeerSignedMessages(
        peerSyncSettings.SigningSecret ?? peerSyncSettings.Secret, peerSyncSettings.PreviousSigningSecret));
    builder.Services.AddSingleton<PeerSyncPublisherDiagnostics>();
    builder.Services.AddHttpClient("peer-sync", client => client.Timeout = TimeSpan.FromSeconds(5))
        .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler {
            AllowAutoRedirect = false, UseCookies = false
        });
    builder.Services.AddHostedService(sp => new PeerSyncPublisher(peerSyncSettings,
        sp.GetRequiredService<PeerStateJournal>(), sp.GetRequiredService<PeerSignedMessages>(),
        sp.GetRequiredService<IHttpClientFactory>(),
        sp.GetRequiredService<ILogger<PeerSyncPublisher>>(),
        sp.GetRequiredService<PeerSyncPublisherDiagnostics>()));
}
var app = builder.Build();
// Count config reload notifications as an operational signal, not proof that new routing was applied.
var configurationReloadTelemetry = GatewayOpenTelemetry.WatchConfigurationReloads(builder.Configuration);
app.Lifetime.ApplicationStopping.Register(configurationReloadTelemetry.Dispose);
var accessLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayCore.AccessLog");
// Avoid even constructing/exporting the additional access-summary event
// when no OTLP exporter was configured at startup.
var telemetryAccessLogger = otlpConfigured
    ? app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayCore.TelemetryAccess")
    : null;
var trustedAccessLogProxies = GatewayClientAddress.ParseTrustedProxyAddresses(
    Environment.GetEnvironmentVariable("GATEWAY_TRUSTED_PROXY_IPS"));
var peerStateJournal = app.Services.GetService<PeerStateJournal>();
var peerSigner = app.Services.GetService<PeerSignedMessages>();
var peerPublisherDiagnostics = app.Services.GetService<PeerSyncPublisherDiagnostics>();
if (sharedPeerLimiter is not null)
    app.Lifetime.ApplicationStopped.Register(sharedPeerLimiter.Dispose);
if (ec2Lab)
{
    // Read-only, loopback-only snapshot of the actual in-memory YARP model,
    // not merely the latest on-disk test configuration. Never mapped in
    // production or on a remote public management listener.
    app.MapGet("/gateway/ec2-lab/loaded-config", (HttpContext ctx, IProxyStateLookup state) =>
    {
        if (ctx.Connection.RemoteIpAddress is not { } addr || !IPAddress.IsLoopback(addr))
            return Results.StatusCode(403);
        var cluster = state.GetClusters().FirstOrDefault(c => c.ClusterId == "ec2");
        if (cluster is null) return Results.StatusCode(503);
        return Results.Ok(new {
            policy = cluster.Model.Config.LoadBalancingPolicy,
            destinations = cluster.Destinations.Values.ToDictionary(
                d => d.DestinationId,
                d => d.Model.Config.Metadata is { } md &&
                     md.TryGetValue("Weight", out var weight) ? weight : "1")
        });
    });
}
// Strictly loopback/admin-only readout. A non-zero drop count is an ALERT,
// never an alternative to the separately persisted security audit trail.
app.MapGet("/admin/api/logging-health", () => Results.Ok(new {
    mode = "bounded-drop-and-count",
    capacity = boundedConsole.Capacity,
    queued = boundedConsole.QueuedMessages,
    enqueuedTotal = boundedConsole.EnqueuedMessages,
    writtenTotal = boundedConsole.WrittenMessages,
    droppedTotal = boundedConsole.DroppedMessages,
    droppedLowPriorityTotal = boundedConsole.DroppedLowPriorityMessages,
    droppedHighPriorityTotal = boundedConsole.DroppedHighPriorityMessages,
    writeErrorsTotal = boundedConsole.WriteErrors,
    guidance = "Alert on any rise in droppedTotal or writeErrorsTotal; audit is separate."
})).RequireAuthorization();
// Organization profile is a management-only API; existing CSRF, admin-role and loopback middleware apply.

var directoryAuth = app.Services.GetRequiredService<DirectoryAuthService>();
var root = app.Environment.ContentRootPath;
var usersPath = Path.Combine(privateDir, "admin-users.json");
var setupCodePath = Path.Combine(privateDir, "first-run-code.txt");
#if GATEWAYCORE_COMMERCIAL
const bool setupEnrollmentRequired = false;
#else
// Windows lab Setup provisions a private, installation-bound local claim.
var setupEnrollmentRequired = Environment.GetEnvironmentVariable("GATEWAYCORE_REQUIRE_SETUP_OTP") == "1"
    || File.Exists(setupCodePath);
SetupEnrollment? setupEnrollment = null;
#endif
var inventoryPath = Path.Combine(privateDir, "inventory.json");
var backupFolder = Path.Combine(privateDir, "config-backups");
Directory.CreateDirectory(backupFolder);
var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var loginGate = new SemaphoreSlim(1, 1);
#if !GATEWAYCORE_COMMERCIAL
// Process-local invitations are deliberately invalidated by a service restart.
// The account writer gate serializes issue, revoke, verify and redemption.
var employeeInvitations = new Dictionary<string, EmployeeInvitation>(StringComparer.Ordinal);
#endif
var pendingOtp = new ConcurrentDictionary<string, OtpChallenge>();
var mailPath = Path.Combine(privateDir, "mail-settings.json");
var mailProofPath = Path.Combine(privateDir, "mail-test-proof.sha256");
var directoryPath = Path.Combine(privateDir, "active-directory.json");
var identitySettingsGate = new SemaphoreSlim(1, 1);
var protector = app.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("GatewayCoreYarp.AdminMail.v1");
MailSettings ReadMail() => File.Exists(mailPath)
    ? JsonSerializer.Deserialize<MailSettings>(File.ReadAllText(mailPath), jsonOptions) ?? new MailSettings()
    : new MailSettings();
string MailFingerprint(MailSettings cfg) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
    $"{cfg.Host.ToLowerInvariant()}|{cfg.Port}|{cfg.From.ToLowerInvariant()}|{cfg.Username}|{cfg.StartTls}|{cfg.EncryptedPassword}|{cfg.AuthMode}|{cfg.OAuthClientId}|{cfg.OAuthTenant}|{cfg.EncryptedOAuthClientSecret}|{cfg.EncryptedOAuthRefreshToken}")));
bool MailDeliveryVerified(MailSettings cfg) => File.Exists(mailProofPath) &&
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(File.ReadAllText(mailProofPath).Trim()),
        Encoding.UTF8.GetBytes(MailFingerprint(cfg)));
async Task SendMailMessage(string recipient, string subject, string body, MailSettings? snapshot = null)
{
    var cfg = snapshot ?? ReadMail();
    if (string.IsNullOrWhiteSpace(cfg.Host) || cfg.Port is < 1 or > 65535 ||
        cfg.Port == 465 || !ValidEmail(cfg.From) || !ValidEmail(recipient))
        throw new InvalidOperationException("SMTP host, supported port, sender and recipient must be configured.");
    // Never downgrade to plaintext or ignore the server certificate.
    // MailKit validates the platform CA trust store and hostname by default.
    if (!cfg.StartTls) throw new InvalidOperationException("STARTTLS is required for management OTP mail.");
    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
    using var smtp = new MailKit.Net.Smtp.SmtpClient();
    // Standard certificate/hostname checks remain MANDATORY. The callback
    // only records safe TLS policy and chain error categories on rejection.
    smtp.ServerCertificateValidationCallback = (_, _, chain, errors) =>
    {
        if (errors != System.Net.Security.SslPolicyErrors.None)
            app.Logger.LogWarning("SMTP_TLS_CERT_REJECTED policy={Policy} chain={Chain}",
                errors, string.Join(",", chain?.ChainStatus.Select(x => x.Status.ToString()) ?? Enumerable.Empty<string>()));
        return errors == System.Net.Security.SslPolicyErrors.None;
    };
    await smtp.ConnectAsync(cfg.Host, cfg.Port, MailKit.Security.SecureSocketOptions.StartTls, timeout.Token);
    var mode = cfg.AuthMode;
    if (MailProviderAuth.UsesOAuth(mode))
    {
        // Reject untrusted SMTP hosts BEFORE fetching or sending an OAuth token.
        var validation = MailProviderAuth.Validate(mode, cfg.Host, cfg.Username,
            cfg.OAuthTenant, cfg.OAuthClientId,
            !string.IsNullOrEmpty(cfg.EncryptedOAuthClientSecret),
            !string.IsNullOrEmpty(cfg.EncryptedOAuthRefreshToken));
        if (validation != null) throw new InvalidOperationException(validation);
        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(9) };
        var token = await MailProviderAuth.FetchAccessTokenAsync(
            mode, cfg.OAuthTenant, cfg.OAuthClientId,
            protector.Unprotect(cfg.EncryptedOAuthClientSecret),
            mode == MailProviderAuth.MicrosoftApp ? "" : protector.Unprotect(cfg.EncryptedOAuthRefreshToken),
            client, timeout.Token);
        await smtp.AuthenticateAsync(new MailKit.Security.SaslMechanismOAuth2(cfg.Username, token), timeout.Token);
    }
    else if (!string.IsNullOrWhiteSpace(cfg.Username))
        await smtp.AuthenticateAsync(cfg.Username, protector.Unprotect(cfg.EncryptedPassword), timeout.Token);
    var message = new MimeKit.MimeMessage();
    message.From.Add(MimeKit.MailboxAddress.Parse(cfg.From));
    message.To.Add(MimeKit.MailboxAddress.Parse(recipient));
    message.Subject = subject;
    message.Body = new MimeKit.TextPart("plain") { Text = body };
    await smtp.SendAsync(message, timeout.Token);
    await smtp.DisconnectAsync(true, timeout.Token);
}
async Task SendOtp(string recipient, string code)
{
    var cfg = ReadMail();
    if (!cfg.Enabled || !MailDeliveryVerified(cfg)) throw new InvalidOperationException("Verified OTP not enabled");
    await SendMailMessage(recipient, "YARP Control Center sign-in code",
        $"Your one-time sign-in code is {code}. It expires in 5 minutes. Do not share this code.", cfg);
}
var configPath = applicationConfigPath;
var gate = new SemaphoreSlim(1, 1);
// MANAGEMENT IS LOOPBACK-ONLY IN THIS RELEASE. Never bind management to the public VIP.
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path;
    var adminPath = path.StartsWithSegments("/admin") || path.StartsWithSegments("/dashboard") || path == "/";
    if (isolatedListeners is not null && !isolatedListeners.Permit(ctx))
    {
        ctx.Response.StatusCode = 403; return;
    }
    IDisposable? vipRequest=null;
    if (localVipAdmission is not null && !localVipAdmission.TryEnter(isolatedListeners?.VirtualServiceId(ctx),ctx.Abort,out vipRequest))
    {
        ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        ctx.Response.Headers.CacheControl = "no-store";
        return;
    }
    using var vipRequestLifetime=vipRequest;
    if (adminPath)
    {
        if (oidcPolicy is not null && !oidcPolicy.MatchesOrigin(ctx.Request.Scheme, ctx.Request.Host.Value))
        { ctx.Response.StatusCode = 403; return; }
        if (isolatedListeners is null && (ctx.Connection.RemoteIpAddress is null || !IPAddress.IsLoopback(ctx.Connection.RemoteIpAddress)))
        {
            ctx.Response.StatusCode = 403; return;
        }
        ctx.Response.Headers.CacheControl = "no-store";
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
        if (ctx.Request.Method is "POST" or "PUT" or "PATCH" or "DELETE")
        {
            var origin = ctx.Request.Headers.Origin.ToString();
            if (!string.IsNullOrWhiteSpace(origin) &&
                (!Uri.TryCreate(origin, UriKind.Absolute, out var o) ||
                 !string.Equals(o.Authority, ctx.Request.Host.Value, StringComparison.OrdinalIgnoreCase)))
            { ctx.Response.StatusCode = 403; return; }
            // Form posts are limited to the independently signed IdP notice
            // and the authenticated, CSRF-protected RP logout form.
            if (ctx.Request.Method == "POST" && ctx.Request.Path == EnterpriseOidcLogout.Path && oidcPolicy is not null)
            {
                if (ctx.Request.ContentLength is not long size || size < 1 || size > EnterpriseOidcLogout.MaxForm ||
                    !string.Equals(ctx.Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
                { ctx.Response.StatusCode = 400; return; }
            }
            else if (ctx.Request.Method == "POST" && ctx.Request.Path == "/admin/api/logout" &&
                string.Equals(ctx.Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
            {
                if (oidcPolicy is null || ctx.Request.ContentLength is not long size || size < 1 || size > 1024)
                { ctx.Response.StatusCode = 400; return; }
            }
            else if (!ctx.Request.HasJsonContentType()) { ctx.Response.StatusCode = 415; return; }
        }
    }
    await next();
});
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
#if GATEWAYCORE_COMMERCIAL
app.Use(async (ctx, next) =>
{
    if (CommercialLicenseRuntime.FleetRecoveryEndpoint(ctx.Request.Method,ctx.Request.Path))
    {
        if(ctx.User.Identity?.IsAuthenticated!=true){ctx.Response.StatusCode=401;return;}
        if(!ctx.User.IsInRole("Administrator")){ctx.Response.StatusCode=403;return;}
        // Only the exact rollback journal endpoints bypass entitlement;
        // existing audit, CSRF, original inventory and revision checks remain.
    }
    else if (ctx.Request.Path.StartsWithSegments("/admin/api") &&
        !CommercialLicenseRuntime.RecoveryEndpoint(ctx.Request.Path))
    {
        if (ctx.User.Identity?.IsAuthenticated != true) { ctx.Response.StatusCode = 401; return; }
        if (!commercialLicense.Permits(ctx.Request.Path))
        {
            ctx.Response.StatusCode = 402;
            await ctx.Response.WriteAsJsonAsync(new { error = "A valid GatewayCore license or feature entitlement is required.", code = "license_required" });
            return;
        }
    }
    await next();
});
#endif
// Enforce acknowledgement on management APIs, not just browser navigation.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/admin/api") &&
        !ManagementPrivacyPolicy.Exempt(ctx.Request.Path) &&
        ctx.GetEndpoint()?.Metadata.GetMetadata<EmployeeInvitationRedemptionEndpoint>() is null)
    {
        if (ctx.User.Identity?.IsAuthenticated != true)
        { ctx.Response.StatusCode = 401; return; }
        if (!ManagementPrivacyPolicy.Accepted(ctx))
        {
            ctx.Response.StatusCode = 428;
            await ctx.Response.WriteAsJsonAsync(new { error = "Please accept the Privacy Policy before using GatewayCore.", code = "privacy_policy_required" });
            return;
        }
    }
    await next();
});
// Process-local, low-cardinality HTTP request telemetry. This is NOT per-destination
// YARP telemetry and is reset on each process restart.
long requestsTotal = 0, requests2xx = 0, requests4xx = 0, requests5xx = 0, durationTicks = 0;
var requestHistogram = new GatewayRequestHistogram();
var processStartedUtc = DateTimeOffset.UtcNow;
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/admin") || ctx.Request.Path.StartsWithSegments("/dashboard") ||
        ctx.Request.Path.StartsWithSegments("/gateway")) { await next(); return; }
    var started = System.Diagnostics.Stopwatch.GetTimestamp();
    var clientAddress = GatewayClientAddress.ForAccessLog(ctx.Connection.RemoteIpAddress,
        ctx.Request.Headers["X-Forwarded-For"].ToString(), trustedAccessLogProxies);
    requestHistogram.Started();
    try { await next(); }
    finally
    {
        Interlocked.Increment(ref requestsTotal);
        var code = ctx.Response.StatusCode;
        if (code is >= 200 and < 300) Interlocked.Increment(ref requests2xx);
        if (code is >= 400 and < 500) Interlocked.Increment(ref requests4xx);
        if (code >= 500) Interlocked.Increment(ref requests5xx);
        var elapsed = System.Diagnostics.Stopwatch.GetTimestamp() - started;
        Interlocked.Add(ref durationTicks, elapsed);
        requestHistogram.Finished(elapsed);
        var routeCandidate = ctx.Features.Get<IReverseProxyFeature>()?.Route?.Config.RouteId;
        var routeId = routeCandidate is not null && ValidId(routeCandidate) ? routeCandidate : "unmatched";
        var timestampUtc = DateTimeOffset.UtcNow;
        var durationMs = Math.Round(elapsed * 1000.0 /
            System.Diagnostics.Stopwatch.Frequency, 3);
        GatewayOpenTelemetry.LogAccess(accessLogger,
            timestampUtc, clientAddress.Address?.ToString() ?? "unknown", clientAddress.Source,
            ctx.Request.Method, routeId, ctx.Response.StatusCode, durationMs);
        // Only bounded, non-identifying fields cross the OTLP exporter.
        // The local access record above remains unchanged for every request.
        if (telemetryAccessLogger is not null)
            GatewayOpenTelemetry.LogTelemetryAccess(telemetryAccessLogger,
                timestampUtc, GatewayOpenTelemetry.BoundedTelemetryMethod(ctx.Request.Method),
                GatewayOpenTelemetry.IsSafeTelemetryId(routeId) ? routeId : "_other",
                ctx.Response.StatusCode, durationMs);
    }
});
var destinationTelemetry = new DestinationTelemetry();
app.MapGet("/admin/api/destination-metrics", () => Results.Ok(new {
    scope = "This gateway instance; routed requests only; counters reset after restart",
    timestampUtc = DateTimeOffset.UtcNow,
    trackedDestinationLimit = DestinationTelemetry.MaximumTrackedDestinations,
    untrackedDestinationRequests = destinationTelemetry.UntrackedRequests,
    destinations = destinationTelemetry.Entries.OrderBy(x => x.Key).Select(x => new {
        id = x.Key, requests = Interlocked.Read(ref x.Value.Requests),
        failures5xx = Interlocked.Read(ref x.Value.ServerErrors),
        clientErrors4xx = Interlocked.Read(ref x.Value.ClientErrors),
        meanLatencyMs = x.Value.MeanLatencyMs
    }).ToArray()
})).RequireAuthorization();
// Authentication-protected operator snapshot. This shows best-effort peer
// telemetry, not a global quota decision or proof of network consensus.
app.MapGet("/admin/api/peer-sync/status", () =>
{
    if (peerSyncSettings is null || peerStateJournal is null)
        return Results.Ok(new {
            enabled = false, mode = "disabled", scope = "No peer synchronization configured",
            strictAdmission = sharedPeerLimiter is not null ? "atomic Redis" : "local process"
        });
    var info = peerStateJournal.Status(PeerStateJournal.CurrentMinute());
    var publisher = peerPublisherDiagnostics?.Snapshot();
    var tolerance = TimeSpan.FromSeconds(Math.Max(15, peerSyncSettings.IntervalSeconds * 3));
    var recentExchange = PeerSyncFreshness.IsRecent(info, tolerance);
    return Results.Ok(new {
        enabled = true, mode = "signed HTTPS peer telemetry",
        info.LocalNode, info.RemoteNode,
        info.LocalIdentities, info.LocalRequests,
        info.RemoteIdentities, info.RemoteRequests,
        info.RemoteReportedInCurrentMinute, info.LastAcceptedUtc,
        info.LastAcceptedAgeSeconds,
        publisherAttemptsTotal = publisher?.AttemptsTotal ?? 0,
        publisherAcknowledgementsTotal = publisher?.AcknowledgementsTotal ?? 0,
        publisherHttpFailuresTotal = publisher?.HttpFailuresTotal ?? 0,
        publisherTransportFailuresTotal = publisher?.TransportFailuresTotal ?? 0,
        publisherResynchronizationsTotal = publisher?.ResynchronizationsTotal ?? 0,
        publisherLastAcknowledgedAgeSeconds = publisher?.LastAcknowledgedAgeSeconds,
        publisherLastAcknowledgedUtc = publisher?.LastAcknowledgedUtc,
        publisherInFlightRequests = publisher?.InFlightRequests ?? 0,
        info.RemoteSequence, recentExchange,
        expectedIntervalSeconds = peerSyncSettings.IntervalSeconds,
        trackedIdentityLimit = peerSyncSettings.Capacity,
        strictAdmission = sharedPeerLimiter is not null ? "atomic Redis" : "local process",
        scope = "This gateway only; eventually consistent; no quorum or distributed admission"
    });
}).RequireAuthorization();
app.MapGet("/admin/api/metrics", () =>
{
    var total = Interlocked.Read(ref requestsTotal);
    var elapsed = Interlocked.Read(ref durationTicks);
    return Results.Ok(new { gateway = Environment.MachineName, collectedUtc = DateTimeOffset.UtcNow,
       totalRequests = total, success2xx = Interlocked.Read(ref requests2xx),
       clientErrors4xx = Interlocked.Read(ref requests4xx), serverErrors5xx = Interlocked.Read(ref requests5xx),
       meanDurationMs = total == 0 ? 0 : Math.Round(elapsed * 1000.0 / System.Diagnostics.Stopwatch.Frequency / total, 2),
       durationBuckets = requestHistogram.Snapshot(),
       scope = "local process; all non-administrative HTTP requests; includes YARP and unmatched paths; resets on restart" });
}).RequireAuthorization();
object TrafficReportSnapshot()
{
    var total = Interlocked.Read(ref requestsTotal);
    var ticks = Interlocked.Read(ref durationTicks);
    return new
    {
        generatedUtc = DateTimeOffset.UtcNow,
        gateway = Environment.MachineName,
        startedUtc = processStartedUtc,
        totalRequests = total,
        success2xx = Interlocked.Read(ref requests2xx),
        clientErrors4xx = Interlocked.Read(ref requests4xx),
        serverErrors5xx = Interlocked.Read(ref requests5xx),
        meanDurationMs = total == 0 ? 0 : Math.Round(ticks * 1000.0 /
            System.Diagnostics.Stopwatch.Frequency / total, 2),
        durationBuckets = requestHistogram.Snapshot(),
        trackedDestinationLimit = DestinationTelemetry.MaximumTrackedDestinations,
        untrackedDestinationRequests = destinationTelemetry.UntrackedRequests,
        destinations = destinationTelemetry.Entries.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new
        {
            id = x.Key,
            requests = Interlocked.Read(ref x.Value.Requests),
            clientErrors4xx = Interlocked.Read(ref x.Value.ClientErrors),
            serverErrors5xx = Interlocked.Read(ref x.Value.ServerErrors),
            meanLatencyMs = x.Value.MeanLatencyMs
        }).ToArray(),
        scope = "single gateway process since startup; counters reset after restart; no client IPs or request paths"
    };
}
app.MapGet("/admin/api/reports/traffic.json", () => Results.Json(TrafficReportSnapshot()))
    .RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
app.MapGet("/admin/api/reports/traffic.csv", () =>
{
    var generated = DateTimeOffset.UtcNow;
    var rows = new List<string>
    {
        "record_type,generated_utc,process_started_utc,gateway,record_id,requests,http_2xx,http_4xx,http_5xx,mean_duration_ms,untracked_destination_requests,duration_bucket_upper_seconds"
    };
    var total = Interlocked.Read(ref requestsTotal);
    rows.Add(string.Join(',', new[]
    {
        "gateway", Csv(generated.ToString("O")), Csv(processStartedUtc.ToString("O")), Csv(Environment.MachineName), "",
        total.ToString(System.Globalization.CultureInfo.InvariantCulture),
        Interlocked.Read(ref requests2xx).ToString(System.Globalization.CultureInfo.InvariantCulture),
        Interlocked.Read(ref requests4xx).ToString(System.Globalization.CultureInfo.InvariantCulture),
        Interlocked.Read(ref requests5xx).ToString(System.Globalization.CultureInfo.InvariantCulture),
        (total == 0 ? 0 : Math.Round(Interlocked.Read(ref durationTicks) * 1000.0 /
            System.Diagnostics.Stopwatch.Frequency / total, 2)).ToString(System.Globalization.CultureInfo.InvariantCulture),
        destinationTelemetry.UntrackedRequests.ToString(System.Globalization.CultureInfo.InvariantCulture),
        ""
    }));
    foreach (var entry in destinationTelemetry.Entries.OrderBy(x => x.Key, StringComparer.Ordinal))
        rows.Add(string.Join(',', new[]
        {
            "destination", Csv(generated.ToString("O")), Csv(processStartedUtc.ToString("O")), Csv(Environment.MachineName), Csv(entry.Key),
            Interlocked.Read(ref entry.Value.Requests).ToString(System.Globalization.CultureInfo.InvariantCulture),
            "", Interlocked.Read(ref entry.Value.ClientErrors).ToString(System.Globalization.CultureInfo.InvariantCulture),
            Interlocked.Read(ref entry.Value.ServerErrors).ToString(System.Globalization.CultureInfo.InvariantCulture),
            entry.Value.MeanLatencyMs.ToString("0.##", System.Globalization.CultureInfo.InvariantCulture),
            "", ""
        }));
    rows.AddRange(GatewayTrafficReportCsv.DurationBucketRows(
        generated, processStartedUtc, Environment.MachineName, requestHistogram.Snapshot()));
    return Results.File(Encoding.UTF8.GetBytes(string.Join("\r\n", rows) + "\r\n"),
        "text/csv; charset=utf-8", $"gateway-traffic-{generated:yyyyMMdd-HHmmss}Z.csv");
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
GatewayDestinationHealthRow[] DestinationHealthRows(IProxyStateLookup runtime) => runtime.GetClusters()
    .OrderBy(cluster => cluster.ClusterId, StringComparer.Ordinal)
    .SelectMany(cluster => cluster.Destinations.Values
        .OrderBy(destination => destination.DestinationId, StringComparer.Ordinal)
        .Select(destination =>
        {
            var id = cluster.ClusterId + "/" + destination.DestinationId;
            destinationTelemetry.TryGetValue(id, out var counters);
            return new GatewayDestinationHealthRow(
                cluster.ClusterId, destination.DestinationId,
                destination.Health.Active.ToString(), destination.Health.Passive.ToString(),
                destination.ConcurrentRequestCount,
                counters is null ? 0 : Interlocked.Read(ref counters.Requests),
                counters is null ? 0 : Interlocked.Read(ref counters.ClientErrors),
                counters is null ? 0 : Interlocked.Read(ref counters.ServerErrors));
        })).ToArray();
object DestinationHealthReportSnapshot(IProxyStateLookup runtime)
{
    var generated = DateTimeOffset.UtcNow;
    var destinations = DestinationHealthRows(runtime);
    return new
    {
        generatedUtc = generated,
        gateway = Environment.MachineName,
        processStartedUtc = processStartedUtc,
        destinationCount = destinations.Length,
        activeHealthy = destinations.Count(x => x.ActiveHealth == "Healthy"),
        activeUnhealthy = destinations.Count(x => x.ActiveHealth == "Unhealthy"),
        activeUnknown = destinations.Count(x => x.ActiveHealth is not "Healthy" and not "Unhealthy"),
        destinations,
        scope = "point-in-time single-process YARP health snapshot; counters reset after restart; no backend addresses, client IPs, or request paths"
    };
}
app.MapGet("/admin/api/reports/health.json", (IProxyStateLookup runtime) =>
    Results.Json(DestinationHealthReportSnapshot(runtime)))
    .RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
app.MapGet("/admin/api/reports/health.csv", (IProxyStateLookup runtime) =>
{
    var generated = DateTimeOffset.UtcNow;
    var rows = new List<string>
    {
        "record_type,generated_utc,process_started_utc,gateway,cluster_id,destination_id,active_health,passive_health,inflight_requests,requests,http_4xx,http_5xx"
    };
    foreach (var destination in DestinationHealthRows(runtime))
        rows.Add(string.Join(',', new[]
        {
            "destination", Csv(generated.ToString("O")), Csv(processStartedUtc.ToString("O")), Csv(Environment.MachineName),
            Csv(destination.ClusterId), Csv(destination.DestinationId), Csv(destination.ActiveHealth), Csv(destination.PassiveHealth),
            destination.InflightRequests.ToString(System.Globalization.CultureInfo.InvariantCulture),
            destination.Requests.ToString(System.Globalization.CultureInfo.InvariantCulture),
            destination.Http4xx.ToString(System.Globalization.CultureInfo.InvariantCulture),
            destination.Http5xx.ToString(System.Globalization.CultureInfo.InvariantCulture)
        }));
    return Results.File(Encoding.UTF8.GetBytes(string.Join("\r\n", rows) + "\r\n"),
        "text/csv; charset=utf-8", $"gateway-health-{generated:yyyyMMdd-HHmmss}Z.csv");
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
// Prometheus 0.0.4 text exposition, LOOPBACK SCRAPE ONLY. No public endpoint or credentials.
// A local collector can scrape and forward to a separately secured metrics backend.
app.MapGet("/gateway/metrics", (HttpContext ctx) =>
{
    if (isolatedListeners is null &&
        (ctx.Connection.RemoteIpAddress is not { } address || !IPAddress.IsLoopback(address)))
        return (IResult)Results.StatusCode(403);
    var output = new StringBuilder();
    output.AppendLine("# HELP yarp_control_http_requests_total Non-admin HTTP requests observed by this process");
    output.AppendLine("# TYPE yarp_control_http_requests_total counter");
    output.Append("yarp_control_http_requests_total ").Append(Interlocked.Read(ref requestsTotal)).Append('\n');
    output.AppendLine("# HELP yarp_control_http_responses_total Non-admin responses by status class");
    output.AppendLine("# TYPE yarp_control_http_responses_total counter");
    output.Append("yarp_control_http_responses_total{status_class=\"2xx\"} ").Append(Interlocked.Read(ref requests2xx)).Append('\n');
    output.Append("yarp_control_http_responses_total{status_class=\"4xx\"} ").Append(Interlocked.Read(ref requests4xx)).Append('\n');
    output.Append("yarp_control_http_responses_total{status_class=\"5xx\"} ").Append(Interlocked.Read(ref requests5xx)).Append('\n');
    output.AppendLine("# HELP yarp_control_http_duration_seconds_sum Total request durations");
    output.AppendLine("# TYPE yarp_control_http_duration_seconds_sum counter");
    output.Append("yarp_control_http_duration_seconds_sum ")
        .Append((Interlocked.Read(ref durationTicks) / (double)System.Diagnostics.Stopwatch.Frequency).ToString("R", System.Globalization.CultureInfo.InvariantCulture))
        .Append('\n');
    requestHistogram.Append(output);
    output.AppendLine("# HELP yarp_control_process_working_set_bytes Current process working set");
    output.AppendLine("# TYPE yarp_control_process_working_set_bytes gauge");
    output.Append("yarp_control_process_working_set_bytes ").Append(Environment.WorkingSet).Append('\n');
    output.AppendLine("# HELP yarp_control_gc_heap_bytes Current managed heap bytes estimated by GC");
    output.AppendLine("# TYPE yarp_control_gc_heap_bytes gauge");
    output.Append("yarp_control_gc_heap_bytes ").Append(GC.GetTotalMemory(false)).Append('\n');
    output.AppendLine("# HELP yarp_control_gc_collections_total GC collection count by generation since process start");
    output.AppendLine("# TYPE yarp_control_gc_collections_total counter");
    for (var gen=0; gen<=2; gen++)
        output.Append("yarp_control_gc_collections_total{generation=\"").Append(gen)
            .Append("\"} ").Append(GC.CollectionCount(gen)).Append('\n');
    output.AppendLine("# HELP yarp_logging_dropped_total Low/high priority nonblocking console messages dropped");
    output.AppendLine("# TYPE yarp_logging_dropped_total counter");
    output.Append("yarp_logging_dropped_total ").Append(boundedConsole.DroppedMessages).Append('\n');
    output.AppendLine("# HELP yarp_logging_dropped_low_priority_total Debug/Information console messages dropped");
    output.AppendLine("# TYPE yarp_logging_dropped_low_priority_total counter");
    output.Append("yarp_logging_dropped_low_priority_total ").Append(boundedConsole.DroppedLowPriorityMessages).Append('\n');
    output.AppendLine("# HELP yarp_logging_dropped_high_priority_total Warning/Error console messages dropped");
    output.AppendLine("# TYPE yarp_logging_dropped_high_priority_total counter");
    output.Append("yarp_logging_dropped_high_priority_total ").Append(boundedConsole.DroppedHighPriorityMessages).Append('\n');
    output.AppendLine("# HELP yarp_logging_write_errors_total Console writer failures");
    output.AppendLine("# TYPE yarp_logging_write_errors_total counter");
    output.Append("yarp_logging_write_errors_total ").Append(boundedConsole.WriteErrors).Append('\n');
    var peerStatus = peerSyncSettings is not null && peerStateJournal is not null
        ? peerStateJournal.Status(PeerStateJournal.CurrentMinute()) : null;
    var peerPublisherStatus = peerSyncSettings is not null
        ? peerPublisherDiagnostics?.Snapshot() : null;
    PeerSyncPrometheus.Append(output, peerSyncSettings is not null, peerStatus, peerPublisherStatus);
    output.AppendLine("# HELP yarp_control_destination_inflight_requests YARP in-flight requests by destination");
    output.AppendLine("# TYPE yarp_control_destination_inflight_requests gauge");
    output.AppendLine("# HELP yarp_control_destination_active_health YARP active health 1 healthy, 0 unknown, -1 unhealthy");
    output.AppendLine("# TYPE yarp_control_destination_active_health gauge");
    var runtime = ctx.RequestServices.GetRequiredService<IProxyStateLookup>();
    foreach (var cluster in runtime.GetClusters())
    foreach (var dest in cluster.Destinations.Values)
    {
        var key = (cluster.ClusterId + "/" + dest.DestinationId)
            .Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        output.Append("yarp_control_destination_inflight_requests{destination=\"")
            .Append(key).Append("\"} ").Append(dest.ConcurrentRequestCount).Append('\n');
        output.Append("yarp_control_destination_active_health{destination=\"")
            .Append(key).Append("\"} ")
            .Append(dest.Health.Active.ToString() switch { "Healthy" => 1, "Unhealthy" => -1, _ => 0 })
            .Append('\n');
    }
    output.AppendLine("# HELP yarp_control_destination_requests_total HTTP requests by configured YARP destination");
    output.AppendLine("# TYPE yarp_control_destination_requests_total counter");
    foreach (var pair in destinationTelemetry.Entries)
    {
        var escaped = pair.Key.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        output.Append("yarp_control_destination_requests_total{destination=\"").Append(escaped)
            .Append("\"} ").Append(Interlocked.Read(ref pair.Value.Requests)).Append('\n');
    }
    output.AppendLine("# HELP yarp_control_destination_telemetry_untracked_requests_total Requests whose destination counters were not tracked because the process cardinality cap was reached");
    output.AppendLine("# TYPE yarp_control_destination_telemetry_untracked_requests_total counter");
    output.Append("yarp_control_destination_telemetry_untracked_requests_total ").Append(destinationTelemetry.UntrackedRequests).Append('\n');
    output.AppendLine("# HELP yarp_control_destination_admission_inflight_requests Requests currently holding an opt-in per-destination admission slot");
    output.AppendLine("# TYPE yarp_control_destination_admission_inflight_requests gauge");
    output.AppendLine("# HELP yarp_control_destination_admission_queued_requests Requests waiting in an opt-in per-destination FIFO queue");
    output.AppendLine("# TYPE yarp_control_destination_admission_queued_requests gauge");
    output.AppendLine("# HELP yarp_control_destination_admission_rejected_total Requests rejected because the per-destination queue was full");
    output.AppendLine("# TYPE yarp_control_destination_admission_rejected_total counter");
    output.AppendLine("# HELP yarp_control_destination_admission_queue_timeouts_total Waiters removed after the configured queue timeout");
    output.AppendLine("# TYPE yarp_control_destination_admission_queue_timeouts_total counter");
    output.AppendLine("# HELP yarp_control_destination_admission_waiter_canceled_total Waiters removed after their cancellation token is signaled (includes request abort, shutdown, and queue timeout)");
    output.AppendLine("# TYPE yarp_control_destination_admission_waiter_canceled_total counter");
    output.AppendLine("# HELP yarp_control_destination_admission_untracked_destinations Enabled destinations omitted from per-destination admission metrics because the bounded registry is full");
    output.AppendLine("# TYPE yarp_control_destination_admission_untracked_destinations gauge");
    var admission = ctx.RequestServices.GetRequiredService<DestinationAdmissionManager>();
    output.Append("yarp_control_destination_admission_untracked_destinations ")
        .Append(admission.UntrackedConfiguredDestinationCount).Append('\n');
    output.AppendLine("# HELP yarp_control_destination_admission_queue_wait_seconds Time spent by requests waiting for a per-destination slot; fixed buckets support tail-latency estimates");
    output.AppendLine("# TYPE yarp_control_destination_admission_queue_wait_seconds histogram");
    foreach (var cluster in runtime.GetClusters())
    foreach (var destination in cluster.Destinations.Values)
    {
        if (!admission.TryGetSnapshot(cluster.ClusterId, destination.DestinationId, out var snapshot)) continue;
        var label = (cluster.ClusterId + "/" + destination.DestinationId)
            .Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        output.Append("yarp_control_destination_admission_inflight_requests{destination=\"").Append(label).Append("\"} ").Append(snapshot.InFlight).Append('\n');
        output.Append("yarp_control_destination_admission_queued_requests{destination=\"").Append(label).Append("\"} ").Append(snapshot.Queued).Append('\n');
        output.Append("yarp_control_destination_admission_rejected_total{destination=\"").Append(label).Append("\"} ").Append(snapshot.Rejected).Append('\n');
        output.Append("yarp_control_destination_admission_queue_timeouts_total{destination=\"").Append(label).Append("\"} ").Append(snapshot.TimedOut).Append('\n');
        output.Append("yarp_control_destination_admission_waiter_canceled_total{destination=\"").Append(label).Append("\"} ").Append(snapshot.Canceled).Append('\n');
        long cumulativeWaits = 0;
        for (var bucketIndex = 0; bucketIndex < DestinationAdmissionState.QueueWaitBucketUpperBoundsMilliseconds.Count; bucketIndex++)
        {
            cumulativeWaits += snapshot.WaitDurationBucketCounts[bucketIndex];
            var upperBoundSeconds = DestinationAdmissionState.QueueWaitBucketUpperBoundsMilliseconds[bucketIndex] / 1000d;
            output.Append("yarp_control_destination_admission_queue_wait_seconds_bucket{destination=\"")
                .Append(label).Append("\",le=\"")
                .Append(upperBoundSeconds.ToString("0.###", System.Globalization.CultureInfo.InvariantCulture))
                .Append("\"} ").Append(cumulativeWaits).Append('\n');
        }
        output.Append("yarp_control_destination_admission_queue_wait_seconds_bucket{destination=\"")
            .Append(label).Append("\",le=\"+Inf\"} ").Append(snapshot.WaitDurationCount).Append('\n');
        output.Append("yarp_control_destination_admission_queue_wait_seconds_sum{destination=\"").Append(label).Append("\"} ").Append(snapshot.WaitDurationSecondsSum.ToString("R", System.Globalization.CultureInfo.InvariantCulture)).Append('\n');
        output.Append("yarp_control_destination_admission_queue_wait_seconds_count{destination=\"").Append(label).Append("\"} ").Append(snapshot.WaitDurationCount).Append('\n');
    }
    return Results.Text(output.ToString(), "text/plain; version=0.0.4; charset=utf-8");
});
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/admin/api") &&
        (ctx.Request.Method is "POST" or "PUT" or "PATCH" or "DELETE") &&
        !ctx.Request.Path.StartsWithSegments("/admin/api/bootstrap") &&
        !ctx.Request.Path.StartsWithSegments("/admin/api/login") &&
        ctx.GetEndpoint()?.Metadata.GetMetadata<EmployeeInvitationRedemptionEndpoint>() is null)
    {
        if (ctx.User.Identity?.IsAuthenticated != true) { ctx.Response.StatusCode = 401; return; }
        var token = ctx.User.FindFirst("csrf")?.Value;
        var provided = ctx.Request.Headers["X-CSRF-Token"].ToString();
        if (ctx.Request.Path == "/admin/api/logout" &&
            string.Equals(ctx.Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var form = await ctx.Request.ReadFormAsync(ctx.RequestAborted);
                var values = form["csrf"];
                provided = form.Count == 1 && values.Count == 1 ? values[0] ?? "" : "";
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or InvalidOperationException or OperationCanceledException)
            { ctx.Response.StatusCode = 400; return; }
        }
        if (string.IsNullOrWhiteSpace(token) ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(provided)))
        { ctx.Response.StatusCode = 403; return; }
        if (ctx.Request.Path != "/admin/api/logout" && ctx.Request.Path != ManagementPrivacyPolicy.AcceptancePath && ctx.User.IsInRole("Viewer")) { ctx.Response.StatusCode = 403; return; }
        // All authenticated administrative mutations require recent verified IdP
        // authentication in enterprise mode, except the explicitly named recovery account.
        // The recovery account must have signed in with local password + delivered OTP.
        if (oidcPolicy is not null && ctx.Request.Path != "/admin/api/logout" &&
            ctx.Request.Path != ManagementPrivacyPolicy.AcceptancePath &&
            !oidcPolicy.IsBreakGlass(ctx.User.Identity?.Name) &&
            !oidcPolicy.SessionValid(ctx.User, ctx.User.Identity?.Name ?? "",
                ctx.User.FindFirst(ClaimTypes.Role)?.Value ?? "", DateTimeOffset.UtcNow, stepUp: true))
        {
            ctx.Response.StatusCode = 403;
            await ctx.Response.WriteAsJsonAsync(new { error = "Fresh phishing-resistant sign-in required. Sign in again using Enterprise SSO.", signIn = "/admin/oidc/start" });
            return;
        }
        if (ctx.Request.Path.StartsWithSegments("/admin/api/restore") && !ctx.User.IsInRole("Administrator"))
        { ctx.Response.StatusCode = 403; return; }
    }
    await next();
});

// Emergency local configuration freeze. Authentication/CSRF checks precede this middleware.
// It freezes mutations to the routing/change-control surface. It does NOT stop proxy traffic.
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Method is "POST" or "PUT" or "PATCH" or "DELETE" &&
        (ctx.Request.Path.StartsWithSegments("/admin/api/change-requests") ||
         ctx.Request.Path.StartsWithSegments("/admin/api/restore") ||
         ctx.Request.Path.StartsWithSegments("/admin/api/fleet/rollout") ||
         ctx.Request.Path.StartsWithSegments("/admin/api/network/virtual-services")) &&
        SetupCenter.ReadFreeze(privateDir).Frozen)
    {
        ctx.Response.StatusCode = 423;
        await ctx.Response.WriteAsJsonAsync(new { error = "Local routing change freeze is active. Unfreeze with administrator approval/reason before modifying configuration." });
        return;
    }
    await next();
});

string Actor(HttpContext context) => context.Items.ContainsKey(vipMachineAuthKey) ?
    "vip-machine:"+vipMachinePin : context.User.Identity?.Name ?? "unknown";
List<AdminUser> ReadUsers() => File.Exists(usersPath)
    ? (JsonSerializer.Deserialize<List<AdminUser>>(File.ReadAllText(usersPath), jsonOptions) ?? new())
    : new();
void WriteUsers(List<AdminUser> users)
{
    var tmp = usersPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
    try
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var file = new FileStream(tmp, options))
        {
            file.Write(JsonSerializer.SerializeToUtf8Bytes(users));
            file.Flush(flushToDisk: true);
        }
        File.Move(tmp, usersPath, true);
    }
    finally { if (File.Exists(tmp)) File.Delete(tmp); }
}
// Capture the exact persisted account baseline under the existing login gate.
byte[] AccountSnapshot() => File.Exists(usersPath) ? File.ReadAllBytes(usersPath) : [];
async Task<(IResult? Error, string? IntentId)> ConfirmAccountMutation(HttpContext ctx,
    byte[] before, List<AdminUser> proposed, string operation)
{
    if (externalAuditIntent is null)
    {
        if (oidcPolicy is null) return (null, null);
        if (!await AuditActorCurrent(ctx, administratorOnly: true)) return (Results.StatusCode(403), null);
        if (ctx.RequestAborted.IsCancellationRequested)
            return (Results.Json(new { error = "Account mutation cancelled; state unchanged" }, statusCode: 503), null);
        if (!AccountSnapshot().AsSpan().SequenceEqual(before))
            return (Results.Conflict(new { error = "Account state changed during final authorization" }), null);
        return (null, null);
    }
    if (!AccountSnapshot().AsSpan().SequenceEqual(before))
        return (Results.Conflict(new { error = "Account state changed before external audit confirmation" }), null);
    if (!await AuditActorCurrent(ctx, administratorOnly: true))
        return (Results.StatusCode(403), null);
    var revision = Convert.ToHexString(SHA256.HashData(before));
    var targetDigest = Convert.ToHexString(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(proposed)));
    var intentId = await externalAuditIntent.ConfirmWithIdAsync(Actor(ctx), operation,
        revision, targetDigest, ctx.RequestAborted);
    if (intentId is null || ctx.RequestAborted.IsCancellationRequested)
        return (Results.Json(new { error = "External audit receipt unavailable; account state unchanged" }, statusCode: 503), null);
    if (!await AuditActorCurrent(ctx, administratorOnly: true))
        return (Results.StatusCode(403), null);
    if (!AccountSnapshot().AsSpan().SequenceEqual(before))
        return (Results.Conflict(new { error = "Account state changed during external audit confirmation" }), null);
    if (auditOutbox is not null)
    {
        // Persist a correlated PREPARED record before allowing the mutation.
        // If storage fails, the account bytes remain unchanged. PREPARED is
        // not proof of success: a crash may leave the outcome unresolved.
        try { await localAudit.AppendAsync(Actor(ctx), "ACCOUNT_MUTATION_PREPARED",
            new { operation, revision, targetDigest }, intentId); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException)
        { return (Results.Json(new { error = "Account audit preparation unavailable; state unchanged" }, statusCode: 503), null); }
    }
    if (ctx.RequestAborted.IsCancellationRequested)
        return (Results.Json(new { error = "Account mutation cancelled; state unchanged" }, statusCode: 503), null);
    if (!AccountSnapshot().AsSpan().SequenceEqual(before))
        return (Results.Conflict(new { error = "Account state changed during audit preparation" }), null);
    if (!await AuditActorCurrent(ctx, administratorOnly: true))
        return (Results.StatusCode(403), null);
    // The shared authority read may yield. Check cancellation and the exact
    // prior bytes again after the final awaited authorization before writing.
    if (ctx.RequestAborted.IsCancellationRequested)
        return (Results.Json(new { error = "Account mutation cancelled; state unchanged" }, statusCode: 503), null);
    if (!AccountSnapshot().AsSpan().SequenceEqual(before))
        return (Results.Conflict(new { error = "Account state changed during final authorization" }), null);
    return (null, intentId);
}
// Call only under the writer lock for the target file. The proposed bytes
// are persisted verbatim, so the signed digest describes the actual state.
byte[] AuditStateBytes(string path) => File.Exists(path) ? File.ReadAllBytes(path) : [];
async Task<bool> AuditActorCurrent(HttpContext ctx, bool administratorOnly)
{
    if(ctx.Items.TryGetValue(vipMachineAuthKey,out var machine)&&machine is Func<Task<bool>> authorized)
        return ctx.Request.Path=="/admin/vip-machine/drain" && await authorized();
    var active = ReadUsers().SingleOrDefault(x => x.Username.Equals(Actor(ctx), StringComparison.OrdinalIgnoreCase));
    if (active is null || !active.Enabled || active.SecurityStamp != ctx.User.FindFirst("stamp")?.Value ||
        active.Role != ctx.User.FindFirst(ClaimTypes.Role)?.Value ||
        (administratorOnly ? active.Role != "Administrator" : active.Role is not ("Administrator" or "Operator")))
        return false;
    if (oidcPolicy is null) return true;
    if (oidcPolicy.IsBreakGlass(active.Username))
        return oidcPolicy.RecoverySessionValid(ctx.User, active.Username, active.Role, active.Provider);
    if (active.Provider != "Local" || !oidcPolicy.SessionValid(ctx.User, active.Username, active.Role, DateTimeOffset.UtcNow, stepUp: true) ||
        !EnterpriseOidcPolicy.AfterRevocation(ctx.User, active.OidcRevokedBefore)) return false;
    if (sharedOidcRevocation is null) return true;
    var subject = EnterpriseOidcPolicy.Single(ctx.User, EnterpriseOidcPolicy.SubjectClaim);
    if (subject is null || !long.TryParse(EnterpriseOidcPolicy.Single(ctx.User, EnterpriseOidcPolicy.AuthTimeClaim),
        System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var authTime) ||
        !await sharedOidcRevocation.AllowsAsync(subject, authTime, active.OidcRevokedBefore)) return false;
    // The Redis check is asynchronous; re-read local state rather than rely
    // on a security stamp or role captured before the remote authority call.
    var current = ReadUsers().SingleOrDefault(x => x.Username.Equals(active.Username, StringComparison.OrdinalIgnoreCase));
    return current is not null && current.Enabled && current.Role == active.Role &&
        current.SecurityStamp == active.SecurityStamp && current.Provider == active.Provider &&
        current.OidcRevokedBefore == active.OidcRevokedBefore &&
        oidcPolicy.SessionValid(ctx.User, current.Username, current.Role, DateTimeOffset.UtcNow, stepUp: true);
}
async Task<IResult?> ConfirmStateMutation(HttpContext ctx, string path, byte[] before, byte[] proposed,
    string operation, bool administratorOnly, Action<string>? onConfirmedIntent = null)
{
    if (externalAuditIntent is null && oidcPolicy is null) return null;
    if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
    if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
        return Results.Conflict(new { error = "State changed before external audit confirmation" });
    if (externalAuditIntent is not null)
    {
        var verifiedId = await externalAuditIntent.ConfirmWithIdAsync(Actor(ctx), operation,
            Convert.ToHexString(SHA256.HashData(before)),
            Convert.ToHexString(SHA256.HashData(proposed)), ctx.RequestAborted);
        if (verifiedId is null)
            return Results.Json(new { error = "External audit receipt unavailable; state unchanged" }, statusCode: 503);
        // Only callers enforcing a durable PREPARED outbox need this ID.
        // This callback never grants authorization by itself: actor, state
        // and cancellation checks below still apply.
        onConfirmedIntent?.Invoke(verifiedId);
    }
    if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
    if (ctx.RequestAborted.IsCancellationRequested)
        return Results.Json(new { error = "Mutation cancelled; state unchanged" }, statusCode: 503);
    if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
        return Results.Conflict(new { error = "State changed during external audit confirmation" });
    return null;
}
// The caller holds the resource gate, never loginGate. Obtain the account
// gate after collector I/O and retain it through the exact state commit.
async Task<IResult?> ConfirmAndWriteResourceMutation(HttpContext ctx, string path,
    byte[] before, byte[] proposed, string operation, bool administratorOnly)
{
    if (externalAuditIntent is null && oidcPolicy is null)
    {
        if(ctx.Items.ContainsKey(vipMachineAuthKey)&&(!await AuditActorCurrent(ctx,true)||ctx.RequestAborted.IsCancellationRequested))
            return Results.StatusCode(403);
        WriteAuditedState(path, proposed);
        return null;
    }
    string? confirmedIntentId = null;
    var denied = await ConfirmStateMutation(ctx, path, before, proposed,
        operation, administratorOnly, id => confirmedIntentId = id);
    if (denied is not null) return denied;
    try { await loginGate.WaitAsync(ctx.RequestAborted); }
    catch (OperationCanceledException)
    { return Results.Json(new { error = "Account mutation commit cancelled; state unchanged" }, statusCode: 503); }
    try
    {
        if (ctx.RequestAborted.IsCancellationRequested)
            return Results.Json(new { error = "Account mutation commit cancelled; state unchanged" }, statusCode: 503);
        if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
        if (ctx.RequestAborted.IsCancellationRequested)
            return Results.Json(new { error = "Resource mutation commit cancelled; state unchanged" }, statusCode: 503);
        if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
            return Results.Conflict(new { error = "State changed during external audit confirmation" });

        if (auditOutbox is not null)
        {
            // A remote signed INTENT receipt is not evidence that the
            // post-receipt resource mutation was even attempted. Persist
            // the correlation and exact proposed/prior digests to a durable
            // outbox BEFORE changing inventory/fleet configuration bytes.
            // Failure here refuses the mutation; the signed intent alone
            // never permits a write with a broken audit queue.
            if (confirmedIntentId is null)
                return Results.Json(new { error = "Resource mutation audit intent missing; state unchanged" },
                    statusCode: 503);
            try
            {
                await localAudit.AppendAsync(Actor(ctx), "RESOURCE_MUTATION_PREPARED",
                    new
                    {
                        operation,
                        revision = Convert.ToHexString(SHA256.HashData(before)),
                        targetDigest = Convert.ToHexString(SHA256.HashData(proposed))
                    }, confirmedIntentId);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or
                InvalidOperationException or InvalidDataException)
            {
                return Results.Json(new { error = "Resource audit preparation unavailable; state unchanged" },
                    statusCode: 503);
            }
        }

        // The queue operation can yield and the account or request may have
        // been revoked meanwhile. Recheck every authority after that await.
        if (ctx.RequestAborted.IsCancellationRequested)
            return Results.Json(new { error = "Resource mutation audit cancelled; state unchanged" },
                statusCode: 503);
        if (!await AuditActorCurrent(ctx, administratorOnly))
            return Results.StatusCode(403);
        if (ctx.RequestAborted.IsCancellationRequested)
            return Results.Json(new { error = "Resource mutation commit cancelled; state unchanged" },
                statusCode: 503);
        if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
            return Results.Conflict(new { error = "State changed during durable audit preparation" });
        WriteAuditedState(path, proposed);
        return null;
    }
    finally { loginGate.Release(); }
}
void WriteAuditedState(string path, byte[] proposed)
{
    var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
    try
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(temp, options))
        {
            stream.Write(proposed);
            stream.Flush(flushToDisk: true);
        }
        File.Move(temp, path, true);
    }
    finally { if (File.Exists(temp)) File.Delete(temp); }
}
Task Audit(string actor, string action, object? details = null) =>
    localAudit.AppendAsync(actor, action, details);
IResult SignInResult(AdminUser user, HttpContext ctx)
{
    return Results.Ok(new { authenticated = true, username = user.Username, role = user.Role });
}
async Task SignIn(AdminUser user, HttpContext ctx)
{
    var claims = new List<Claim> {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role),
        new Claim("csrf", Convert.ToHexString(RandomNumberGenerator.GetBytes(32))),
        new Claim("stamp", user.SecurityStamp)
    };
    var properties = new AuthenticationProperties();
    if (oidcPolicy is not null)
    {
        if (!oidcPolicy.IsBreakGlass(user.Username) || user.Provider != "Local" ||
            user.Role != "Administrator" || !ReadMail().Enabled)
            throw new InvalidOperationException("Only approved recovery account may use local sign-in in enterprise mode");
        claims.Add(new Claim(EnterpriseOidcPolicy.RecoveryClaim, oidcPolicy.Fingerprint));
        properties.AllowRefresh = false;
        properties.ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(10);
    }
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)), properties);
}

app.MapGet("/admin/api/session", (HttpContext ctx) => Results.Ok(new {
    initialized = ReadUsers().Count != 0,
    setupRequired = setupEnrollmentRequired && ReadUsers().Count == 0,
    authenticated = ctx.User.Identity?.IsAuthenticated == true,
    username = ctx.User.Identity?.Name,
    role = ctx.User.FindFirst(ClaimTypes.Role)?.Value,
    csrf = ctx.User.FindFirst("csrf")?.Value,
    federatedOidc = oidcPolicy is not null && ctx.User.HasClaim(c => c.Type == EnterpriseOidcPolicy.SubjectClaim),
#if GATEWAYCORE_COMMERCIAL
    commercial = true,
    licenseActive = commercialLicense.Allows("l7"),
#endif
    privacyAccepted = ManagementPrivacyPolicy.Accepted(ctx),
    privacyVersion = ManagementPrivacyPolicy.Version,
    privacyText = ManagementPrivacyPolicy.Text,
    mode = "Local administrative test console — not certified for CA production"
}));

#if GATEWAYCORE_COMMERCIAL
app.MapGet("/admin/api/license/status", () => Results.Ok(commercialLicense.Status())).RequireAuthorization();
app.MapGet("/admin/api/license/request", () =>
{
    try { return Results.Ok(new { file = Encoding.ASCII.GetString(commercialLicense.Request()) }); }
    catch (Exception) { return Results.Conflict(new { error = "Installation identity is unavailable; use approved local provisioning or recovery." }); }
}).RequireAuthorization(policy => policy.RequireRole("Administrator"));
async Task<IResult> ImportCommercialLicense(HttpContext ctx, bool revoke)
{
    try
    {
        var bytes = await CommercialLicenseRuntime.ReadUpload(ctx);
        var result = commercialLicense.Import(bytes, revoke);
        await Audit(Actor(ctx), revoke ? "LICENSE_REVOKED" : "LICENSE_IMPORTED",
            new { result.LicenseId, result.AllocationId, result.Revision, validity = result.Validity.ToString() });
        return Results.Ok(commercialLicense.Status());
    }
    catch (Exception e) when (e is IOException or CryptographicException or InvalidDataException or
        FormatException or JsonException or ArgumentException or InvalidOperationException or UnauthorizedAccessException)
    { return Results.BadRequest(new { error = "License import rejected or state unavailable; inspect current status and contact the issuer." }); }
}
app.MapPost("/admin/api/license/import", (Delegate)(Func<HttpContext, Task<IResult>>)(ctx => ImportCommercialLicense(ctx, false)))
    .RequireAuthorization(policy => policy.RequireRole("Administrator"));
app.MapPost("/admin/api/license/revoke", (Delegate)(Func<HttpContext, Task<IResult>>)(ctx => ImportCommercialLicense(ctx, true)))
    .RequireAuthorization(policy => policy.RequireRole("Administrator"));
#endif
app.MapPost(ManagementPrivacyPolicy.AcceptancePath, async (HttpContext ctx, PrivacyAcceptanceInput input) =>
{
    if (!string.Equals(input.Version, ManagementPrivacyPolicy.Version, StringComparison.Ordinal))
        return Results.Conflict(new { error = "The Privacy Policy changed. Review the current notice before accepting." });
    if (!ManagementPrivacyPolicy.Accepted(ctx))
    {
        await Audit(Actor(ctx), "PRIVACY_POLICY_ACCEPTED", new { version = ManagementPrivacyPolicy.Version });
        ManagementPrivacyPolicy.Issue(ctx);
    }
    return Results.Ok(new { accepted = true, version = ManagementPrivacyPolicy.Version });
}).RequireAuthorization();

app.MapPost("/admin/api/bootstrap", async (HttpContext ctx, LoginInput input) =>
{
    if (oidcPolicy is not null)
        return Results.Json(new { error = "Provision local recovery and mapped accounts before enabling enterprise SSO" }, statusCode: 403);
    await loginGate.WaitAsync();
    try
    {
        if (ReadUsers().Count > 0) return Results.Conflict(new { error = "Already initialized" });
        if (setupEnrollmentRequired)
            return Results.Conflict(new { error = "Complete the verified first-run wizard before creating an administrator." });
        if (!ValidUser(input.Username) || !ValidPassword(input.Password) || !ValidEmail(input.Email))
            return Results.BadRequest(new { error = "Username: 3–40 letters/numbers/_/-. Password: at least 16 characters." });
        var user = NewUser(input.Username, "Administrator", input.Password, input.Email);
        WriteUsers(new List<AdminUser> { user });
        await SignIn(user, ctx);
        await Audit(user.Username, "BOOTSTRAP_ADMIN");
        return SignInResult(user, ctx);
    }
    finally { loginGate.Release(); }
}).RequireRateLimiting("login");


#if !GATEWAYCORE_COMMERCIAL
// Local setup only; each step requires the protected claim and is serialized
// by the same lock as account bootstrap. No generic unauthenticated SMTP API.
app.MapPost("/admin/api/bootstrap/setup", async (HttpContext ctx, SetupEnrollmentInput input) =>
{
    if (!setupEnrollmentRequired || oidcPolicy is not null || externalAuditIntent is not null ||
        ctx.Connection.RemoteIpAddress is not { } address || !IPAddress.IsLoopback(address) ||
        !(ctx.Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
          ctx.Request.Host.Host is "127.0.0.1" or "[::1]" or "::1"))
        return Results.StatusCode(403);
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        if (ReadUsers().Count != 0)
            return Results.Conflict(new { error = "GatewayCore is already initialized." });
        if (!File.Exists(setupCodePath) || (File.GetAttributes(setupCodePath) & FileAttributes.ReparsePoint) != 0)
            return Results.Json(new { error = "Protected setup code unavailable; ask the local system administrator to repair Setup." }, statusCode: 503);
        var secret = File.ReadAllText(setupCodePath).Trim();
        if (secret.Length != 64 || !Regex.IsMatch(secret, "^[A-Fa-f0-9]{64}$") ||
            input.SetupCode is null || input.SetupCode.Length != 64 ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(input.SetupCode)))
            return Results.Json(new { error = "Installation setup code is invalid." }, statusCode: 403);
        if (input.Action == "unlock")
            return Results.Ok(new { authorized = true });
        if (input.Action == "sender")
        {
            var m = input.Mail;
            if (m is null || string.IsNullOrWhiteSpace(m.Host) || m.Host.Length > 255 ||
                m.Port is < 1 or > 65535 or 465 || !m.StartTls ||
                !ValidEmail(m.From) || !ValidEmail(input.Email) ||
                m.Username is null || m.Username.Length > 254 ||
                m.Password is null || m.Password.Length > 4096 ||
                (m.OAuthClientSecret?.Length ?? 0) > 4096 || (m.OAuthRefreshToken?.Length ?? 0) > 16384)
                return Results.BadRequest(new { error = "Enter a sender, readable verification mailbox, SMTP host and STARTTLS port (465 unsupported)." });
            var mode = string.IsNullOrEmpty(m.AuthMode) ? MailProviderAuth.PasswordMode : m.AuthMode;
            var oauth = MailProviderAuth.UsesOAuth(mode);
            var validation = MailProviderAuth.Validate(mode, m.Host, m.Username, m.OAuthTenant,
                m.OAuthClientId, !string.IsNullOrEmpty(m.OAuthClientSecret), !string.IsNullOrEmpty(m.OAuthRefreshToken));
            if (validation is not null) return Results.BadRequest(new { error = validation });
            if (mode == MailProviderAuth.PasswordMode && !string.IsNullOrWhiteSpace(m.Username) && string.IsNullOrWhiteSpace(m.Password))
                return Results.BadRequest(new { error = "Enter an approved SMTP app password, or use an authorized relay without a username." });
            var cfg = new MailSettings(true, m.Host, m.Port, m.From, m.Username,
                !oauth && !string.IsNullOrEmpty(m.Password) ? protector.Protect(m.Password) : "",
                true, mode, oauth ? m.OAuthClientId : "",
                oauth ? protector.Protect(m.OAuthClientSecret) : "",
                oauth && mode != MailProviderAuth.MicrosoftApp ? protector.Protect(m.OAuthRefreshToken) : "",
                oauth ? m.OAuthTenant : "");
            var code = RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
            var flow = SetupEnrollment.Issue(Convert.ToHexString(RandomNumberGenerator.GetBytes(24)), cfg, input.Email!, "sender-code", code);
            // Invalidate previous challenges before dispatch. Do not persist
            // an unverified sender configuration or enable login prematurely.
            setupEnrollment = null;
            await SendMailMessage(input.Email!, "GatewayCore sender verification code",
                $"Your sender verification code is {code}. It expires in 5 minutes. Do not share this code.", cfg);
            setupEnrollment = flow;
            return Results.Ok(new { flowId = flow.Id, emailHint = MaskEmail(flow.Email) });
        }
        var current = setupEnrollment;
        if (current is null || input.FlowId != current.Id || current.ExpiresAt <= DateTimeOffset.UtcNow)
            return Results.Conflict(new { error = "Setup verification expired or changed. Restart the wizard." });
        if (input.Action is "verify-sender" or "verify-admin")
        {
            var expected = input.Action == "verify-sender" ? "sender-code" : "admin-code";
            if (current.Stage != expected)
                return Results.Conflict(new { error = "Complete the preceding verification step first." });
            if (!current.Matches(input.Code))
            {
                setupEnrollment = current.Attempts + 1 >= 5 ? null : current with { Attempts = current.Attempts + 1 };
                return Results.Json(new { error = "Verification code is incorrect or expired." }, statusCode: 401);
            }
            setupEnrollment = current with { Stage = expected == "sender-code" ? "sender-verified" : "admin-verified",
                Nonce = "", Hash = "", Attempts = 0, ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10) };
            return Results.Ok(new { verified = true });
        }
        if (input.Action == "administrator")
        {
            if (current.Stage != "sender-verified" || !ValidEmail(input.Email))
                return Results.BadRequest(new { error = "Verify sender delivery first and enter a valid administrator email." });
            var code = RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
            var flow = SetupEnrollment.Issue(current.Id, current.Mail, input.Email!, "admin-code", code);
            await SendMailMessage(input.Email!, "GatewayCore administrator registration code",
                $"Your administrator registration code is {code}. It expires in 5 minutes. Do not share this code.", current.Mail);
            setupEnrollment = flow;
            return Results.Ok(new { flowId = flow.Id, emailHint = MaskEmail(flow.Email) });
        }
        if (input.Action == "finish")
        {
            if (current.Stage != "admin-verified")
                return Results.Conflict(new { error = "Verify administrator email before creating a password." });
            if (!ValidUser(input.Username) || !ValidPassword(input.Password))
                return Results.BadRequest(new { error = "Username: 3–40 letters/numbers/_/-. Password: 16–256 characters." });
            // Save verified mail and proof before users. An interruption
            // cannot create an account without enabled, verified email OTP.
            WriteAuditedState(mailPath, JsonSerializer.SerializeToUtf8Bytes(current.Mail));
            WriteAuditedState(mailProofPath, Encoding.UTF8.GetBytes(MailFingerprint(current.Mail)));
            var user = NewUser(input.Username!, "Administrator", input.Password!, current.Email);
            WriteUsers(new List<AdminUser> { user });
            setupEnrollment = null;
            try { File.Delete(setupCodePath); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            { app.Logger.LogWarning("Completed first-run claim cleanup requires local administrator; initialized account gate remains closed."); }
            await Audit(user.Username, "BOOTSTRAP_ADMIN_EMAIL_VERIFIED");
            await SignIn(user, ctx);
            return SignInResult(user, ctx);
        }
        return Results.BadRequest(new { error = "Unknown setup step." });
    }
    catch (Exception ex)
    {
        // Do not record secrets, OTPs or raw mail-provider errors.
        app.Logger.LogWarning("FIRST_RUN_SETUP_FAILED type={ErrorType}", ex.GetType().Name);
        return Results.Json(new { error = "Setup could not complete. Check SMTP reachability, trusted TLS, credentials and mailbox permissions, or contact the local administrator." }, statusCode: 503);
    }
    finally { loginGate.Release(); }
}).RequireRateLimiting("first-run");
#endif

app.MapGet("/admin/api/auth-methods", () => Results.Ok(new {
    local = true, activeDirectory = oidcPolicy is null && directoryAuth.Read().Enabled,
    mailOtp = ReadMail().Enabled, enterpriseOidc = oidcPolicy is not null,
    employeeInvitations = EmployeeInvitationsAvailable(),
    info = oidcPolicy is not null ? "Enterprise SSO with phishing-resistant MFA; local sign-in reserved for recovery" :
        "AD sign-in requires LDAPS, mapped groups and email OTP"
}));

app.MapGet("/admin/oidc/start", (HttpContext ctx) =>
{
    if (oidcPolicy is null) return Results.NotFound();
    return Results.Challenge(new AuthenticationProperties { RedirectUri = "/dashboard" },
        [EnterpriseOidcPolicy.Scheme]);
}).RequireRateLimiting("login");
app.MapPost(EnterpriseOidcLogout.Path, async (HttpContext ctx, IOptionsMonitor<OpenIdConnectOptions> options) =>
{
    if (oidcPolicy is null) return Results.NotFound();
    IFormCollection form;
    try { form = await ctx.Request.ReadFormAsync(ctx.RequestAborted); }
    catch (Exception ex) when (ex is InvalidDataException or IOException or OperationCanceledException)
    { return Results.BadRequest(); }
    if (form.Count != 1 || !form.TryGetValue("logout_token", out var tokens) || tokens.Count != 1)
        return Results.BadRequest();
    var notice = await EnterpriseOidcLogout.ValidateAsync(tokens[0] ?? "", oidcPolicy,
        options.Get(EnterpriseOidcPolicy.Scheme), ctx.RequestAborted);
    if (notice is null) return Results.BadRequest();
    var row = oidcPolicy.Resolve(notice.Subject)!;
    if (sharedOidcRevocation is not null &&
        await sharedOidcRevocation.ReadOrAdvanceAsync(notice.Subject, notice.IssuedAt) is null)
        return Results.StatusCode(503);
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        var users = ReadUsers();
        var user = users.SingleOrDefault(u => u.Username.Equals(row.Username, StringComparison.OrdinalIgnoreCase));
        if (user is null || user.Provider != "Local") return Results.Ok();
        // Persist a monotonic subject-wide cutoff and audit checkpoint. A
        // failed audit append leaves it pending, so an IdP retry cannot receive
        // 200 until the corresponding local audit record has been appended.
        if (notice.IssuedAt > user.OidcRevokedBefore)
        {
            var index = users.IndexOf(user);
            user = user with { OidcRevokedBefore = notice.IssuedAt,
                SecurityStamp = sharedOidcRevocation is null
                    ? Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) : user.SecurityStamp };
            users[index] = user;
            WriteUsers(users);
        }
        if (user.OidcLogoutAuditThrough < user.OidcRevokedBefore)
        {
            await Audit(user.Username, "OIDC_BACKCHANNEL_LOGOUT", new { revokedBefore = user.OidcRevokedBefore });
            users = ReadUsers();
            var current = users.SingleOrDefault(u => u.Username.Equals(row.Username, StringComparison.OrdinalIgnoreCase));
            if (current is null || current.Provider != "Local" || current.OidcRevokedBefore != user.OidcRevokedBefore)
                return Results.StatusCode(503);
            users[users.IndexOf(current)] = current with { OidcLogoutAuditThrough = current.OidcRevokedBefore };
            WriteUsers(users);
        }
        return Results.Ok();
    }
    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
    { return Results.StatusCode(503); }
    finally { loginGate.Release(); }
}).RequireRateLimiting("oidc-logout");
app.MapGet("/admin/oidc/error", () => Results.Text(
    "Enterprise sign-in was denied. Check your identity provider, account mapping, MFA policy or contact an administrator. Return to /dashboard.", statusCode: 403));

app.MapPost("/admin/api/login", async (HttpContext ctx, LoginInput input) =>
{
    if (oidcPolicy is not null &&
        (!oidcPolicy.IsBreakGlass(input.Username) || !string.Equals(input.Provider, "local", StringComparison.OrdinalIgnoreCase) ||
         !ReadMail().Enabled))
    {
        await Audit("recovery:unknown", "ENTERPRISE_LOCAL_LOGIN_DENIED");
        return Results.Json(new { error = "Enterprise SSO required; local login is restricted to the configured OTP recovery account" }, statusCode: 403);
    }
    AdminUser? user;
    if (string.Equals(input.Provider, "directory", StringComparison.OrdinalIgnoreCase))
    {
        if (!directoryAuth.Read().Enabled || !ReadMail().Enabled)
            return Results.Json(new { error = "Directory sign-in unavailable: configure LDAPS and OTP first" }, statusCode: 403);
        DirectoryLoginResult? adResult;
        try { adResult = directoryAuth.TryLogin(input.Username ?? "", input.Password ?? ""); }
        catch { adResult = null; }
        if (adResult is null)
        {
            await Audit("ad:unknown", "AD_LOGIN_DENIED");
            return Results.Json(new { error = "Invalid directory credentials or unauthorized AD group" }, statusCode: 401);
        }
        var adName = "ad:" + adResult.SamAccountName.ToLowerInvariant();
        await loginGate.WaitAsync();
        try
        {
            var all = ReadUsers();
            var old = all.FirstOrDefault(x => x.Username.Equals(adName, StringComparison.OrdinalIgnoreCase));
            if (old is not null && (!old.Enabled || old.Provider != "AD" ||
                !string.Equals(old.DistinguishedName, adResult.DistinguishedName, StringComparison.OrdinalIgnoreCase)))
                return Results.Json(new { error = "Directory account is disabled or its identity changed; contact administrator" }, statusCode: 403);
            if (old is null)
            {
                user = new AdminUser(adName, adResult.Role, "", "", adResult.Email, true,
                    Convert.ToHexString(RandomNumberGenerator.GetBytes(24)), "AD", adResult.DistinguishedName);
                all.Add(user);
            }
            else
            {
                user = old with { Role = adResult.Role, Email = adResult.Email,
                    SecurityStamp = old.Role == adResult.Role ? old.SecurityStamp : Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) };
                all[all.IndexOf(old)] = user;
            }
            WriteUsers(all);
        }
        finally { loginGate.Release(); }
        await Audit(user!.Username, "AD_PASSWORD_VERIFIED", new { role = user.Role });
    }
    else
    {
        user = ReadUsers().FirstOrDefault(x => x.Username.Equals(input.Username ?? "", StringComparison.OrdinalIgnoreCase));
    }
    if (user is null || !user.Enabled ||
        (user.Provider != "AD" && !VerifyPassword(input.Password ?? "", user)) ||
        (user.Provider == "AD" && !string.Equals(input.Provider, "directory", StringComparison.OrdinalIgnoreCase)))
    {
        await Audit(input.Username ?? "unknown", "LOGIN_DENIED");
        return Results.Json(new { error = "Invalid credentials" }, statusCode: 401);
    }
    if (oidcPolicy is not null && (user.Provider != "Local" || user.Role != "Administrator"))
        return Results.Json(new { error = "Recovery account not authorized" }, statusCode: 403);
    var mail = ReadMail();
    if (oidcPolicy is not null && !mail.Enabled)
        return Results.Json(new { error = "Recovery OTP unavailable" }, statusCode: 503);
    if (mail.Enabled)
    {
        if (!ValidEmail(user.Email)) return Results.Json(new { error = "Account has no verified email. Contact administrator." }, statusCode: 403);
        var challengeId = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        var otp = RandomNumberGenerator.GetInt32(0, 1000000).ToString("D6");
        var nonce = RandomNumberGenerator.GetBytes(24);
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(Convert.ToHexString(nonce) + otp));
        pendingOtp[challengeId] = new OtpChallenge(user.Username, Convert.ToHexString(nonce), Convert.ToHexString(hash), DateTimeOffset.UtcNow.AddMinutes(5), 0);
        try { await SendOtp(user.Email!, otp); }
        catch { pendingOtp.TryRemove(challengeId, out _); return Results.Problem("Unable to deliver OTP. Contact administrator; sign-in blocked.", statusCode: 503); }
        await Audit(user.Username, "LOGIN_OTP_SENT");
        return Results.Ok(new { otpRequired = true, challengeId, emailHint = MaskEmail(user.Email!) });
    }
    await SignIn(user, ctx);
    await Audit(user.Username, "LOGIN_SUCCESS_PASSWORD_ONLY_LOCAL");
    return SignInResult(user, ctx);
}).RequireRateLimiting("login");

app.MapPost("/admin/api/login/verify", async (HttpContext ctx, VerifyOtpInput input) =>
{
    if (string.IsNullOrWhiteSpace(input.ChallengeId) || !pendingOtp.TryGetValue(input.ChallengeId, out var challenge))
        return Results.Json(new { error = "Code expired or invalid" }, statusCode: 401);
    if (challenge.ExpiresAt < DateTimeOffset.UtcNow || challenge.Attempts >= 5 || !Regex.IsMatch(input.Code ?? "", "^[0-9]{6}$"))
    { pendingOtp.TryRemove(input.ChallengeId, out _); return Results.Json(new { error = "Code expired or invalid" }, statusCode: 401); }
    var computed = SHA256.HashData(Encoding.UTF8.GetBytes(challenge.Nonce + input.Code));
    var valid = CryptographicOperations.FixedTimeEquals(computed, Convert.FromHexString(challenge.Hash));
    if (!valid)
    {
        pendingOtp[input.ChallengeId] = challenge with { Attempts = challenge.Attempts + 1 };
        return Results.Json(new { error = "Code expired or invalid" }, statusCode: 401);
    }
    pendingOtp.TryRemove(input.ChallengeId, out _);
    var user = ReadUsers().FirstOrDefault(x => x.Username.Equals(challenge.Username, StringComparison.OrdinalIgnoreCase));
    if (user is null || !user.Enabled) return Results.Json(new { error = "Account disabled" }, statusCode: 403);
    if (oidcPolicy is not null &&
        (!oidcPolicy.IsBreakGlass(user.Username) || user.Provider != "Local" ||
         user.Role != "Administrator" || !ReadMail().Enabled))
        return Results.Json(new { error = "Recovery session not authorized" }, statusCode: 403);
    if (user.Provider == "AD")
    {
        try { if (!directoryAuth.StillAuthorized(user.Username, user.DistinguishedName, user.Role))
            return Results.Json(new { error = "Directory authorization is no longer valid" }, statusCode: 403); }
        catch { return Results.Json(new { error = "Directory not available" }, statusCode: 503); }
    }
    await SignIn(user, ctx);
    await Audit(user.Username, "LOGIN_OTP_VERIFIED");
    return SignInResult(user, ctx);
}).RequireRateLimiting("login");

app.MapPost("/admin/api/logout", async (HttpContext ctx) =>
{
    await Audit(Actor(ctx), "LOGOUT");
    ManagementPrivacyPolicy.Clear(ctx);
    if (oidcPolicy is not null && ctx.User.HasClaim(c => c.Type == EnterpriseOidcPolicy.SubjectClaim))
        return Results.SignOut(new AuthenticationProperties { RedirectUri = "/dashboard" },
            [CookieAuthenticationDefaults.AuthenticationScheme, EnterpriseOidcPolicy.Scheme]);
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    if (string.Equals(ctx.Request.ContentType?.Split(';')[0].Trim(), "application/x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase))
        return Results.Redirect("/dashboard");
    return Results.Ok(new { loggedOut = true });
}).RequireAuthorization();

app.MapGet("/admin/api/users", () => Results.Ok(ReadUsers().Select(u => new { u.Username, u.Role, u.Email, u.Enabled, u.Provider })))
   .RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/users", async (HttpContext ctx, UserInput input) =>
{
    if (!ValidUser(input.Username) || !ValidPassword(input.Password) || !ValidEmail(input.Email) ||
        input.Role is not ("Administrator" or "Operator" or "Viewer"))
        return Results.BadRequest(new { error = "Invalid username, role or password (min 16 characters)" });
    await loginGate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AccountSnapshot();
        var users = ReadUsers();
        if (users.Any(x => x.Username.Equals(input.Username, StringComparison.OrdinalIgnoreCase)))
            return Results.Conflict(new { error = "Username exists" });
        users.Add(NewUser(input.Username, input.Role, input.Password, input.Email));
        var confirmation = await ConfirmAccountMutation(ctx, before, users, "USER_CREATE_INTENT");
        if (confirmation.Error is not null) return confirmation.Error;
        WriteUsers(users);
        await localAudit.AppendAsync(Actor(ctx), "USER_CREATED", new { input.Username, input.Role }, confirmation.IntentId);
        return Results.Ok(new { created = input.Username });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
// Invite-based self-registration is limited to ordinary, local-account lab
// installations. Enterprise identity, signed commercial identity, and external
// audit deployments continue to use their existing approved enrollment paths.
bool EmployeeInvitationsAvailable()
{
#if GATEWAYCORE_COMMERCIAL
    return false;
#else
    if (oidcPolicy is not null || externalAuditIntent is not null || OnboardingApi.IsMultiGatewayDesign(privateDir)) return false;
    var mail = ReadMail();
    return mail.Enabled && MailDeliveryVerified(mail) &&
        ReadUsers().Any(u => u.Enabled && u.Role == "Administrator");
#endif
}
#if !GATEWAYCORE_COMMERCIAL
void ExpireEmployeeInvitations()
{
    var now = DateTimeOffset.UtcNow;
    foreach (var id in employeeInvitations.Where(p => p.Value.ExpiresUtc <= now).Select(p => p.Key).ToArray())
        employeeInvitations.Remove(id);
}
bool InvitationTransportAllowed(HttpContext ctx) => ctx.Request.IsHttps ||
    (ctx.Connection.RemoteIpAddress is { } address && IPAddress.IsLoopback(address) &&
     (ctx.Request.Host.Host.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
      ctx.Request.Host.Host is "127.0.0.1" or "[::1]" or "::1"));
bool InvitationIssuerCurrent(EmployeeInvitation entry, List<AdminUser> users) =>
    users.Any(u => u.Enabled && u.Role == "Administrator" &&
        u.Username.Equals(entry.Issuer, StringComparison.OrdinalIgnoreCase) &&
        u.SecurityStamp == entry.IssuerStamp);
bool InvitationAccountFree(EmployeeInvitation entry, List<AdminUser> users) =>
    !users.Any(u => u.Username.Equals(entry.Username, StringComparison.OrdinalIgnoreCase) ||
        string.Equals(u.Email, entry.Email, StringComparison.OrdinalIgnoreCase));
IResult InvalidInvitation() => Results.BadRequest(new { error = "Invitation is invalid, expired or already used. Ask your administrator to issue a new invitation." });
app.MapGet("/admin/api/users/invitations", async (HttpContext ctx) =>
{
    if (!EmployeeInvitationsAvailable() || !InvitationTransportAllowed(ctx)) return Results.StatusCode(403);
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        if (!await AuditActorCurrent(ctx, administratorOnly: true)) return Results.StatusCode(403);
        ExpireEmployeeInvitations();
        return Results.Ok(employeeInvitations.Values.Select(x => new {
            x.Id, x.Username, emailHint = MaskEmail(x.Email), x.Role, x.ExpiresUtc,
            status = x.Verified ? "email-verified" : "awaiting-email-verification"
        }).ToArray());
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/users/invitations", async (HttpContext ctx, EmployeeInvitationInput input) =>
{
    if (!EmployeeInvitationsAvailable() || !InvitationTransportAllowed(ctx)) return Results.StatusCode(403);
    if (ctx.Request.ContentLength is > 4096 || !ValidUser(input.Username) ||
        !ValidEmail(input.Email) || !MailAddress.TryCreate(input.Email, out var address) ||
        !string.Equals(address.Address, input.Email, StringComparison.OrdinalIgnoreCase) ||
        input.Role is not ("Operator" or "Viewer"))
        return Results.BadRequest(new { error = "Enter a unique username, plain mailbox address and Operator or Viewer role." });
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        if (!await AuditActorCurrent(ctx, administratorOnly: true) || !EmployeeInvitationsAvailable())
            return Results.StatusCode(403);
        ExpireEmployeeInvitations();
        var users = ReadUsers();
        var issuer = users.Single(u => u.Username.Equals(Actor(ctx), StringComparison.OrdinalIgnoreCase));
        var cfg = ReadMail();
        var code = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var entry = new EmployeeInvitation(Convert.ToHexString(RandomNumberGenerator.GetBytes(16)),
            input.Username!, address.Address, input.Role!, issuer.Username, issuer.SecurityStamp,
            MailFingerprint(cfg), EmployeeInvitation.Digest(code), DateTimeOffset.UtcNow.AddMinutes(30), false);
        if (!InvitationAccountFree(entry, users)) return Results.Conflict(new { error = "Username or mailbox already belongs to an account." });
        if (employeeInvitations.Count >= 128) return Results.Json(new { error = "Invitation capacity reached; revoke unused invitations." }, statusCode: 429);
        if (employeeInvitations.Values.Any(x => x.Username.Equals(entry.Username, StringComparison.OrdinalIgnoreCase) ||
            x.Email.Equals(entry.Email, StringComparison.OrdinalIgnoreCase)))
            return Results.Conflict(new { error = "A pending invitation already exists; revoke it before issuing another." });
        await SendMailMessage(entry.Email, "GatewayCore employee invitation",
            $"You have been invited to GatewayCore as {entry.Role} with username {entry.Username}. Open the authorized management dashboard, choose Accept employee invitation, and enter this one-time code: {code}. It expires in 30 minutes. Never share this code or a password.", cfg);
        if (ctx.RequestAborted.IsCancellationRequested || !EmployeeInvitationsAvailable() ||
            !InvitationIssuerCurrent(entry, ReadUsers()) || MailFingerprint(ReadMail()) != entry.MailFingerprint)
            return Results.Conflict(new { error = "Invitation authorization changed; ask the administrator to issue another." });
        await Audit(issuer.Username, "EMPLOYEE_INVITATION_ISSUED", new { entry.Id, entry.Username, entry.Role });
        employeeInvitations.Add(entry.Id, entry);
        return Results.Ok(new { entry.Id, entry.Username, emailHint = MaskEmail(entry.Email), entry.Role, entry.ExpiresUtc });
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        app.Logger.LogWarning("EMPLOYEE_INVITATION_ISSUE_FAILED type={ErrorType}", ex.GetType().Name);
        return Results.Json(new { error = "Invitation could not be issued. Check verified SMTP and audit availability." }, statusCode: 503);
    }
    finally { loginGate.Release(); }
}).WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(4096)).RequireRateLimiting("employee-invite-issue").RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/users/invitations/{id}/revoke", async (HttpContext ctx, string id) =>
{
    if (!InvitationTransportAllowed(ctx) || !Regex.IsMatch(id, "^[A-F0-9]{32}$")) return Results.BadRequest();
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        if (!await AuditActorCurrent(ctx, administratorOnly: true)) return Results.StatusCode(403);
        ExpireEmployeeInvitations();
        if (!employeeInvitations.TryGetValue(id, out var entry)) return Results.NotFound();
        await Audit(Actor(ctx), "EMPLOYEE_INVITATION_REVOKED", new { entry.Id, entry.Username });
        employeeInvitations.Remove(id);
        return Results.Ok(new { revoked = true });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/employee-invitation/redeem", async (HttpContext ctx, EmployeeInvitationRedeem input) =>
{
    // This exact unauthenticated endpoint is protected by an emailed 256-bit
    // capability, the existing management transport restriction, bounded body,
    // rate limiting and the account writer gate. It never issues a session.
    if (!EmployeeInvitationsAvailable() || !InvitationTransportAllowed(ctx) ||
        ctx.User.Identity?.IsAuthenticated == true) return Results.StatusCode(403);
    if (ctx.Request.ContentLength is > 4096 || input.Action is not ("verify" or "finish") ||
        input.Code is null || !Regex.IsMatch(input.Code, "^[A-Fa-f0-9]{64}$")) return InvalidInvitation();
    await loginGate.WaitAsync(ctx.RequestAborted);
    try
    {
        if (!EmployeeInvitationsAvailable()) return Results.StatusCode(403);
        ExpireEmployeeInvitations();
        var digest = EmployeeInvitation.Digest(input.Code.ToUpperInvariant());
        var entry = employeeInvitations.Values.SingleOrDefault(x => CryptographicOperations.FixedTimeEquals(x.CodeHash, digest));
        if (entry is null || entry.Verified != (input.Action == "finish")) return InvalidInvitation();
        var users = ReadUsers();
        if (!InvitationIssuerCurrent(entry, users) || !InvitationAccountFree(entry, users) ||
            entry.MailFingerprint != MailFingerprint(ReadMail()))
        {
            employeeInvitations.Remove(entry.Id);
            return InvalidInvitation();
        }
        // The server's stored capability state, not the submitted action,
        // determines the transition. Action is only a consistency assertion.
        if (!entry.Verified)
        {
            // Rotate away from the emailed credential immediately. The short
            // completion capability never appears in a URL or persistent storage.
            var completion = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            var expires = DateTimeOffset.UtcNow.AddMinutes(10);
            if (expires > entry.ExpiresUtc) expires = entry.ExpiresUtc;
            await Audit(entry.Issuer, "EMPLOYEE_INVITATION_EMAIL_VERIFIED", new { entry.Id, entry.Username });
            employeeInvitations[entry.Id] = entry with { CodeHash = EmployeeInvitation.Digest(completion), Verified = true, ExpiresUtc = expires };
            return Results.Ok(new { verified = true, completion, entry.Username, entry.Role });
        }
        if (!ValidPassword(input.Password)) return Results.BadRequest(new { error = "Password must contain 16–256 characters." });
        users.Add(NewUser(entry.Username, entry.Role, input.Password!, entry.Email));
        await Audit(entry.Issuer, "EMPLOYEE_INVITATION_REDEMPTION_PREPARED", new { entry.Id, entry.Username, entry.Role });
        if (ctx.RequestAborted.IsCancellationRequested || !EmployeeInvitationsAvailable() ||
            entry.MailFingerprint != MailFingerprint(ReadMail()) || entry.ExpiresUtc <= DateTimeOffset.UtcNow ||
            !InvitationIssuerCurrent(entry, ReadUsers()) || !InvitationAccountFree(entry, ReadUsers()))
            return InvalidInvitation();
        WriteUsers(users);
        employeeInvitations.Remove(entry.Id);
        await Audit(entry.Username, "EMPLOYEE_INVITATION_REDEEMED", new { entry.Id, entry.Role });
        return Results.Ok(new { created = true, entry.Username });
    }
    catch (Exception ex) when (ex is not OperationCanceledException)
    {
        app.Logger.LogWarning("EMPLOYEE_INVITATION_REDEEM_FAILED type={ErrorType}", ex.GetType().Name);
        return Results.Json(new { error = "Registration could not be completed. Contact your administrator." }, statusCode: 503);
    }
    finally { loginGate.Release(); }
}).WithMetadata(new Microsoft.AspNetCore.Mvc.RequestSizeLimitAttribute(4096),
    new EmployeeInvitationRedemptionEndpoint()).RequireRateLimiting("employee-invite-redeem").AllowAnonymous();
#endif

app.MapPost("/admin/api/users/{username}/password", async (HttpContext ctx, string username, PasswordInput input) =>
{
    if (!ValidPassword(input.Password)) return Results.BadRequest(new { error = "Password must contain at least 16 characters" });
    await loginGate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AccountSnapshot();
        var users = ReadUsers();
        var user = users.FirstOrDefault(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (user is null) return Results.NotFound();
        if (user.Provider == "AD") return Results.BadRequest(new { error = "Reset directory passwords in Active Directory, not this console" });
        var updated = NewUser(user.Username, user.Role, input.Password, user.Email) with
        { Enabled = user.Enabled, OidcRevokedBefore = user.OidcRevokedBefore,
            OidcLogoutAuditThrough = user.OidcLogoutAuditThrough };
        users[users.IndexOf(user)] = updated;
        var confirmation = await ConfirmAccountMutation(ctx, before, users, "USER_PASSWORD_RESET_INTENT");
        if (confirmation.Error is not null) return confirmation.Error;
        WriteUsers(users);
        await localAudit.AppendAsync(Actor(ctx), "PASSWORD_RESET", new { username }, confirmation.IntentId);
        return Results.Ok(new { changed = true, reLoginRequired = true });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

// User offboarding rotates the security stamp; OnValidatePrincipal rejects old cookies on each authenticated request.
app.MapPost("/admin/api/users/{username}/disable", async (HttpContext ctx, string username) =>
{
    await loginGate.WaitAsync();
    try
    {
        if (string.Equals(username, Actor(ctx), StringComparison.OrdinalIgnoreCase)) return Results.BadRequest(new { error = "Cannot disable own account" });
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AccountSnapshot();
        var users = ReadUsers(); var i = users.FindIndex(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return Results.NotFound();
        if (users[i].Role == "Administrator" && users.Count(x => x.Enabled && x.Role == "Administrator") <= 1)
            return Results.BadRequest(new { error = "Last active administrator cannot be disabled" });
        users[i] = users[i] with { Enabled = false, SecurityStamp = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) };
        var confirmation = await ConfirmAccountMutation(ctx, before, users, "USER_DISABLE_INTENT");
        if (confirmation.Error is not null) return confirmation.Error;
        WriteUsers(users);
        await localAudit.AppendAsync(Actor(ctx), "USER_OFFBOARDED", new { username }, confirmation.IntentId);
        return Results.Ok(new { disabled = username });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/users/{username}/enable", async (HttpContext ctx, string username) =>
{
    await loginGate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AccountSnapshot();
        var users = ReadUsers(); var i = users.FindIndex(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return Results.NotFound();
        users[i] = users[i] with { Enabled = true, SecurityStamp = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) };
        var confirmation = await ConfirmAccountMutation(ctx, before, users, "USER_ENABLE_INTENT");
        if (confirmation.Error is not null) return confirmation.Error;
        WriteUsers(users);
        await localAudit.AppendAsync(Actor(ctx), "USER_REENABLED", new { username }, confirmation.IntentId);
        return Results.Ok(new { enabled = username });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/mail", () => {
    var m = ReadMail();
    return Results.Ok(new { m.Enabled, m.Host, m.Port, m.From, m.Username, m.StartTls,
        m.AuthMode, m.OAuthClientId, m.OAuthTenant,
        passwordConfigured = !string.IsNullOrEmpty(m.EncryptedPassword),
        oauthClientSecretConfigured = !string.IsNullOrEmpty(m.EncryptedOAuthClientSecret),
        oauthRefreshTokenConfigured = !string.IsNullOrEmpty(m.EncryptedOAuthRefreshToken),
        deliveryVerified = MailDeliveryVerified(m) });
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/mail", async (HttpContext ctx, MailSettingsInput input) =>
{
    if (input.Host is null || input.From is null || input.Username is null || input.Password is null ||
        input.Port is < 1 or > 65535 || input.Port == 465 || input.Host.Length > 255 || input.From.Length > 254 || input.Username.Length > 254 ||
        (input.Enabled && (string.IsNullOrWhiteSpace(input.Host) || !ValidEmail(input.From) || !input.StartTls)))
        return Results.BadRequest(new { code = "SMTP_INVALID_SETTINGS", error = "Check SMTP host, port (465 unsupported), sender address, and STARTTLS before enabling OTP." });
    await identitySettingsGate.WaitAsync(ctx.RequestAborted);
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(mailPath);
        var existing = ReadMail();
        var mode = string.IsNullOrEmpty(input.AuthMode) ? MailProviderAuth.PasswordMode : input.AuthMode;
        var sameOAuthIdentity = string.Equals(existing.AuthMode, mode, StringComparison.Ordinal)
            && string.Equals(existing.Host, input.Host, StringComparison.OrdinalIgnoreCase)
            && string.Equals(existing.Username, input.Username, StringComparison.OrdinalIgnoreCase)
            && string.Equals(existing.OAuthClientId, input.OAuthClientId, StringComparison.Ordinal)
            && string.Equals(existing.OAuthTenant, input.OAuthTenant, StringComparison.Ordinal);
        var encrypted = mode != MailProviderAuth.PasswordMode ? ""
            : string.IsNullOrEmpty(input.Password)
              ? string.Equals(existing.Username, input.Username, StringComparison.OrdinalIgnoreCase)
                && string.Equals(existing.Host, input.Host, StringComparison.OrdinalIgnoreCase)
                ? existing.EncryptedPassword : ""
              : protector.Protect(input.Password);
        var oauthSecret = !MailProviderAuth.UsesOAuth(mode) ? ""
            : !string.IsNullOrEmpty(input.OAuthClientSecret)
              ? protector.Protect(input.OAuthClientSecret)
              : sameOAuthIdentity ? existing.EncryptedOAuthClientSecret : "";
        var oauthRefresh = !MailProviderAuth.UsesOAuth(mode) || mode == MailProviderAuth.MicrosoftApp ? ""
            : !string.IsNullOrEmpty(input.OAuthRefreshToken)
              ? protector.Protect(input.OAuthRefreshToken)
              : sameOAuthIdentity ? existing.EncryptedOAuthRefreshToken : "";
        var validation = MailProviderAuth.Validate(mode, input.Host, input.Username,
            input.OAuthTenant, input.OAuthClientId, !string.IsNullOrEmpty(oauthSecret),
            !string.IsNullOrEmpty(oauthRefresh));
        if (validation != null)
            return Results.BadRequest(new { code = "MAIL_AUTH_INVALID", error = validation });
        if (mode == MailProviderAuth.PasswordMode && !string.IsNullOrWhiteSpace(input.Username)
            && string.IsNullOrEmpty(encrypted))
            return Results.BadRequest(new { code = "SMTP_PASSWORD_REQUIRED", error = "Supply an app password for authenticated SMTP or remove the username for a trusted relay." });
        var mail = new MailSettings(input.Enabled, input.Host, input.Port, input.From,
            input.Username, encrypted, input.StartTls, mode,
            MailProviderAuth.UsesOAuth(mode) ? input.OAuthClientId : "",
            oauthSecret, oauthRefresh, MailProviderAuth.UsesOAuth(mode) ? input.OAuthTenant : "");
        if (input.Enabled && !MailDeliveryVerified(mail))
            return Results.Json(new { code = "SMTP_TEST_REQUIRED", error = "Save SMTP settings with OTP disabled, send a successful test to the administrator email, then enable OTP." }, statusCode: 409);
        var proposed = JsonSerializer.SerializeToUtf8Bytes(mail);
        var denied = await ConfirmStateMutation(ctx, mailPath, before, proposed, "MAIL_SETTINGS_INTENT", true);
        if (denied is not null) return denied;
        if (mail.Enabled && !MailDeliveryVerified(mail))
            return Results.Conflict(new { error = "Verified SMTP settings changed during confirmation" });
        WriteAuditedState(mailPath, proposed);
        await Audit(Actor(ctx), "MAIL_SETTINGS_UPDATED", new { input.Enabled, input.Host, input.Port, input.StartTls });
        return Results.Ok(new { saved = true, otpRequiredOnNextLogin = mail.Enabled });
    }
    finally { identitySettingsGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/mail/test", async (HttpContext ctx) =>
{
    var admin = ReadUsers().FirstOrDefault(x => x.Username.Equals(Actor(ctx), StringComparison.OrdinalIgnoreCase));
    if (admin is null || !ValidEmail(admin.Email)) return Results.BadRequest(new { code = "SMTP_ADMIN_EMAIL_REQUIRED", error = "Set a valid administrator email under Administrators and roles before sending a test." });
    await identitySettingsGate.WaitAsync(ctx.RequestAborted);
    try
    {
        var cfg = ReadMail();
        if (string.IsNullOrWhiteSpace(cfg.Host) || !ValidEmail(cfg.From) || !cfg.StartTls)
            return Results.Json(new { code = "SMTP_NOT_CONFIGURED", error = "Save a valid SMTP relay, sender, and STARTTLS configuration with OTP disabled before testing." }, statusCode: 409);
        await SendMailMessage(admin.Email!, "YARP Control Center SMTP test", "This is a test message from your local YARP administration console.", cfg);
        if (ReadMail() != cfg)
            return Results.Conflict(new { error = "SMTP settings changed during delivery test" });
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(mailProofPath);
        var proposed = Encoding.UTF8.GetBytes(MailFingerprint(cfg));
        var denied = await ConfirmStateMutation(ctx, mailProofPath, before, proposed, "MAIL_PROOF_INTENT", true);
        if (denied is not null) return denied;
        if (ReadMail() != cfg)
            return Results.Conflict(new { error = "SMTP settings changed during audit confirmation" });
        WriteAuditedState(mailProofPath, proposed);
        await Audit(Actor(ctx), "SMTP_DELIVERY_TEST_SUCCEEDED", new { cfg.Host, recipient = admin.Email });
        return Results.Ok(new { tested = true, recipient = admin.Email, note = "SMTP relay accepted message; confirm it arrived" });
    }
    catch (Exception ex)
    {
        // Diagnostics are intentionally limited to exception TYPES, never the
        // untrusted error message: SMTP libraries can include credentials,
        // server banners, usernames or recipient addresses in exception text.
        var failureType = ex.GetType().Name;
        var innerType = ex.InnerException?.GetType().Name ?? "None";
        var smtpStatus = ex is MailKit.Net.Smtp.SmtpCommandException smtpException ? (int)smtpException.StatusCode : -1;
        app.Logger.LogWarning("SMTP_DELIVERY_TEST_FAILED errorType={ErrorType} innerType={InnerType} smtpStatus={SmtpStatus}",
            failureType, innerType, smtpStatus);
        await Audit(Actor(ctx), "SMTP_DELIVERY_TEST_FAILED", new { failureType, innerType, smtpStatus });
        return Results.Json(new { code = "SMTP_RELAY_UNAVAILABLE", error = "SMTP relay test failed. Check reachability, STARTTLS certificate trust, credentials and relay permissions. No OTP settings were enabled." }, statusCode: 503);
    }
    finally { identitySettingsGate.Release(); }
}).RequireRateLimiting("mailtest").RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/directory", () => Results.Ok(directoryAuth.PublicSettings()))
    .RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/directory", async (HttpContext ctx, DirectorySettingsInput input) =>
{
    await identitySettingsGate.WaitAsync(ctx.RequestAborted);
    try
    {
        var mail = ReadMail();
        if (input.Enabled && (!mail.Enabled || !MailDeliveryVerified(mail)))
            return Results.BadRequest(new { error = "Enable verified SMTP email OTP before enabling AD login" });
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(directoryPath);
        var proposed = directoryAuth.PrepareSettings(input);
        var denied = await ConfirmStateMutation(ctx, directoryPath, before, proposed, "DIRECTORY_SETTINGS_INTENT", true);
        if (denied is not null) return denied;
        if (input.Enabled && (ReadMail() != mail || !MailDeliveryVerified(mail)))
            return Results.Conflict(new { error = "Verified SMTP settings changed during directory confirmation" });
        WriteAuditedState(directoryPath, proposed);
        await Audit(Actor(ctx), "DIRECTORY_SETTINGS_UPDATED", new { input.Enabled, input.Host, input.Port, input.SearchBaseDn });
        return Results.Ok(new { saved = true, enabled = input.Enabled, note = "Existing AD sessions are revalidated on requests" });
    }
    catch (Exception ex) when (ex is ArgumentException or LdapException or InvalidOperationException or DirectoryOperationException)
    { return Results.BadRequest(new { error = "LDAPS configuration not accepted: check hostname, certificate, bind identity, base DN and mapped group DNs" }); }
    finally { identitySettingsGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/directory/test", async (HttpContext ctx) =>
{
    try
    {
        directoryAuth.TestSavedConnection();
        await Audit(Actor(ctx), "DIRECTORY_CONNECTION_TEST_PASSED");
        return Results.Ok(new { tested = true, connection = "LDAPS/TLS validated; service bind and group lookup succeeded" });
    }
    catch
    {
        await Audit(Actor(ctx), "DIRECTORY_CONNECTION_TEST_FAILED");
        return Results.Json(new { error = "LDAPS connection test failed. Verify DC certificate trust, DNS, 636/TCP, service bind and group DN" }, statusCode: 503);
    }
}).RequireRateLimiting("ldaptest").RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/directory/test-user", async (HttpContext ctx, DirectoryLoginTest input) =>
{
    try
    {
        var user = directoryAuth.TryLogin(input.Username, input.Password);
        await Audit(Actor(ctx), user is null ? "DIRECTORY_USER_TEST_DENIED" : "DIRECTORY_USER_TEST_PASSED");
        return user is null ? Results.Json(new { error = "Not authenticated or not in an allowed AD group" }, statusCode: 401)
            : Results.Ok(new { tested = true, username = user.SamAccountName, role = user.Role, emailAvailable = !string.IsNullOrWhiteSpace(user.Email) });
    }
    catch { return Results.Json(new { error = "Directory user test failed" }, statusCode: 503); }
}).RequireRateLimiting("ldaptest").RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/inventory", () => Results.Ok(ReadInventory())).RequireAuthorization();
app.MapGet("/admin/api/network/interfaces", (HttpContext ctx) =>
{
    ctx.Response.Headers.CacheControl = "no-store";
    try
    {
        var snapshot = LocalNetworkInventory.Read();
        var virtualAddresses = (isolatedListeners?.VirtualServices ?? Array.Empty<GatewayListenerIsolation.VirtualSocket>())
            .Select(service =>
            {
                var observed = NetworkObservation.ObserveVirtualAddress(service.Id, service.Ip, service.Port, service.Protocol, snapshot);
                return new { observed.Id, observed.Ip, observed.Port, observed.Protocol, observed.Status,
                    observed.Interfaces, service.RequireLocalAddressPresence, distributedOwnershipRequired = service.VipQuorumConfigPath is not null, admission = localVipAdmission?.Status(service.Id) ?? "disabled", activeGuardedRequests = localVipAdmission?.Active(service.Id) ?? 0,
                    ownershipMode=service.VipJournalDirectory is not null?"journal-bound":service.VipOwnershipEpoch is not null?"fixed-epoch":"local-only",
                    haPolicyScope=service.VipJournalDirectory is not null?FleetQuorum.VipScope(service.VipFleetId!,service.Ip):null,
                    plannedDrain=localVipAdmission?.IsManualDrain(service.Id)??false,
                    automaticDrain=localVipAdmission?.IsAutomaticDrain(service.Id)??false,
                    automaticDrainConfigured=vipMachineAddress==IPAddress.Parse(service.Ip).ToString(),
                    ownershipEpoch=vipEpochs.TryGetValue(service.Id,out var vipEpoch)?vipEpoch:(long?)null,
                    recoveryAuthority=service.VipJournalDirectory is not null?"independent-controller":null,
                    recoveryVerified=false,
                    drainEligible=vipDrainGroups.ContainsKey(IPAddress.Parse(service.Ip).ToString()) };
            })
            .ToArray();
        return Results.Ok(new { snapshot.Scope, snapshot.Platform, snapshot.ObservedUtc, snapshot.Interfaces,
            snapshot.Truncated, vlans = NetworkObservation.ReadVlans(), virtualAddresses });
    }
    catch (Exception error) when (error is System.Net.NetworkInformation.NetworkInformationException or
        InvalidOperationException or PlatformNotSupportedException or System.Net.Sockets.SocketException)
    { return Results.Json(new { error = "Local network inventory unavailable." }, statusCode: 503); }
}).RequireAuthorization(policy => policy.RequireRole("Administrator", "Operator"));
// Nonsecret policy proposal only: never mutates the independent controller.
app.MapPost("/admin/api/network/virtual-services/ha-policy",async (HttpContext ctx,VipPolicyDocument proposal)=>
{
    ctx.Response.Headers.CacheControl = "no-store";
    if(!await AuditActorCurrent(ctx,true))return Results.StatusCode(403);
    var configured=(guardedVirtualServices??[]).Any(s=>s.VipJournalDirectory is not null&&
        FleetQuorum.VipScope(s.VipFleetId!,s.Ip)==proposal.Scope);
    if(!configured)return Results.BadRequest(new{error="Choose an existing journal-bound VIP."});
    try{proposal.Validate(proposal.Scope);}
    catch(InvalidDataException){return Results.BadRequest(new{error="Invalid HA policy: verify exact scope, two distinct pins and safety bounds."});}
    var json=JsonSerializer.Serialize(proposal,VipPolicyDocument.Json);
    var digest=Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(json)));
    await Audit(Actor(ctx),"VIP_HA_POLICY_EXPORTED",new{scope=proposal.Scope,sha256=digest});
    return Results.Ok(new{json,sha256=digest,applied=false});
}).RequireAuthorization(policy=>policy.RequireRole("Administrator"));
// Machine-only endpoint is isolated on the mTLS administration socket.
// It cannot authenticate as a user, clear manual drains, or change routes.
app.MapPost("/admin/vip-machine/drain",async (HttpContext ctx,VipMachineDrainInput input)=>
{
    if(vipMachineService is null||vipMachinePath is null||localVipAdmission is null||
        isolatedListeners is null||vipMachineAddress is null||input.Scope!=vipMachineScope||
        input.Epoch!=vipMachineEpoch||!VipFenceProvider.Pin(input.Nonce)||
        !isolatedListeners.OnAdmin(ctx)||ctx.Connection.ClientCertificate is not { } cert||
        !CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.RawData),Convert.FromHexString(vipMachinePin!)))
        return Results.StatusCode(403);
#if GATEWAYCORE_COMMERCIAL
    if(!commercialLicense.Permits("/admin/api/network/virtual-services"))return Results.StatusCode(402);
#endif
    var group=vipDrainGroups[vipMachineAddress];
    async Task<bool> Authorized()
    {
        if(ctx.RequestAborted.IsCancellationRequested||SetupCenter.ReadFreeze(privateDir).Frozen||
            group.Any(id=>!localVipAdmission.Allows(id)))return false;
#if GATEWAYCORE_COMMERCIAL
        if(!commercialLicense.Permits("/admin/api/network/virtual-services"))return false;
#endif
        try
        {
            using var timeout=CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
            timeout.CancelAfter(TimeSpan.FromSeconds(2));
            return await vipAuthorityChecks[vipMachineService.Id](timeout.Token)&&!timeout.IsCancellationRequested;
        }
        catch(Exception error) when(error is HttpRequestException or IOException or InvalidOperationException or
            JsonException or OperationCanceledException or FormatException or UnauthorizedAccessException or KeyNotFoundException)
        {return false;}
    }
    await gate.WaitAsync(ctx.RequestAborted);
    try
    {
        if(!await Authorized())return Results.StatusCode(403);
        if(input.Drain&&!vipMachineDrained)
        {
            ctx.Items[vipMachineAuthKey]=(Func<Task<bool>>)Authorized;
            var before=AuditStateBytes(vipMachinePath);
            var proposed=VipMachineDrainState.Encode(vipMachineScope!,vipMachineEpoch);
            await Audit(Actor(ctx),"VIP_AUTOMATIC_DRAIN_REQUESTED",new{scope=input.Scope,epoch=input.Epoch});
            var denied=await ConfirmAndWriteResourceMutation(ctx,vipMachinePath,before,proposed,"VIP_AUTOMATIC_DRAIN_INTENT",true);
            if(denied is not null)return denied;
            vipMachineDrained=true;
            activeAutomaticDrains.UnionWith(group);
            localVipAdmission.SetAutomaticDrains(activeAutomaticDrains);
            await Audit(Actor(ctx),"VIP_AUTOMATIC_DRAIN_COMMITTED",new{scope=input.Scope,epoch=input.Epoch});
        }
        return Results.Ok(new{scope=input.Scope,epoch=input.Epoch,nonce=input.Nonce,
            draining=vipMachineDrained,manualDrain=group.Any(localVipAdmission.IsManualDrain),
            active=group.Sum(localVipAdmission.Active)});
    }
    finally{ctx.Items.Remove(vipMachineAuthKey);gate.Release();}
});
app.MapPost("/admin/api/network/virtual-services/{id}/drain",async (HttpContext ctx,string id,VipDrainInput input)=>
{
    if(input.Draining is null || string.IsNullOrWhiteSpace(input.Reason) ||
        input.Reason.Length>240 || input.Reason.Any(char.IsControl))
        return Results.BadRequest(new {error="Explicit drain/resume choice and reason required (1–240 characters)."});
    var service=isolatedListeners?.VirtualServices.SingleOrDefault(s=>s.Id==id);
    if(service is null || localVipAdmission is null ||
        !vipDrainGroups.TryGetValue(IPAddress.Parse(service.Ip).ToString(),out var group))
        return Results.NotFound(new {error="No eligible dedicated guarded VIP group."});
    var address=IPAddress.Parse(service.Ip).ToString();
    await gate.WaitAsync(ctx.RequestAborted);
    try
    {
        var before=AuditStateBytes(vipDrainPath);
        var current=VipDrainState.Read(vipDrainPath,vipDrainGroups.Keys);
        if(vipDrainGroups.Any(pair=>pair.Value.Any(socket=>localVipAdmission.IsManualDrain(socket)!=current.Contains(pair.Key))))
            return Results.Conflict(new {error="Persistent and live drain states differ. Independently reconcile before changing traffic."});
        if(!input.Draining.Value && group.Any(socket=>!localVipAdmission.Allows(socket)))
            return Results.Conflict(new {error="Fresh local and required quorum authorization must be confirmed before resuming."});
        if(input.Draining.Value)current.Add(address);else current.Remove(address);
        var proposed=VipDrainState.Encode(current);
        await Audit(Actor(ctx),"VIP_PLANNED_DRAIN_REQUESTED",new {serviceId=id,draining=input.Draining.Value,reason=input.Reason});
        var denied=await ConfirmAndWriteResourceMutation(ctx,vipDrainPath,before,proposed,"VIP_PLANNED_DRAIN_INTENT",true);
        if(denied is not null)return denied;
        localVipAdmission.SetPlannedDrains(current.SelectMany(ip=>vipDrainGroups[ip]));
        await Audit(Actor(ctx),"VIP_PLANNED_DRAIN_COMMITTED",new {serviceId=id,draining=input.Draining.Value});
        return Results.Ok(new {plannedDrain=input.Draining.Value,activeGuardedRequests=group.Sum(localVipAdmission.Active),
            scope="local gateway; not hard-fencing evidence"});
    }
    finally{gate.Release();}
}).RequireAuthorization(policy=>policy.RequireRole("Administrator"));
app.MapPost("/admin/api/inventory", async (HttpContext ctx, InventoryInput input) =>
{
    if (!ValidId(input.Id) || input.Name.Length is < 1 or > 100 ||
        input.Type is not ("YARP Gateway" or "Application Server" or "Pgpool" or "Database" or "Service") ||
        input.Address.Length > 255) return Results.BadRequest(new { error = "Invalid inventory entry" });
    await gate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(inventoryPath);
        var entries = ReadInventory();
        if (entries.Any(x => x.Id == input.Id)) return Results.Conflict(new { error = "ID already exists" });
        entries.Add(input);
        var proposed = JsonSerializer.SerializeToUtf8Bytes(entries);
        var denied = await ConfirmAndWriteResourceMutation(ctx, inventoryPath, before, proposed, "INVENTORY_ADD_INTENT", false);
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "INVENTORY_ADDED", new { input.Id, input.Type });
        return Results.Ok(new { added = input.Id });
    }
    finally { gate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
app.MapDelete("/admin/api/inventory/{id}", async (HttpContext ctx, string id) =>
{
    await gate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(inventoryPath);
        var items = ReadInventory();
        var changed = items.RemoveAll(x => x.Id == id);
        if (changed == 0) return Results.NotFound();
        var proposed = JsonSerializer.SerializeToUtf8Bytes(items);
        var denied = await ConfirmAndWriteResourceMutation(ctx, inventoryPath, before, proposed, "INVENTORY_DELETE_INTENT", false);
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "INVENTORY_DELETED", new { id });
        return Results.Ok(new { deleted = id });
    }
    finally { gate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));
List<InventoryInput> ReadInventory() => File.Exists(inventoryPath)
    ? (JsonSerializer.Deserialize<List<InventoryInput>>(File.ReadAllText(inventoryPath), jsonOptions) ?? new())
    : new();

app.MapGet("/", () => Results.Redirect("/dashboard"));
app.MapGet("/dashboard", () => Results.File(Path.Combine(root, "wwwroot", "index.html"), "text/html; charset=utf-8"));
#if GATEWAYCORE_COMMERCIAL
app.MapGet("/dashboard/license", () => Results.File(Path.Combine(root, "wwwroot", "license.html"), "text/html; charset=utf-8"));
app.MapGet("/dashboard/license.js", () => Results.File(Path.Combine(root, "wwwroot", "license.js"), "text/javascript; charset=utf-8"));
#endif
app.MapGet("/dashboard/privacy", () => Results.Content(ManagementPrivacyPolicy.Page(), "text/html; charset=utf-8"));
app.MapGet("/dashboard/app.js", () => Results.File(Path.Combine(root, "wwwroot", "app.js"), "text/javascript; charset=utf-8"));
app.MapGet("/dashboard/first-run.js", () => Results.File(Path.Combine(root, "wwwroot", "first-run.js"), "text/javascript; charset=utf-8"));
app.MapGet("/dashboard/style.css", () => Results.File(Path.Combine(root, "wwwroot", "style.css"), "text/css; charset=utf-8"));
app.MapGet("/gateway/health", () => Results.Ok(new { status = "healthy", gateway = Environment.MachineName, utc = DateTimeOffset.UtcNow }));
app.MapHttp01Challenge(acmeHttp01PublicEntrypointEnabled,
    ctx => isolatedListeners?.OnTrafficHttp(ctx) == true);
if (acmeRenewalSettings is { } revokeSettings)
{
    app.MapPost("/admin/api/tls/acme/renew-due", async (HttpContext ctx, AcmeRenewalBackgroundService worker) =>
    {
        if (!await AuditActorCurrent(ctx, administratorOnly: true))
            return Results.StatusCode(403);
        await Audit(Actor(ctx), "ACME_RENEWAL_CHECK_REQUESTED", new { dnsName = revokeSettings.DnsName });
        if (!await AuditActorCurrent(ctx, administratorOnly: true))
            return Results.StatusCode(403);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted,
            app.Lifetime.ApplicationStopping);
        linked.CancelAfter(TimeSpan.FromMinutes(11));
        try
        {
            var outcome = await worker.CheckDueAsync(linked.Token);
            if (outcome is null) return Results.Conflict(new { error = "A scheduled or manual certificate check is already in progress." });
            await Audit(Actor(ctx), "ACME_RENEWAL_CHECK_COMPLETED", new { outcome.Renewed, outcome.NotAfter, outcome.Reason });
            return Results.Ok(outcome);
        }
        catch (Exception ex)
        {
            await Audit(Actor(ctx), "ACME_RENEWAL_CHECK_FAILED", new { failureType = ex.GetType().Name });
            return Results.Json(new { error = "Renewal was not confirmed. Inspect certificate status and audit before retrying." }, statusCode: 503);
        }
    }).RequireAuthorization(policy => policy.RequireRole("Administrator"))
      .RequireRateLimiting("acme-renew-due");

    app.MapPost("/admin/api/tls/acme/revoke", async (HttpContext ctx,
        AcmeRevocationCoordinator coordinator) =>
    {
        AcmeRevocationRequest input;
        try
        {
            // Read the body ourselves before parsing. The same limit is also endpoint
            // metadata so Kestrel rejects Content-Length and chunked overflows.
            input = await AcmeRevocationRequestReader.ReadAsync(ctx.Request, ctx.RequestAborted);
        }
        catch (AcmeRevocationRequestTooLargeException)
        {
            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
        }
        catch (Exception ex) when (ex is InvalidDataException or JsonException)
        {
            return Results.BadRequest(new { error = "Revocation request JSON is invalid." });
        }

        await Audit(Actor(ctx), "ACME_CERTIFICATE_REVOCATION_REQUEST", new
        {
            thumbprint = input.Thumbprint,
            reason = input.Reason,
            dnsName = revokeSettings.DnsName
        });
        try
        {
            var result = await coordinator.RevokeAsync(input, ctx.RequestAborted);
            await Audit(Actor(ctx), "ACME_CERTIFICATE_REVOKED", new
            {
                result.Thumbprint, result.DnsName, reason = result.Reason.ToString()
            });
            return Results.Ok(new { revoked = true, result.Thumbprint, result.DnsName, reason = result.Reason.ToString() });
        }
        catch (AcmeActiveCertificateRevocationException)
        {
            await Audit(Actor(ctx), "ACME_CERTIFICATE_REVOCATION_REJECTED_ACTIVE", new { thumbprint = input.Thumbprint });
            return Results.Conflict(new { error = "The currently served traffic certificate cannot be revoked." });
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException or InvalidOperationException)
        {
            await Audit(Actor(ctx), "ACME_CERTIFICATE_REVOCATION_REJECTED", new
            {
                thumbprint = input.Thumbprint, failureType = ex.GetType().Name
            });
            return Results.BadRequest(new { error = "Certificate revocation request was rejected." });
        }
        catch (Exception ex)
        {
            await Audit(Actor(ctx), "ACME_CERTIFICATE_REVOCATION_FAILED", new
            {
                thumbprint = input.Thumbprint, failureType = ex.GetType().Name
            });
            return Results.Json(new { error = "ACME certificate revocation is unavailable." }, statusCode: 503);
        }
    })
    .WithMetadata(new RequestSizeLimitAttribute(AcmeRevocationRequestReader.MaxRequestBytes))
    .RequireAuthorization(policy => policy.RequireRole("Administrator"))
    .RequireRateLimiting("acme-revoke");
}
// Readiness is on the DATA listener only in isolated mode; unknown/empty backends fail closed.
app.MapGet("/gateway/health/ready", (IProxyStateLookup proxy) =>
    !app.Lifetime.ApplicationStopping.IsCancellationRequested && GatewayListenerIsolation.AnyDestinationHealthy(proxy)
        ? Results.Ok(new { ready = true })
        : Results.StatusCode(503));

// Authenticated management-plane observation. Do not relax data-listener isolation
// to make the dashboard poll the public readiness endpoint.
app.MapGet("/admin/api/gateway-readiness", (IProxyStateLookup proxy) =>
    Results.Ok(new {
        ready = !app.Lifetime.ApplicationStopping.IsCancellationRequested && GatewayListenerIsolation.AnyDestinationHealthy(proxy),
        scope = "Local active destination health",
        collectedUtc = DateTimeOffset.UtcNow
    })).RequireAuthorization();

// Parse and hash one immutable file snapshot. Preserve the text reader's
// BOM handling for pre-existing operator-managed configuration files.
static JsonObject ParseConfigSnapshot(byte[] bytes)
{
    using var reader = new StreamReader(new MemoryStream(bytes), detectEncodingFromByteOrderMarks: true);
    return JsonNode.Parse(reader.ReadToEnd())!.AsObject();
}
JsonObject ReadConfig() => ParseConfigSnapshot(File.ReadAllBytes(configPath));
JsonObject ReadProxy() => (ReadConfig()["ReverseProxy"]?.DeepClone() as JsonObject) ?? new JsonObject();

app.MapGet("/admin/api/state", () =>
{
    var snapshot = File.ReadAllBytes(configPath);
    var proxy = ParseConfigSnapshot(snapshot)["ReverseProxy"] as JsonObject ?? new JsonObject();
    var disabled = (proxy["AdminDisabledDestinations"] as JsonObject)?.DeepClone() as JsonObject ?? new JsonObject();
    proxy.Remove("AdminDisabledDestinations");
    return Results.Ok(new { name = "YARP Control Center", gateway = "online", time = DateTimeOffset.UtcNow,
        routes = proxy["Routes"] ?? new JsonObject(), clusters = proxy["Clusters"] ?? new JsonObject(), disabled,
        monitorProfiles = proxy[MonitorProfileRegistry.StorageKey] ?? new JsonObject(),
        realServers = proxy[RealServerCatalog.StorageKey] ?? new JsonObject(),
        serviceGroups = proxy[ServiceGroupCatalog.StorageKey] ?? new JsonObject(),
        mode = "Authenticated local management", telemetry = "Local HTTP counters only; no backend or fleet metrics", revision = Convert.ToHexString(SHA256.HashData(snapshot)) });
}).RequireAuthorization();

app.MapGet("/admin/api/virtual-servers", () => Results.Ok(new {
    isolated = isolatedListeners is not null,
    services = (isolatedListeners?.VirtualServices ?? Array.Empty<GatewayListenerIsolation.VirtualSocket>())
        .Select(service=>new { service.Id,service.Ip,service.Port,service.Protocol,
            service.RequireLocalAddressPresence, distributedOwnershipRequired=service.VipQuorumConfigPath is not null }),
    unifiedPlan = isolatedListeners?.UnifiedPlan?.Entries,
    unifiedPlanScope = "Host-provisioned configuration only; L4 runtime readiness and OS ownership not asserted",
    scope = "Locally provisioned data-plane sockets; operating-system VIP ownership is external"
})).RequireAuthorization();

app.MapGet("/admin/api/audit", async () =>
    Results.Ok(await localAudit.ReadRecentAsync())).RequireAuthorization();

app.MapGet("/admin/api/audit/delivery", () =>
{
    if (auditOutbox is null) return Results.Ok(new { enabled = false, pending = 0, storageFault = false, deliveryBlocked = false });
    var status = auditOutbox.Status();
    return Results.Ok(new { enabled = true, pending = status.Pending, storageFault = status.StorageFault,
        deliveryBlocked = status.DeliveryBlocked });
}).RequireAuthorization(p => p.RequireRole("Administrator"));

// Explicit, on-demand connectivity probes: these are not YARP's own destination health states.
app.MapPost("/admin/api/probe", async (IHttpClientFactory factory, HttpContext ctx) =>
{
    var results = new List<object>();
    var clusters = ReadProxy()["Clusters"] as JsonObject;
    foreach (var cluster in clusters ?? new JsonObject())
    {
        var c = cluster.Value as JsonObject;
        foreach (var dest in (c?["Destinations"] as JsonObject) ?? new JsonObject())
        {
            var addr = dest.Value?["Address"]?.ToString() ?? "";
            var path = c?["HealthCheck"]?["Active"]?["Path"]?.ToString() ?? "/health/ready";
            ctx.RequestAborted.ThrowIfCancellationRequested();
            if (c is not null && !CompoundProbeSettings.TryRead(c, out _))
            {
                results.Add(new { cluster = cluster.Key, destination = dest.Key, address = addr, status = "invalid-compound-config", httpStatus = (int?)null });
                continue;
            }
            if (c is not null && CompoundProbeSettings.TryRead(c, out var compound) && compound is not null)
            {
                if (!Uri.TryCreate(addr, UriKind.Absolute, out var origin) || !CompoundProbeSettings.TryTarget(origin, path, out _))
                {
                    results.Add(new { cluster = cluster.Key, destination = dest.Key, address = addr, status = "invalid-compound-config", httpStatus = (int?)null });
                    continue;
                }
                using var diagnosticClient = factory.CreateClient("probe");
                var result = await CompoundDiagnostics.EvaluateAsync(diagnosticClient, origin, path, compound, ctx.RequestAborted);
                results.Add(new { cluster = cluster.Key, destination = dest.Key, address = addr,
                    status = result.Passed ? "reachable" : "unreachable", httpStatus = result.Checks[1].HttpStatus,
                    compoundMode = compound.Mode, checks = result.Checks });
                continue;
            }
            var status = "unreachable"; int? code = null;
            try
            {
                if (Uri.TryCreate(addr, UriKind.Absolute, out var baseUri) && (baseUri.Scheme == "https" || baseUri.Scheme == "http"))
                {
                    using var client = factory.CreateClient("probe");
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
                    cts.CancelAfter(TimeSpan.FromSeconds(3));
                    var target = new Uri(baseUri, path.TrimStart('/'));
                    using var response = await client.GetAsync(target, cts.Token);
                    code = (int)response.StatusCode;
                    status = response.IsSuccessStatusCode ? "reachable" : "http-error";
                }
            }
            catch (OperationCanceledException) when (ctx.RequestAborted.IsCancellationRequested) { throw; }
            catch { }
            results.Add(new { cluster = cluster.Key, destination = dest.Key, address = addr, status, httpStatus = code });
        }
    }
    ctx.RequestAborted.ThrowIfCancellationRequested();
    return Results.Ok(new { checkedAt = DateTimeOffset.UtcNow, type = "On-demand HTTP/compound diagnostics (not YARP health state)", results });
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));

// Whole-proxy changes make route/cluster edits atomic and allow an editable UI without remote command execution.
// A saved draft MUST be reviewed by a second named administrator. No direct /apply endpoint.
var changeFolder = Path.Combine(privateDir, "change-requests");
Directory.CreateDirectory(changeFolder);
var changeGate = new SemaphoreSlim(1, 1);
IResult? ValidateChangePayload(JsonObject submitted)
{
    var routes = submitted["routes"] as JsonObject;
    var clusters = submitted["clusters"] as JsonObject;
    var disabled = submitted["disabled"] as JsonObject ?? new JsonObject();
    if (routes is null || clusters is null) return Results.BadRequest(new { error = "Routes and clusters must be objects" });
    if (routes.Count > 100 || clusters.Count > 100) return Results.BadRequest(new { error = "Too many routes/clusters" });
    if (RealServerCatalog.Validate(submitted) is { } serverError)
        return Results.BadRequest(new { error = serverError });
    if (MonitorProfileRegistry.Validate(submitted) is { } profileError)
        return Results.BadRequest(new { error = profileError });
    var currentCatalog = ReadProxy();
    if (ServiceGroupCatalog.Validate(submitted, currentCatalog) is { } serviceGroupError)
        return Results.BadRequest(new { error = serviceGroupError });
    if (ServiceGroupCatalog.ValidateLinked(clusters, disabled, submitted, currentCatalog) is { } linkedError)
        return Results.BadRequest(new { error = linkedError });
    if (SecureAffinityContract.Validate(clusters) is { } affinityError)
        return Results.BadRequest(new { error = affinityError });
    if (SharedMonitorContract.Validate(clusters) is { } monitorError)
        return Results.BadRequest(new { error = monitorError });
    foreach (var (key, clusterNode) in clusters)
    {
        if (!ValidId(key) || clusterNode is not JsonObject c) return Results.BadRequest(new { error = "Invalid cluster ID" });
        if (!ActiveCompoundSettings.ValidateDraft(c))
            return Results.BadRequest(new { error = $"Cluster {key}: invalid active compound health configuration" });
        if (!CompoundProbeSettings.TryRead(c, out _))
            return Results.BadRequest(new { error = $"Cluster {key}: invalid compound diagnostic mode or readiness path" });
        // Refuse proxy settings that bypass trust checks or produce unexpected insecure forwarding.
        if (string.Equals(c["HttpClient"]?["DangerousAcceptAnyServerCertificate"]?.ToString(), "true", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new { error = "Backend TLS certificate validation cannot be disabled" });
        if (c["HttpClient"]?["MaxConnectionsPerServer"] is JsonNode maxConnections &&
            (!int.TryParse(maxConnections.ToString(), out var maxConn) || maxConn < 1 || maxConn > 50000))
            return Results.BadRequest(new { error = "MaxConnectionsPerServer must be 1..50000" });
        if (string.Equals(c["SessionAffinity"]?["Enabled"]?.ToString(), "true", StringComparison.OrdinalIgnoreCase))
        {
            var affinityPolicy = c["SessionAffinity"]?["Policy"]?.ToString() ?? "HashCookie";
            if (affinityPolicy is not ("HashCookie" or "Cookie" or "ArrCookie" or "CustomHeader" or ExpiringCookieAffinityPolicy.PolicyName))
                return Results.BadRequest(new { error = "Unsupported session-affinity policy" });
        }
        if (c["HttpRequest"]?["Version"] is JsonNode version && version.ToString() is not ("1.0" or "1.1" or "2" or "3"))
            return Results.BadRequest(new { error = "Unsupported outbound HTTP version" });
        var policy = c["LoadBalancingPolicy"]?.ToString() ?? "RoundRobin";
        if (policy is not ("RoundRobin" or "PowerOfTwoChoices" or "LeastRequests" or "Random" or "FirstAlphabetical" or "WeightedRandom" or "WeightedLeastRequests" or "WeightedRoundRobin" or "FastestResponse" or "SourceIpHash" or "PrimaryBackup")) return Results.BadRequest(new { error = "Unsupported load-balancing policy" });
        if (policy == "PrimaryBackup" && c["HealthCheck"]?["Active"]?["Enabled"]?.ToString()?.ToLowerInvariant() != "true")
            return Results.BadRequest(new { error = $"Cluster {key}: PrimaryBackup requires enabled active health checks for safe fallback" });
        if (c["Destinations"] is not JsonObject dests || dests.Count > 40) return Results.BadRequest(new { error = "Invalid destinations" });
        foreach (var (destId, node) in dests)
        {
            if (!ValidId(destId) || !ValidAddress(node?["Address"]?.ToString()))
                return Results.BadRequest(new { error = $"Invalid destination {destId} in {key}" });
            if (node?["Metadata"]?["Weight"] is JsonNode weightValue &&
                !LoadBalancingCore.TryWeight(weightValue.ToString(), out _))
                return Results.BadRequest(new { error = $"Destination {destId} Weight must be integer 1..100" });
            var role = node?["Metadata"]?["TrafficRole"]?.ToString();
            if (!PrimaryBackupCore.TryBackupRole(role, out _))
                return Results.BadRequest(new { error = $"Destination {destId} TrafficRole must be primary or backup" });
            var trafficState = node?["Metadata"]?["TrafficState"]?.ToString() ?? "active";
            if (trafficState is not ("active" or "draining"))
                return Results.BadRequest(new { error = $"Destination {destId} TrafficState must be active or draining" });
            if (node?["Metadata"]?["SlowStartSeconds"] is JsonNode secondsNode &&
                !LoadBalancingCore.TrySlowStartSeconds(secondsNode.ToString(), out _))
                return Results.BadRequest(new { error = $"Destination {destId} SlowStartSeconds must be 0..600" });
            if (!DestinationAdmissionPolicy.TryParse(node?["Metadata"] as JsonObject,
                    out _, out var admissionError))
                return Results.BadRequest(new { error = $"Destination {destId}: {admissionError}" });
        }
        if (c["Metadata"]?[BackendMutualTls.MetadataKey] is JsonNode clientCertificate)
        {
            if (!BackendMutualTls.TryNormalizeThumbprint(clientCertificate.ToString(), out _))
                return Results.BadRequest(new { error = $"Cluster {key}: client certificate thumbprint must be 40 hex characters" });
            if (dests.Any(d => !(d.Value?["Address"]?.ToString() ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                return Results.BadRequest(new { error = $"Cluster {key}: backend mTLS requires all HTTPS destinations" });
        }
        if (string.Equals(c["HealthCheck"]?["Active"]?["Policy"]?.ToString(), "RiseFall", StringComparison.Ordinal))
        {
            foreach (var setting in new[] { "RiseFall.Rise", "RiseFall.Fall" })
                if (c["Metadata"]?[setting] is JsonNode value &&
                    (!int.TryParse(value.ToString(), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out var threshold) || threshold is < 1 or > 10))
                    return Results.BadRequest(new { error = $"Cluster {key}: {setting} must be 1..10" });
        }
        var hc = c["HealthCheck"]?["Active"];
        if (hc is not null && hc["Path"] is not null && !ValidPath(hc["Path"]!.ToString())) return Results.BadRequest(new { error = "Invalid health-check path" });
    }
    foreach (var (id, routeNode) in routes)
    {
        if (!ValidId(id) || routeNode is not JsonObject r) return Results.BadRequest(new { error = "Invalid route ID" });
        if (!ApplicationAccessPolicy.Validate(r))
            return Results.BadRequest(new { error = $"Invalid application access policy on route {id}" });
        if (r["Metadata"] is JsonObject routeMetadata && routeMetadata.ContainsKey(VirtualServiceBinding.Key) &&
            (routeMetadata[VirtualServiceBinding.Key] is not JsonValue binding || !binding.TryGetValue<string>(out var socketId) ||
             !VirtualServiceBinding.ValidId(socketId) || isolatedListeners?.HasVirtualService(socketId!) != true))
            return Results.BadRequest(new { error = $"Route {id} references a virtual service not provisioned on this gateway" });
        if (r["Transforms"] is JsonArray transformList && transformList.Count > 20)
            return Results.BadRequest(new { error = "Too many route transforms" });
        if (r["Match"]?["Methods"] is JsonArray methods && methods.Count > 12)
            return Results.BadRequest(new { error = "Too many HTTP method matches" });
        var clusterId = r["ClusterId"]?.ToString() ?? "";
        if (!clusters.ContainsKey(clusterId)) return Results.BadRequest(new { error = $"Route {id} references nonexistent cluster" });
        var path = r["Match"]?["Path"]?.ToString() ?? "";
        if (!ValidPath(path)) return Results.BadRequest(new { error = $"Invalid path in route {id}" });
        if (r["Match"]?["Hosts"] is JsonArray hosts && hosts.Any(h => string.IsNullOrWhiteSpace(h?.ToString()) || h!.ToString().Length > 255))
            return Results.BadRequest(new { error = "Invalid host match" });
    }
    foreach (var (id, value) in disabled)
    {
        var pieces = id.Split("::");
        if (pieces.Length != 2 || !ValidId(pieces[0]) || !ValidId(pieces[1]) || !ValidAddress(value?["Address"]?.ToString()) || !clusters.ContainsKey(pieces[0]))
            return Results.BadRequest(new { error = "Invalid disabled destination" });
    }
    return null;
}

IResult? ValidateChangeSafely(JsonObject submitted)
{
    try { return ValidateChangePayload(submitted); }
    catch (Exception ex) when (ex is InvalidOperationException or ArgumentException)
    {
        return Results.BadRequest(new { error = "Invalid configuration field type" });
    }
}

// Caller holds the routing writer gate. Never hold loginGate across
// external collector I/O. Serialize the final authorization and write with
// local account mutations, and recheck the shared authority after waiting.
async Task<(IResult? Denied, string? Backup)> CommitRoutingBytes(HttpContext ctx,
    byte[] before, byte[] proposed, string operation)
{
    var denied = await ConfirmStateMutation(ctx, configPath, before, proposed, operation, true);
    if (denied is not null) return (denied, null);
    try { await loginGate.WaitAsync(ctx.RequestAborted); }
    catch (OperationCanceledException)
    { return (Results.Json(new { error = "Routing mutation cancelled; configuration unchanged" }, statusCode: 503), null); }
    try
    {
        if (!await AuditActorCurrent(ctx, true)) return (Results.StatusCode(403), null);
        if (ctx.RequestAborted.IsCancellationRequested)
            return (Results.Json(new { error = "Routing mutation cancelled; configuration unchanged" }, statusCode: 503), null);
        if (!File.ReadAllBytes(configPath).AsSpan().SequenceEqual(before))
            return (Results.Conflict(new { error = "Configuration changed during final authorization" }), null);
        Directory.CreateDirectory(backupFolder);
        var backup = Path.Combine(backupFolder, $"appsettings-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffff}Z.json");
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        using (var stream = new FileStream(backup, options))
        {
            stream.Write(before);
            stream.Flush(flushToDisk: true);
        }
        // No await between final local account fence and configuration publication.
        WriteAuditedState(configPath, proposed);
        return (null, backup);
    }
    finally { loginGate.Release(); }
}

async Task<IResult> CommitReviewedChange(HttpContext ctx, JsonObject submitted)
{
    var invalid = ValidateChangeSafely(submitted);
    if (invalid is not null) return invalid;
    var routes = (JsonObject)submitted["routes"]!;
    var clusters = (JsonObject)submitted["clusters"]!;
    var disabled = submitted["disabled"] as JsonObject ?? new JsonObject();
    var expectedRevision = submitted["revision"]?.ToString() ?? "";
    await gate.WaitAsync();
    try
    {
        var snapshot = File.ReadAllBytes(configPath);
        var currentRevision = Convert.ToHexString(SHA256.HashData(snapshot));
        if (!string.Equals(expectedRevision, currentRevision, StringComparison.Ordinal))
            return Results.Conflict(new { error = "Configuration changed since loading. Refresh before saving." });
        var doc = ParseConfigSnapshot(snapshot);
        var proxy = (doc["ReverseProxy"] as JsonObject) ?? new JsonObject();
        proxy["Routes"] = routes.DeepClone();
        proxy["Clusters"] = clusters.DeepClone();
        proxy["AdminDisabledDestinations"] = disabled.DeepClone();
        if (submitted[MonitorProfileRegistry.PayloadKey] is JsonObject profiles)
            proxy[MonitorProfileRegistry.StorageKey] = profiles.DeepClone();
        if (submitted[RealServerCatalog.PayloadKey] is JsonObject realServers)
            proxy[RealServerCatalog.StorageKey] = realServers.DeepClone();
        if (submitted[ServiceGroupCatalog.PayloadKey] is JsonObject serviceGroups)
            proxy[ServiceGroupCatalog.StorageKey] = serviceGroups.DeepClone();
        doc["ReverseProxy"] = proxy;
        var newConfig = doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        var (denied, backup) = await CommitRoutingBytes(ctx, snapshot, Encoding.UTF8.GetBytes(newConfig), "CONFIG_APPLY_INTENT");
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "CONFIG_APPLIED", new { routes = routes.Count, clusters = clusters.Count, monitorProfiles = (proxy[MonitorProfileRegistry.StorageKey] as JsonObject)?.Count ?? 0, backup = Path.GetFileName(backup) });
        return Results.Ok(new { saved = true, backup = Path.GetFileName(backup), message = "Saved to appsettings.json; YARP config reload typically occurs automatically. Verify gateway logs." });
    }
    catch (Exception) { return Results.Problem("Configuration write failed. Check server logs."); }
    finally { gate.Release(); }
}

// Read-only GitOps planning. Reuse the exact approval-time business
// validator; no backup, file write, draft, audit mutation or auto-approval.
app.MapPost("/admin/api/gitops/plan", async (HttpContext ctx) =>
{
    const int maxBytes = 524288;
    if (ctx.Request.ContentLength is > maxBytes)
        return Results.StatusCode(413);
    JsonObject? request;
    try
    {
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var read = await ctx.Request.Body.ReadAsync(buffer.AsMemory(), ctx.RequestAborted);
            if (read == 0) break;
            if (body.Length + read > maxBytes) return Results.StatusCode(413);
            body.Write(buffer, 0, read);
        }
        body.Position = 0;
        request = await JsonSerializer.DeserializeAsync<JsonObject>(body, jsonOptions, ctx.RequestAborted);
    }
    catch (JsonException) { return Results.BadRequest(new { error = "Invalid JSON" }); }
    if (request is null || request.Count != 2 ||
        request["schemaVersion"] is not JsonValue version ||
        !version.TryGetValue<int>(out var schemaVersion) || schemaVersion != 1 ||
        request["payload"] is not JsonObject payload ||
        payload.Count != 4 + (payload.ContainsKey(MonitorProfileRegistry.PayloadKey) ? 1 : 0) +
            (payload.ContainsKey(RealServerCatalog.PayloadKey) ? 1 : 0) +
            (payload.ContainsKey(ServiceGroupCatalog.PayloadKey) ? 1 : 0) ||
        payload["routes"] is not JsonObject routes ||
        payload["clusters"] is not JsonObject clusters ||
        payload["disabled"] is not JsonObject disabled ||
        payload["revision"] is not JsonValue revisionValue ||
        !revisionValue.TryGetValue<string>(out var revision) || revision is null ||
        revision.Length != 64 || revision.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
        return Results.BadRequest(new { error = "Expected schemaVersion 1 and routes, clusters, disabled, revision payload" });
    var invalid = ValidateChangeSafely(payload);
    if (invalid is not null) return invalid;
    await gate.WaitAsync(ctx.RequestAborted);
    try
    {
        var currentBytes = await File.ReadAllBytesAsync(configPath, ctx.RequestAborted);
        var currentRevision = Convert.ToHexString(SHA256.HashData(currentBytes));
        if (!string.Equals(revision, currentRevision, StringComparison.Ordinal))
            return Results.Conflict(new { error = "Configuration changed since loading. Refresh before planning." });
        var current = ParseConfigSnapshot(currentBytes)["ReverseProxy"] as JsonObject ?? new JsonObject();
        static object Diff(JsonObject? previous, JsonObject proposed)
        {
            previous ??= new JsonObject();
            var added = proposed.Select(x => x.Key).Where(k => !previous.ContainsKey(k)).Order(StringComparer.Ordinal).ToArray();
            var removed = previous.Select(x => x.Key).Where(k => !proposed.ContainsKey(k)).Order(StringComparer.Ordinal).ToArray();
            var updated = proposed.Select(x => x.Key).Where(k => previous.ContainsKey(k) &&
                !JsonNode.DeepEquals(previous[k], proposed[k])).Order(StringComparer.Ordinal).ToArray();
            return new { added, removed, updated, unchanged = proposed.Count - added.Length - updated.Length };
        }
        return Results.Ok(new { schemaVersion = 1, revision = currentRevision, dryRun = true,
            approvalRequired = true, validationScope = "Control Center change payload; not YARP runtime acceptance",
            routes = Diff(current["Routes"] as JsonObject, routes),
            clusters = Diff(current["Clusters"] as JsonObject, clusters),
            disabled = Diff(current["AdminDisabledDestinations"] as JsonObject, disabled),
            monitorProfiles = Diff(current[MonitorProfileRegistry.StorageKey] as JsonObject,
                payload[MonitorProfileRegistry.PayloadKey] as JsonObject ?? current[MonitorProfileRegistry.StorageKey] as JsonObject ?? new JsonObject()),
            realServers = Diff(current[RealServerCatalog.StorageKey] as JsonObject,
                payload[RealServerCatalog.PayloadKey] as JsonObject ?? current[RealServerCatalog.StorageKey] as JsonObject ?? new JsonObject()),
            serviceGroups = Diff(current[ServiceGroupCatalog.StorageKey] as JsonObject,
                payload[ServiceGroupCatalog.PayloadKey] as JsonObject ?? current[ServiceGroupCatalog.StorageKey] as JsonObject ?? new JsonObject()) });
    }
    finally { gate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));

app.MapGet("/admin/api/change-requests", () =>
{
    var requests = Directory.GetFiles(changeFolder, "change-*.json")
        .OrderByDescending(Path.GetFileName).Take(100)
        .Select(path => JsonNode.Parse(File.ReadAllText(path))?.AsObject())
        .Where(x => x is not null)
        .Select(x => new { id = x!["id"]?.ToString(), requestedBy = x["requestedBy"]?.ToString(),
            createdUtc = x["createdUtc"]?.ToString(), status = x["status"]?.ToString(),
            reviewedBy = x["reviewedBy"]?.ToString(), reviewUtc = x["reviewUtc"]?.ToString(),
            changeReason = x["changeReason"]?.ToString(),
            routeCount = (x["payload"]?["routes"] as JsonObject)?.Count ?? 0,
            clusterCount = (x["payload"]?["clusters"] as JsonObject)?.Count ?? 0 })
        .ToArray();
    return Results.Ok(requests);
}).RequireAuthorization();

app.MapGet("/admin/api/change-requests/{id}", (string id) =>
{
    if (!Regex.IsMatch(id, "^change-[0-9]{8}T[0-9]{13,}Z-[A-F0-9]{10}$")) return Results.BadRequest(new { error = "Invalid request ID" });
    var path = Path.Combine(changeFolder, id + ".json");
    return File.Exists(path) ? Results.Text(File.ReadAllText(path), "application/json") : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/admin/api/change-requests", async (HttpContext ctx) =>
{
    if (ctx.Request.ContentLength is > 524288) return Results.BadRequest(new { error = "Request too large" });
    JsonObject? request;
    try { request = await JsonSerializer.DeserializeAsync<JsonObject>(ctx.Request.Body, jsonOptions); }
    catch { return Results.BadRequest(new { error = "Invalid JSON" }); }
    if (request is null || request["payload"] is not JsonObject payload ||
        payload["routes"] is not JsonObject || payload["clusters"] is not JsonObject ||
        payload["revision"] is null) return Results.BadRequest(new { error = "Invalid configuration draft" });
    var reason = request["reason"]?.ToString() ?? "";
    if (reason.Length < 12 || reason.Length > 500) return Results.BadRequest(new { error = "Change justification must contain 12–500 characters" });
    var id = "change-" + DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffffffZ") + "-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(5));
    var item = new JsonObject {
        ["id"] = id, ["requestedBy"] = Actor(ctx), ["createdUtc"] = DateTimeOffset.UtcNow.ToString("O"),
        ["status"] = "Pending", ["changeReason"] = reason, ["payload"] = payload.DeepClone()
    };
    await changeGate.WaitAsync(ctx.RequestAborted);
    try
    {
        var path = Path.Combine(changeFolder, id + ".json");
        if (File.Exists(path)) return Results.Conflict(new { error = "Change request ID already exists" });
        var proposed = Encoding.UTF8.GetBytes(item.ToJsonString());
        var denied = await ConfirmStateMutation(ctx, path, Array.Empty<byte>(), proposed, "CHANGE_REQUEST_INTENT", false);
        if (denied is not null) return denied;
        WriteAuditedState(path, proposed);
    }
    finally { changeGate.Release(); }
    await Audit(Actor(ctx), "CHANGE_REQUESTED", new { id, reason });
    return Results.Ok(new { id, status = "Pending", message = "A different administrator must review and approve" });
}).RequireAuthorization(p => p.RequireRole("Administrator", "Operator"));

app.MapPost("/admin/api/change-requests/{id}/decision", async (HttpContext ctx, string id, ChangeDecision input) =>
{
    if (!Regex.IsMatch(id, "^change-[0-9]{8}T[0-9]{13,}Z-[A-F0-9]{10}$")) return Results.BadRequest(new { error = "Invalid request ID" });
    if (input.Decision is not ("approve" or "reject")) return Results.BadRequest(new { error = "Decision must be approve or reject" });
    var reason = input.Reason?.Trim() ?? "";
    if (reason.Length < 10 || reason.Length > 500) return Results.BadRequest(new { error = "Review note must contain 10–500 characters" });
    await changeGate.WaitAsync();
    try
    {
        var path = Path.Combine(changeFolder, id + ".json");
        if (!File.Exists(path)) return Results.NotFound();
        var before = File.ReadAllBytes(path);
        var item = JsonNode.Parse(before)!.AsObject();
        if (item["status"]?.ToString() != "Pending") return Results.Conflict(new { error = "Already reviewed" });
        if (string.Equals(item["requestedBy"]?.ToString(), Actor(ctx), StringComparison.OrdinalIgnoreCase))
            return Results.Json(new { error = "Two-person control: requester cannot approve or reject own change" }, statusCode: 403);
        if (input.Decision == "approve")
        {
            if (item["payload"] is not JsonObject config) return Results.BadRequest(new { error = "Missing saved payload" });
            // CommitReviewedChange validates IDs, paths, destinations and revision at approval time.
            var result = await CommitReviewedChange(ctx, config);
            if (result is not IStatusCodeHttpResult { StatusCode: 200 }) return result;
        }
        item["status"] = input.Decision == "approve" ? "Approved" : "Rejected";
        item["reviewedBy"] = Actor(ctx); item["reviewUtc"] = DateTimeOffset.UtcNow.ToString("O");
        item["reviewReason"] = reason;
        var proposed = Encoding.UTF8.GetBytes(item.ToJsonString());
        if (input.Decision == "reject")
        {
            var denied = await ConfirmStateMutation(ctx, path, before, proposed, "CHANGE_REJECT_INTENT", true);
            if (denied is not null) return denied;
        }
        WriteAuditedState(path, proposed);
        await Audit(Actor(ctx), "CHANGE_" + item["status"]!.ToString().ToUpperInvariant(), new { id, reason });
        return Results.Ok(new { id, status = item["status"]?.ToString() });
    }
    finally { changeGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/backups", () =>
{
    var folder = backupFolder;
    var names = Directory.Exists(folder) ? Directory.GetFiles(folder, "appsettings-*.json").Select(Path.GetFileName).OrderDescending().Take(30) : Enumerable.Empty<string?>();
    return Results.Ok(names);
}).RequireAuthorization();

app.MapPost("/admin/api/restore/{name}", async (HttpContext ctx, string name) =>
{
    if (!Regex.IsMatch(name, "^appsettings-[0-9]{8}T[0-9]{7,}Z\\.json$")) return Results.BadRequest(new { error = "Invalid backup name" });
    var path = Path.Combine(backupFolder, name);
    if (!File.Exists(path)) return Results.NotFound();
    await gate.WaitAsync();
    try
    {
        var json = await File.ReadAllTextAsync(path);
        if (JsonNode.Parse(json)?["ReverseProxy"] is null) return Results.BadRequest(new { error = "Backup lacks ReverseProxy configuration" });
        var restoreSnapshot = File.ReadAllBytes(configPath);
        var (denied, safety) = await CommitRoutingBytes(ctx, restoreSnapshot, Encoding.UTF8.GetBytes(json), "CONFIG_RESTORE_INTENT");
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "CONFIG_RESTORED", new { restored = name, preRestore = Path.GetFileName(safety) });
        return Results.Ok(new { restored = true });
    }
    finally { gate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));


// Gateway fleet inventory and READ-ONLY mTLS observation. Cross-node writes are deliberately
// not enabled: an approved distributed-transaction/rollback protocol is required first.
var fleetPath = Path.Combine(privateDir, "fleet-gateways.json");
var fleetGate = new SemaphoreSlim(1, 1);
var rolloutGate = new SemaphoreSlim(1, 1);
var rolloutFolder = Path.Combine(privateDir, "fleet-rollouts");
Directory.CreateDirectory(rolloutFolder);
List<FleetGateway> ReadFleet() => File.Exists(fleetPath)
    ? JsonSerializer.Deserialize<List<FleetGateway>>(File.ReadAllText(fleetPath), jsonOptions) ?? new()
    : new();
app.MapGet("/admin/api/fleet", () => Results.Ok(ReadFleet())).RequireAuthorization();
app.MapPost("/admin/api/fleet", async (HttpContext ctx, FleetGateway row) =>
{
    if (!ctx.User.IsInRole("Administrator")) return Results.Forbid();
    if (string.IsNullOrWhiteSpace(row.Id) || !ValidId(row.Id) || row.Id.Length > 40 || !Uri.TryCreate(row.Url, UriKind.Absolute, out var uri) ||
        uri.Scheme != "https" || !string.IsNullOrEmpty(uri.UserInfo) || uri.AbsolutePath != "/" ||
        uri.Query.Length != 0 || uri.Fragment.Length != 0 || !Regex.IsMatch(row.ClientCertificateThumbprint, "^[a-fA-F0-9]{40,64}$"))
        return Results.BadRequest(new { error = "Gateway requires an ID, HTTPS origin URL and valid client certificate thumbprint" });
    await fleetGate.WaitAsync();
    try
    {
        if (FleetRolloutJournal.HasUnresolved(rolloutFolder))
            return Results.Conflict(new { error = "Resolve the unfinished rollout before changing fleet membership." });
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(fleetPath);
        var list = ReadFleet();
        if (list.Any(x => x.Id.Equals(row.Id, StringComparison.OrdinalIgnoreCase))) return Results.Conflict(new { error = "Duplicate gateway ID" });
#if GATEWAYCORE_COMMERCIAL
        if (!commercialLicense.AllowsFleetCount(list.Count + 1))
            return Results.Json(new { error = "Licensed managed-gateway count exceeded or HA/fleet feature unavailable.", code = "license_node_limit" }, statusCode: 402);
#endif
        list.Add(row);
        var proposed = JsonSerializer.SerializeToUtf8Bytes(list);
        var denied = await ConfirmAndWriteResourceMutation(ctx, fleetPath, before, proposed, "FLEET_REGISTER_INTENT", true);
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "FLEET_GATEWAY_REGISTERED", new { row.Id, row.Url });
        return Results.Ok(new { registered = true });
    }
    finally { fleetGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapDelete("/admin/api/fleet/{id}", async (HttpContext ctx, string id) =>
{
    if (string.IsNullOrWhiteSpace(id) || !ValidId(id)) return Results.BadRequest();
    await fleetGate.WaitAsync();
    try
    {
        if (FleetRolloutJournal.HasUnresolved(rolloutFolder))
            return Results.Conflict(new { error = "Resolve the unfinished rollout before changing fleet membership." });
        var before = externalAuditIntent is null && oidcPolicy is null ? Array.Empty<byte>() : AuditStateBytes(fleetPath);
        var list = ReadFleet();
        if (list.RemoveAll(x => x.Id == id) != 1) return Results.NotFound();
        var proposed = JsonSerializer.SerializeToUtf8Bytes(list);
        var denied = await ConfirmAndWriteResourceMutation(ctx, fleetPath, before, proposed, "FLEET_UNREGISTER_INTENT", true);
        if (denied is not null) return denied;
        await Audit(Actor(ctx), "FLEET_GATEWAY_UNREGISTERED", new { id });
        return Results.Ok(new { removed = id });
    }
    finally { fleetGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapGet("/admin/api/fleet/status", async () =>
{
    var responses = new List<object>();
    foreach (var row in ReadFleet().Take(20))
    {
        try
        {
            using var store = new System.Security.Cryptography.X509Certificates.X509Store(
                System.Security.Cryptography.X509Certificates.StoreName.My,
                OperatingSystem.IsWindows()
                    ? System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
                    : System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
            store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
            var matches = store.Certificates.Find(
                System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
                row.ClientCertificateThumbprint, validOnly: true);
            if (matches.Count != 1 || !matches[0].HasPrivateKey)
            { responses.Add(new { row.Id, state = "client-certificate-missing" }); continue; }
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
            handler.ClientCertificates.Add(matches[0]);
            using var client = new HttpClient(handler)
            {
                Timeout = TimeSpan.FromSeconds(4),
                MaxResponseContentBufferSize = 64 * 1024
            };
            using var response = await client.GetAsync(new Uri(new Uri(row.Url), "agent/v1/status"));
            if (!response.IsSuccessStatusCode)
            { responses.Add(new { row.Id, state = "http-error", httpStatus = (int)response.StatusCode }); continue; }
            var report = JsonNode.Parse(await response.Content.ReadAsStringAsync());
            var engineConfigState = "disabled";
            var gslbRuntimeState = "not-staged";
            JsonNode? gslbRuntime = null;
            JsonNode? engines = null;
            if (report?["engineConfigStagingEnabled"] is JsonValue enabled &&
                enabled.TryGetValue<bool>(out var isEnabled) && isEnabled)
            {
                using var engineResponse = await client.GetAsync(
                    new Uri(new Uri(row.Url), "agent/v1/engines"));
                if (engineResponse.IsSuccessStatusCode)
                {
                    engines = JsonNode.Parse(await engineResponse.Content.ReadAsStringAsync());
                    engineConfigState = engines is JsonArray ? "available" : "invalid-response";
                }
                else engineConfigState = "http-error";
            }
            if (engines is JsonArray engineRows && engineRows.Any(engine =>
                    engine?["engineId"] is JsonValue id && id.TryGetValue<string>(out var engineId) &&
                    string.Equals(engineId, "gslb", StringComparison.Ordinal)))
            {
                using var runtimeResponse = await client.GetAsync(
                    new Uri(new Uri(row.Url), "agent/v1/engines/gslb/runtime-status"));
                if (runtimeResponse.IsSuccessStatusCode)
                {
                    gslbRuntime = JsonNode.Parse(await runtimeResponse.Content.ReadAsStringAsync());
                    var validType = gslbRuntime?["type"] is JsonValue type &&
                        type.TryGetValue<string>(out var typeName) &&
                        typeName == "loopback-gslb-runtime-metrics";
                    gslbRuntimeState = validType ? "available" : "invalid-response";
                }
                else gslbRuntimeState = runtimeResponse.StatusCode == System.Net.HttpStatusCode.NotFound
                    ? "disabled" : "unavailable";
            }
            responses.Add(new { row.Id, state = "connected", report, engineConfigState, engines,
                gslbRuntimeState, gslbRuntime });
        }
        catch (Exception ex)
        { responses.Add(new { row.Id, state = "unavailable", errorType = ex.GetType().Name }); }
    }
    return Results.Ok(new { checkedUtc = DateTimeOffset.UtcNow,
        type = "mTLS agent and signed engine-configuration status; not live DNS or YARP destination health",
        gateways = responses });
}).RequireAuthorization();

// Per-destination request observations are recorded after YARP chooses its target.
// Counters are process-local, not durable, and health is reported separately.

// Controlled fleet rollout: the only accepted payload comes from a previously
// approved two-person local change request. Every agent validates its revision.
// No general-purpose remote shell or arbitrary filesystem access is exposed.
string FleetDigest() => Convert.ToHexString(SHA256.HashData(AuditStateBytes(fleetPath)));
#if GATEWAYCORE_COMMERCIAL
async Task CompleteQuorum(string logPath,JsonObject journal,string outcome)
{
    if(fleetQuorum is null || journal["quorumScope"]?.ToString()!=fleetQuorum.Scope)
        throw new InvalidOperationException("Original quorum scope unavailable.");
    var targets=FleetRolloutJournal.Targets(journal);
    if(outcome=="activated" && !targets.All(x=>x["activationConfirmed"]?.GetValue<bool>()==true) ||
       outcome=="rolled-back" && targets.Any(FleetRolloutJournal.NeedsRollback) ||
       outcome is not ("activated" or "rolled-back"))
        throw new InvalidOperationException("Unverified fleet completion cannot release quorum.");
    if(journal["quorumOutcome"] is not null && journal["quorumOutcome"]!.ToString()!=outcome)
        throw new InvalidOperationException("Cannot change durable quorum completion intent.");
    journal["quorumOutcome"]=outcome;
    FleetRolloutJournal.Log(logPath,journal,"fleet","quorum-completion-intent",outcome);
    await fleetQuorum.Release(journal["id"]!.GetValue<string>(),journal["sequence"]!.GetValue<long>(),outcome);
}
#endif
async Task<List<string>> RollbackAttempted(string logPath, JsonObject journal, List<FleetGateway> gateways)
{
#if GATEWAYCORE_COMMERCIAL
    try
    {
        // Recovery after an ambiguous completion must not re-enter the
        // mutation path. Exact receipt/intent matching is idempotent.
        if(journal["quorumOutcome"]?.ToString() is { } outcome)
        {
            await CompleteQuorum(logPath,journal,outcome);
            journal["status"]=outcome=="activated"?"activated-pending-health-validation":"rollback-verified";
            FleetRolloutJournal.Log(logPath,journal,"fleet","quorum-completion-recovered",outcome);
            return new List<string>();
        }
        if(fleetQuorum is null || journal["quorumScope"]?.ToString()!=fleetQuorum.Scope)
            throw new InvalidOperationException("Original quorum scope unavailable.");
        var tx=journal["id"]!.GetValue<string>();
        var epoch=journal["sequence"]?.GetValue<long>()??0;
        if(epoch==0)
        {
            if(FleetRolloutJournal.Targets(journal).Any(x=>x["prepareSent"]!.GetValue<bool>()))
                throw new InvalidOperationException("Missing epoch after dispatch; independent reconciliation required.");
            epoch=await fleetQuorum.RecoverOwnEpoch(tx);
            journal["sequence"]=epoch;
            FleetRolloutJournal.Log(logPath,journal,"fleet","quorum-acquisition-recovered","no-dispatch");
        }
        await fleetQuorum.Assert(tx,epoch);
    }
    catch(Exception ex)
    {
        journal["status"]="manual-intervention-required";
        FleetRolloutJournal.Log(logPath,journal,"fleet","quorum-recovery","blocked",ex.GetType().Name);
        return new List<string>{"quorum: original ownership or completion unavailable"};
    }
#endif
    return await FleetRolloutJournal.RollbackAttemptedAsync(logPath,journal,id=>
    {
        var row=gateways.Single(x=>x.Id==id);
        return (new Uri(row.Url),CreateFleetClient(row));
    }
#if GATEWAYCORE_COMMERCIAL
        ,()=>CompleteQuorum(logPath,journal,"rolled-back")
#endif
    );
}
app.MapPost("/admin/api/fleet/rollout/{changeId}", async (HttpContext ctx, string changeId) =>
{
    if (!Regex.IsMatch(changeId, "^change-[0-9]{8}T[0-9]{13,}Z-[A-F0-9]{10}$"))
        return Results.BadRequest(new { error = "Invalid change ID" });
    if (!await rolloutGate.WaitAsync(0)) return Results.Conflict(new { error = "Another rollout is running" });
    bool fleetHeld = false, persisted = false;
    JsonObject? journal = null;
    var gateways = new List<FleetGateway>();
    var txId = "rollout_" + Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
    var logPath = Path.Combine(rolloutFolder, txId + ".json");
    try
    {
        await fleetGate.WaitAsync(ctx.RequestAborted);
        fleetHeld = true;
        if (FleetRolloutJournal.HasUnresolved(rolloutFolder))
            return Results.Conflict(new { error = "An earlier rollout is unresolved. Recover it before starting another." });
        if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
        var changePath = Path.Combine(changeFolder, changeId + ".json");
        if (!File.Exists(changePath)) return Results.NotFound();
        var changeBytes = File.ReadAllBytes(changePath);
        var change = JsonNode.Parse(changeBytes)?.AsObject();
        if (change?["status"]?.ToString() != "Approved" || change["reviewedBy"] is null ||
            string.Equals(change["requestedBy"]?.ToString(), change["reviewedBy"]?.ToString(), StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new { error = "An independent administrator must have approved this change" });
        if (change["payload"] is not JsonObject payload || payload["routes"] is not JsonObject routes ||
            payload["clusters"] is not JsonObject clusters)
            return Results.BadRequest(new { error = "Approved change has no route and cluster payload" });
        gateways = ReadFleet();
        if (gateways.Count < 2 || gateways.Count > 20)
            return Results.Conflict(new { error = "Register at least two managed gateways; maximum 20" });
#if GATEWAYCORE_COMMERCIAL
        if (!commercialLicense.AllowsFleetCount(gateways.Count))
            return Results.Json(new { error = "Licensed managed-gateway count exceeded or HA/fleet feature unavailable.", code = "license_node_limit" }, statusCode: 402);
#endif
        var fleetDigest = FleetDigest();
        if (!FleetAdcContract.TryBuildApproved(payload, ReadProxy(), out var proxy, out var adcError))
            return Results.Conflict(new { error = adcError });
        var signingKeyPath = Path.Combine(privateDir, "fleet-signing-private.pem");
        if (!File.Exists(signingKeyPath))
            return Results.Conflict(new { error = "Fleet signing key not provisioned" });
        var signingKeyPem = await File.ReadAllTextAsync(signingKeyPath, ctx.RequestAborted);
        var targets = new JsonArray();
#if GATEWAYCORE_COMMERCIAL
        if(fleetQuorum is null || fleetQuorum.Scope!=commercialLicense.FleetScope())
            return Results.Conflict(new {error="Authenticated quorum configuration matching the signed deployment is required."});
        long nodeHighWater=0;
        long quorumEpoch=0;
        var licensedPeers=new Dictionary<string,VerifiedLicense>(StringComparer.Ordinal);
        async Task<VerifiedLicense> ReadPeer(FleetGateway row,HttpClient client)
        {
            var challenge=Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            using var response=await client.PostAsJsonAsync(new Uri(new Uri(row.Url),"agent/v1/license/proof"),
                new {challenge},ctx.RequestAborted);
            response.EnsureSuccessStatusCode();
            var proof=JsonNode.Parse(await response.Content.ReadAsStringAsync(ctx.RequestAborted))?["proof"]?.GetValue<string>()
                ?? throw new CryptographicException("Missing signed fleet allocation proof.");
            return commercialLicense.VerifyPeerProof(proof,challenge);
        }
        async Task RequireSameFleet()
        {
            // All targets, not only the next dispatch target, must remain
            // reachable and entitled. Fresh independent nonces on every
            // observation; concurrent calls bounded by each client's timeout.
            var observed=await Task.WhenAll(gateways.Select(async row =>
            {
                using var peerClient=CreateFleetClient(row);
                var peer=await ReadPeer(row,peerClient);
                if(peer.PayloadSha256!=licensedPeers[row.Id].PayloadSha256 ||
                   peer.InstallationKeySha256!=licensedPeers[row.Id].InstallationKeySha256)
                    throw new CryptographicException("Peer entitlement changed during rollout.");
                return peer;
            }));
            commercialLicense.ValidateFleetProofs(observed);
            await fleetQuorum.Assert(txId,quorumEpoch,ctx.RequestAborted);
        }
#endif
        // Preflight every target before authorizing or dispatching any mutation.
        foreach (var row in gateways)
        {
            using var client = CreateFleetClient(row);
#if GATEWAYCORE_COMMERCIAL
            licensedPeers.Add(row.Id,await ReadPeer(row,client));
#endif
            using var statusResponse = await client.GetAsync(new Uri(new Uri(row.Url), "agent/v1/status"), ctx.RequestAborted);
            statusResponse.EnsureSuccessStatusCode();
            var status = JsonNode.Parse(await statusResponse.Content.ReadAsStringAsync(ctx.RequestAborted));
            var revision = status?["revision"]?.ToString();
            if (!FleetRolloutJournal.IsDigest(revision) || status?["rollbackFenceProtocol"]?.GetValue<int>() != 1)
                throw new InvalidOperationException("Agent configuration revision unavailable");
#if GATEWAYCORE_COMMERCIAL
            if(status?["quorumFenceProtocol"]?.GetValue<int>()!=1 ||
                status["quorumScope"]?.ToString()!=fleetQuorum.Scope)
                throw new InvalidOperationException("Agent does not enforce the same quorum scope.");
            nodeHighWater=Math.Max(nodeHighWater,status["highestAcceptedSequence"]!.GetValue<long>());
#endif
            targets.Add(new JsonObject { ["id"] = row.Id, ["originalRevision"] = revision,
                ["prepareSent"] = false, ["activateSent"] = false, ["rollbackVerified"] = false });
        }
#if GATEWAYCORE_COMMERCIAL
        commercialLicense.ValidateFleetProofs(licensedPeers.Values.ToArray());
#endif
        journal = new JsonObject { ["schema"] = 2, ["id"] = txId, ["changeId"] = changeId,
            ["initiator"] = Actor(ctx), ["createdUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["status"] = "starting", ["fleetDigest"] = fleetDigest,
            ["changeDigest"] = Convert.ToHexString(SHA256.HashData(changeBytes)), ["targets"] = targets,
            ["details"] = new JsonArray() };
#if GATEWAYCORE_COMMERCIAL
        journal["quorumScope"]=fleetQuorum.Scope;
#endif
        var initial = JsonSerializer.SerializeToUtf8Bytes(journal);
        var denied = await ConfirmStateMutation(ctx, logPath, Array.Empty<byte>(), initial, "FLEET_ROLLOUT_INTENT", true);
        if (denied is not null) return denied;
        async Task<bool> CurrentPlan() => await AuditActorCurrent(ctx, true) && !ctx.RequestAborted.IsCancellationRequested &&
#if GATEWAYCORE_COMMERCIAL
            commercialLicense.AllowsFleetCount(gateways.Count) &&
#endif
            OnboardingApi.IsMultiGatewayDesign(privateDir) && FleetDigest() == fleetDigest &&
            File.Exists(changePath) && File.ReadAllBytes(changePath).AsSpan().SequenceEqual(changeBytes);
        if (!await CurrentPlan()) return Results.Conflict(new { error = "Rollout authorization or plan changed" });
        WriteAuditedState(logPath, initial);
        persisted = true;
#if GATEWAYCORE_COMMERCIAL
        // Persist intent first: if the CAS result is lost, never steal or
        // silently clear the lock. Reconciliation can inspect this transaction.
        var ownership=await fleetQuorum.Acquire(txId,nodeHighWater,ctx.RequestAborted);
        var sequence=quorumEpoch=ownership.Epoch;
#else
        var sequence = FleetSequenceState.AllocateNext(Path.Combine(privateDir, "fleet-sequence.txt"));
#endif
        journal["sequence"] = sequence;
        journal["status"] = "preparing";
        FleetRolloutJournal.Write(logPath, journal);
        foreach (var target in FleetRolloutJournal.Targets(journal))
        {
            if (!await CurrentPlan()) throw new InvalidOperationException("Rollout authorization or plan changed");
            var row = gateways.Single(x => x.Id == target["id"]!.GetValue<string>());
            var revision = target["originalRevision"]!.GetValue<string>();
            var signed = FleetConfigSignature.SignV2(signingKeyPem, txId, revision, proxy,
                DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds(), sequence);
            using var client = CreateFleetClient(row);
#if GATEWAYCORE_COMMERCIAL
            await RequireSameFleet();
            if(!await CurrentPlan())throw new InvalidOperationException("Rollout authorization or plan changed during fleet proof.");
#endif
            target["prepareSent"] = true;
            FleetRolloutJournal.Log(logPath, journal, row.Id, "prepare", "dispatching");
            using var response = await client.PostAsJsonAsync(new Uri(new Uri(row.Url), "agent/v1/config/prepare"),
                new { TransactionId = txId, ExpectedRevision = revision, ReverseProxy = proxy,
                    signed.ExpiresUnixSeconds, signed.Sequence, signed.KeyId, signed.Signature }, ctx.RequestAborted);
            response.EnsureSuccessStatusCode();
            var staged = JsonNode.Parse(await response.Content.ReadAsStringAsync(ctx.RequestAborted));
            var prepared = staged?["preparedRevision"]?.ToString();
            if (staged?["transactionId"]?.ToString() != txId || staged["originalRevision"]?.ToString() != revision ||
                !FleetRolloutJournal.IsDigest(prepared)) throw new InvalidOperationException("Invalid prepare acknowledgment");
            target["preparedRevision"] = prepared;
            FleetRolloutJournal.Log(logPath, journal, row.Id, "prepare", "ok", prepared);
        }
        journal["status"] = "activating";
        FleetRolloutJournal.Write(logPath, journal);
        foreach (var target in FleetRolloutJournal.Targets(journal))
        {
            if (!await CurrentPlan()) throw new InvalidOperationException("Rollout authorization or plan changed");
            var row = gateways.Single(x => x.Id == target["id"]!.GetValue<string>());
            var prepared = target["preparedRevision"]!.GetValue<string>();
            using var client = CreateFleetClient(row);
#if GATEWAYCORE_COMMERCIAL
            await RequireSameFleet();
            if(!await CurrentPlan())throw new InvalidOperationException("Rollout authorization or plan changed during fleet proof.");
#endif
            target["activateSent"] = true;
            FleetRolloutJournal.Log(logPath, journal, row.Id, "activate", "dispatching");
            using var response = await client.PostAsJsonAsync(new Uri(new Uri(row.Url), "agent/v1/config/activate"),
                new { TransactionId = txId, PreparedRevision = prepared }, ctx.RequestAborted);
            response.EnsureSuccessStatusCode();
            var activated = JsonNode.Parse(await response.Content.ReadAsStringAsync(ctx.RequestAborted));
            if (activated?["transactionId"]?.ToString() != txId || activated["revision"]?.ToString() != prepared)
                throw new InvalidOperationException("Invalid activation acknowledgment");
            target["activationConfirmed"]=true;
            FleetRolloutJournal.Log(logPath, journal, row.Id, "activate", "ok", prepared);
        }
#if GATEWAYCORE_COMMERCIAL
        await RequireSameFleet();
        if(!await CurrentPlan())throw new InvalidOperationException("Rollout authorization or plan changed before completion.");
#endif
#if GATEWAYCORE_COMMERCIAL
        // Release only after all activations are acknowledged and the audit
        // record is durable. If release is ambiguous, retain unresolved state.
        await Audit(Actor(ctx), "FLEET_ROLLOUT_ACTIVATED", new { txId, changeId });
        await CompleteQuorum(logPath,journal,"activated");
#endif
        journal["status"] = "activated-pending-health-validation";
        FleetRolloutJournal.Log(logPath, journal, "fleet", "finish", "activation-complete", "Live application health is not verified");
#if !GATEWAYCORE_COMMERCIAL
        await Audit(Actor(ctx), "FLEET_ROLLOUT_ACTIVATED", new { txId, changeId });
#endif
        return Results.Ok(journal);
    }
#if GATEWAYCORE_COMMERCIAL
    catch(FleetQuorumContentionException) when(persisted && journal is not null &&
        journal["sequence"] is null && !FleetRolloutJournal.Targets(journal).Any(x=>x["prepareSent"]!.GetValue<bool>()))
    {
        // Definite CAS refusal is not an ambiguous commit. This transaction
        // never held authority and sent no mutation, so it need not block
        // the local controller after the actual owner finishes.
        journal["status"]="rollback-verified";
        FleetRolloutJournal.Log(logPath,journal,"fleet","quorum-acquire","contended-no-dispatch");
        await Audit(Actor(ctx),"FLEET_QUORUM_CONTENDED",new {txId,changeId});
        return Results.Conflict(new {error="Another fleet transaction owns or completed the quorum fence."});
    }
#endif
    catch (Exception ex)
    {
        if (!persisted || journal is null)
            return Results.Json(new { error = "Rollout preflight failed", errorType = ex.GetType().Name }, statusCode: 502);
        // Compensation is covered by the authorized initial plan; never
        // suppress it because the original request or session was cancelled.
        journal["status"] = "recovering";
        FleetRolloutJournal.Log(logPath, journal, "fleet", "error", "failed", ex.GetType().Name);
        var rollbackErrors = await RollbackAttempted(logPath, journal, gateways);
        await Audit(Actor(ctx), "FLEET_ROLLOUT_FAILED", new { txId, changeId, rollbackErrors });
        return Results.Json(new { transactionId = txId, status = journal["status"]?.ToString(),
            error = "Deployment failed; inspect durable journal", rollbackErrors }, statusCode: 502);
    }
    finally { if (fleetHeld) fleetGate.Release(); rolloutGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/fleet/rollouts/{id}/recover", async (HttpContext ctx, string id) =>
{
    if (!FleetRolloutJournal.IsTransaction(id)) return Results.BadRequest();
    if (!await rolloutGate.WaitAsync(0)) return Results.Conflict(new { error = "Another rollout is running" });
    bool fleetHeld = false;
    try
    {
        await fleetGate.WaitAsync(ctx.RequestAborted);
        fleetHeld = true;
        var path = Path.Combine(rolloutFolder, id + ".json");
        if (!File.Exists(path)) return Results.NotFound();
        var before = File.ReadAllBytes(path);
        var journal = FleetRolloutJournal.Read(path);
        var gateways = ReadFleet();
        if (!FleetRolloutJournal.RecoveryAllowed(journal, id, FleetDigest()) ||
            !FleetRolloutJournal.Targets(journal).Select(x => x["id"]!.GetValue<string>())
                .SequenceEqual(gateways.Select(x => x.Id)))
            return Results.Conflict(new { error = "Recovery requires original inventory and a valid unfinished v2 journal" });
        journal["status"] = "recovering";
        var proposed = JsonSerializer.SerializeToUtf8Bytes(journal);
        var denied = await ConfirmStateMutation(ctx, path, before, proposed, "FLEET_RECOVERY_INTENT", true);
        if (denied is not null) return denied;
        if (!await AuditActorCurrent(ctx, true) || ctx.RequestAborted.IsCancellationRequested)
            return Results.StatusCode(403);
        WriteAuditedState(path, proposed);
        var errors = await RollbackAttempted(path, journal, gateways);
        await Audit(Actor(ctx), "FLEET_ROLLOUT_RECOVERY", new { id, errors });
        return errors.Count == 0 ? Results.Ok(journal) :
            Results.Json(new { transactionId = id, status = "manual-intervention-required", errors }, statusCode: 502);
    }
    finally { if (fleetHeld) fleetGate.Release(); rolloutGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapGet("/admin/api/fleet/rollouts", () => Results.Ok(
    Directory.GetFiles(rolloutFolder,"rollout_*.json").OrderByDescending(x=>x).Take(30)
        .Select(x=>JsonNode.Parse(File.ReadAllText(x))).ToArray())).RequireAuthorization();

HttpClient CreateFleetClient(FleetGateway row)
{
    using var store = new System.Security.Cryptography.X509Certificates.X509Store(
        System.Security.Cryptography.X509Certificates.StoreName.My,
        OperatingSystem.IsWindows()
                    ? System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine
                    : System.Security.Cryptography.X509Certificates.StoreLocation.CurrentUser);
    store.Open(System.Security.Cryptography.X509Certificates.OpenFlags.ReadOnly);
    var matches=store.Certificates.Find(System.Security.Cryptography.X509Certificates.X509FindType.FindByThumbprint,
        row.ClientCertificateThumbprint, validOnly:true);
    if(matches.Count != 1 || !matches[0].HasPrivateKey) throw new InvalidOperationException("Missing controller certificate for "+row.Id);
    var handler=new HttpClientHandler {AllowAutoRedirect=false,UseProxy=false};
    handler.ClientCertificates.Add(matches[0]);
    return new HttpClient(handler,disposeHandler:true) {Timeout=TimeSpan.FromSeconds(8), MaxResponseContentBufferSize=65536};
}

// Version 0.1 setup APIs and independently verified YARP runtime state.
app.MapSetupCenter(privateDir, Audit);
app.MapCapabilityRegistry();
app.MapOnboardingApi(privateDir,
    (ctx, path, before, proposed, operation, administratorOnly) =>
        ConfirmStateMutation(ctx, path, before, proposed, operation, administratorOnly),
    WriteAuditedState, Audit
#if GATEWAYCORE_COMMERCIAL
    , commercialLicense.AllowsTopology
#endif
    );
// Enforce onboarding state server-side; hiding navigation is never a security boundary.
app.Use(async (ctx, next) =>
{
    var path = ctx.Request.Path;
    var modifying = ctx.Request.Method is "POST" or "PUT" or "PATCH" or "DELETE";
    if (modifying && (path.StartsWithSegments("/admin/api/change-requests") ||
                      path.StartsWithSegments("/admin/api/restore")) &&
        !OnboardingApi.IsDesignConfirmed(privateDir))
    {
        ctx.Response.StatusCode = 409;
        await ctx.Response.WriteAsJsonAsync(new { error = "Confirm the architecture design before changing YARP routing." });
        return;
    }
    if (modifying && path.StartsWithSegments("/admin/api/fleet") &&
#if GATEWAYCORE_COMMERCIAL
        !CommercialLicenseRuntime.FleetRecoveryEndpoint(ctx.Request.Method,path) &&
#endif
        !OnboardingApi.IsMultiGatewayDesign(privateDir))
    {
        ctx.Response.StatusCode = 409;
        await ctx.Response.WriteAsJsonAsync(new { error = "Fleet actions require a confirmed multi-gateway design." });
        return;
    }
    await next();
});


// Opt-in peer telemetry transport. Never accept plaintext or unauthenticated
// messages, even when a proxy adds an untrusted X-Forwarded-Proto header.
if (peerSyncSettings is not null && peerStateJournal is not null && peerSigner is not null)
{
    app.MapPost("/gateway/internal/peer-sync", async (HttpContext ctx) =>
    {
        if (!ctx.Request.IsHttps) return Results.StatusCode(403);
        if (ctx.Request.ContentLength is > 262144) return Results.StatusCode(413);
        using var body = new MemoryStream();
        var buffer = new byte[8192];
        while (true)
        {
            var n = await ctx.Request.Body.ReadAsync(buffer, ctx.RequestAborted);
            if (n == 0) break;
            if (body.Length + n > 262144) return Results.StatusCode(413);
            body.Write(buffer, 0, n);
        }
        var bytes = body.ToArray();
        var sender = ctx.Request.Headers["X-GC-Peer-Id"].ToString();
        var nonce = ctx.Request.Headers["X-GC-Peer-Nonce"].ToString();
        var signature = ctx.Request.Headers["X-GC-Peer-Sig"].ToString();
        if (!long.TryParse(ctx.Request.Headers["X-GC-Peer-Ts"].ToString(),
                System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out var ts) ||
            !peerSigner.Verify(sender, peerSyncSettings.RemoteId, ts, nonce, signature,
                bytes, DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
            return Results.StatusCode(403);
        PeerStateFrame? frame;
        try { frame = System.Text.Json.JsonSerializer.Deserialize<PeerStateFrame>(bytes); }
        catch (System.Text.Json.JsonException) { return Results.BadRequest(); }
        // Only a correctly signed, current-protocol request from the expected
        // peer may learn this process's challenge. No old snapshot is applied.
        if (frame is null || frame.ProtocolVersion != PeerStateFrame.CurrentProtocolVersion ||
            frame.NodeId != peerSyncSettings.RemoteId)
            return Results.StatusCode(409);
        if (!peerStateJournal.MatchesReceiverEpoch(frame))
        {
            ctx.Response.Headers[PeerStateJournal.ReceiverEpochHeader] = peerStateJournal.ReceiverEpoch;
            ctx.Response.Headers.CacheControl = "no-store";
            return Results.StatusCode(409);
        }
        if (!peerStateJournal.ApplyBoundFrame(frame, PeerStateJournal.CurrentMinute()))
            return Results.StatusCode(409);
        return Results.NoContent();
    });
}
app.MapOrganizationProfile(privateDir, Audit);
app.MapTlsInventory();
if (stagedImportEnabled)
{
    app.MapPost("/admin/api/tls/staged/preview", async (HttpContext ctx, StagedTrafficCertificate service) =>
    {
        if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        try
        {
            var preview = await service.PreviewAsync(timeout.Token);
            var fleetMode = OnboardingApi.IsMultiGatewayDesign(privateDir);
            var fleetGrantReady = false;
#if GATEWAYCORE_COMMERCIAL
            if (fleetMode && fleetQuorum is not null && externalAuditIntent is not null &&
                auditOutbox is not null && acmeRenewalSettings is null)
            {
                try
                {
                    using var fleetLock = FleetTlsOperator.OpenExclusive(privateDir);
                    var plan = FleetTlsOperator.ReadActivation(privateDir, commercialLicense,
                        preview.ActiveDigest, preview.CandidateDigest);
                    if (fleetQuorum.Scope == plan.Scope)
                    {
                        await fleetQuorum.Assert(plan.TransactionId, plan.Epoch, timeout.Token);
                        fleetGrantReady = true;
                    }
                }
                catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or
                    InvalidOperationException or CryptographicException or OperationCanceledException or ArgumentException)
                { }
            }
#endif
            return Results.Ok(new { preview.CandidateDigest, preview.ActiveDigest, preview.Thumbprint,
                preview.NotAfterUtc, fleetMode, fleetGrantReady });
        }
        catch (Exception ex)
        {
            await Audit(Actor(ctx), "TLS_STAGED_PREVIEW_FAILED", new { failureType = ex.GetType().Name });
            return Results.Conflict(new { error = "No usable staged PFX or active certificate drift. Check host provisioning." });
        }
    }).RequireAuthorization(p => p.RequireRole("Administrator")).RequireRateLimiting("tls-stage-import");
    app.MapPost("/admin/api/tls/staged/activate", async (HttpContext ctx, StagedTrafficCertificate service, StagedActivationInput input) =>
    {
        if (input.CandidateDigest is null || input.ActiveDigest is null ||
            !Regex.IsMatch(input.CandidateDigest, "^[A-F0-9]{64}$") || !Regex.IsMatch(input.ActiveDigest, "^[A-F0-9]{64}$") ||
            input.Confirmation != "ACTIVATE " + input.CandidateDigest)
            return Results.BadRequest(new { error = "Exact preview digests and typed confirmation required." });
        if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
        // Multi-gateway import is supported only through the commercial,
        // installation-bound, independently signed per-node quorum plan.
        var fleetMode = OnboardingApi.IsMultiGatewayDesign(privateDir);
#if GATEWAYCORE_COMMERCIAL
        if (fleetMode && (fleetQuorum is null || externalAuditIntent is null ||
            auditOutbox is null || acmeRenewalSettings is not null))
            return Results.Conflict(new { error = "Fleet certificate import requires authenticated quorum, durable external audit and independently controlled renewal." });
#else
        if (fleetMode)
            return Results.Conflict(new { error = "Fleet certificate import requires the licensed signed fleet workflow." });
#endif
        if (externalAuditIntent is not null && auditOutbox is null)
            return Results.Conflict(new { error = "Enterprise certificate import requires a configured durable audit outbox." });
        if (SetupCenter.ReadFreeze(privateDir).Frozen)
            return Results.Conflict(new { error = "Local change freeze is active." });
        await Audit(Actor(ctx), "TLS_STAGED_ACTIVATION_REQUEST", new { input.CandidateDigest, input.ActiveDigest });
        if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted, app.Lifetime.ApplicationStopping);
        timeout.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            string? intentId = null;
#if GATEWAYCORE_COMMERCIAL
            using var fleetLock = fleetMode ? FleetTlsOperator.OpenExclusive(privateDir) : null;
            var fleetPlan = fleetMode ? FleetTlsOperator.ReadActivation(privateDir, commercialLicense,
                input.ActiveDigest, input.CandidateDigest) : null;
#endif
            async Task<IDisposable> AuthorizeCertificateCommit(CancellationToken token)
            {
                if (!await AuditActorCurrent(ctx, true))
                    throw new InvalidOperationException("Certificate authorization no longer current.");
                if (externalAuditIntent is not null)
                {
                    intentId = await externalAuditIntent.ConfirmWithIdAsync(Actor(ctx), "tls-staged-activate",
                        input.ActiveDigest, input.CandidateDigest, token);
                    if (intentId is null) throw new InvalidOperationException("External certificate intent unavailable.");
                }
                await loginGate.WaitAsync(token);
                try
                {
                    if (!await AuditActorCurrent(ctx, true) || SetupCenter.ReadFreeze(privateDir).Frozen ||
                        OnboardingApi.IsMultiGatewayDesign(privateDir) != fleetMode)
                        throw new InvalidOperationException("Certificate authorization or topology changed.");
                    if (intentId is not null)
                        await localAudit.AppendAsync(Actor(ctx), "TLS_STAGED_MUTATION_PREPARED",
                            new { input.ActiveDigest, input.CandidateDigest }, intentId);
                    if (!await AuditActorCurrent(ctx, true) || SetupCenter.ReadFreeze(privateDir).Frozen ||
                        OnboardingApi.IsMultiGatewayDesign(privateDir) != fleetMode)
                        throw new InvalidOperationException("Certificate authorization changed during audit.");
#if GATEWAYCORE_COMMERCIAL
                    if (fleetMode)
                    {
                        if (fleetPlan is null || fleetQuorum is null)
                            throw new InvalidOperationException("Fleet certificate plan unavailable.");
                        await FleetTlsOperator.ConsumeAsync(privateDir, commercialLicense, fleetQuorum, fleetPlan, token);
                        if (!await AuditActorCurrent(ctx, true) || SetupCenter.ReadFreeze(privateDir).Frozen ||
                            !OnboardingApi.IsMultiGatewayDesign(privateDir))
                            throw new InvalidOperationException("Certificate authority changed at fleet commit.");
                    }
#endif
                    token.ThrowIfCancellationRequested();
                    return new StagedActivationGateLease(loginGate);
                }
                catch { loginGate.Release(); throw; }
            }
            var result = await service.ActivateAsync(input.CandidateDigest, input.ActiveDigest, timeout.Token,
                AuthorizeCertificateCommit);
            await localAudit.AppendAsync(Actor(ctx), "TLS_STAGED_ACTIVATED",
                new { result.Thumbprint, result.NotAfterUtc, input.CandidateDigest, fleetMode }, intentId);
            return Results.Ok(new { activated = true, result.Thumbprint, result.NotAfterUtc,
                independentFleetCompletionRequired = fleetMode });
        }
        catch (Exception ex)
        {
            await Audit(Actor(ctx), "TLS_STAGED_ACTIVATION_UNCONFIRMED", new { failureType = ex.GetType().Name });
            return Results.Conflict(new { error = "Activation not confirmed. Verify live TLS and reconcile before retrying." });
        }
    }).RequireAuthorization(p => p.RequireRole("Administrator")).RequireRateLimiting("tls-stage-import");
}
app.MapSpecialistDrafts();
var wafBroker = WafDashboardBroker.FromEnvironment();
var dnsBroker = WafDashboardBroker.FromEnvironment("YARP_GSLB_DASHBOARD");
app.MapGet("/admin/api/specialist/gslb-deployment", () => Results.Ok(new {
    configured = dnsBroker is not null,
    scope = "Independently staged signed DNS plan; separate authority commit required"
})).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/specialist/gslb-deployment", async (HttpContext ctx, WafDashboardRequest request) =>
{
    if (dnsBroker is null) return Results.Conflict(new { error = "Host DNS deployment broker not configured." });
    if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
    if (externalAuditIntent is not null || oidcPolicy is not null)
        return Results.Conflict(new { error = "Enterprise deployments require the independent operator workflow." });
    if (request.Operation is not ("preflight" or "execute") || request.Revision is < 1 or > 9007199254740991 ||
        request.Digest is null || !Regex.IsMatch(request.Digest, "^[A-F0-9]{64}$") ||
        request.Confirmation != request.Operation.ToUpperInvariant() + " " + request.Digest)
        return Results.BadRequest(new { error = "Exact signed DNS plan sequence, digest and confirmation required." });
    if (SetupCenter.ReadFreeze(privateDir).Frozen)
        return Results.Conflict(new { error = "Local routing change freeze is active." });
    await Audit(Actor(ctx), "DNS_BROKER_REQUESTED", new { request.Operation, request.Revision, request.Digest });
    if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
    try
    {
        var outcome = await dnsBroker.RequestAsync(request, ctx.RequestAborted);
        await Audit(Actor(ctx), "DNS_BROKER_OUTCOME", new { request.Revision, request.Digest, outcome });
        return outcome == "refused-or-failed"
            ? Results.Conflict(new { error = "Broker refused or failed. Reconcile independent DNS journal." })
            : Results.Ok(new { outcome });
    }
    catch (Exception ex)
    {
        await Audit(Actor(ctx), "DNS_BROKER_UNCONFIRMED", new { failureType = ex.GetType().Name });
        return Results.Json(new { error = "Result unconfirmed. Do not retry until independent reconciliation." }, statusCode: 503);
    }
}).WithMetadata(new RequestSizeLimitAttribute(2048))
  .RequireAuthorization(p => p.RequireRole("Administrator"))
  .RequireRateLimiting("waf-dashboard-deployment");
app.MapGet("/admin/api/specialist/waf-deployment", () => Results.Ok(new {
    configured = wafBroker is not null,
    scope = "Host-approved signed policy via local or mutually authenticated operator broker; independent quorum commit required"
})).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/specialist/waf-deployment", async (HttpContext ctx, WafDashboardRequest request) =>
{
    if (wafBroker is null) return Results.Conflict(new { error = "Host WAF deployment broker not configured." });
    if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
    if (externalAuditIntent is not null || oidcPolicy is not null)
        return Results.Conflict(new { error = "External-audit/enterprise deployments require the independent operator workflow." });
    if (request.Operation is not ("preflight" or "execute") || request.Revision is < 1 or > 9007199254740991 ||
        request.Digest is null || !Regex.IsMatch(request.Digest, "^[A-F0-9]{64}$") ||
        request.Confirmation != request.Operation.ToUpperInvariant() + " " + request.Digest)
        return Results.BadRequest(new { error = "Exact signed policy revision, digest and confirmation required." });
    if (SetupCenter.ReadFreeze(privateDir).Frozen)
        return Results.Conflict(new { error = "Local routing change freeze is active." });
    await Audit(Actor(ctx), "WAF_BROKER_REQUESTED", new { request.Operation, request.Revision, request.Digest });
    if (!await AuditActorCurrent(ctx, true)) return Results.StatusCode(403);
    try
    {
        var outcome = await wafBroker.RequestAsync(request, ctx.RequestAborted);
        await Audit(Actor(ctx), "WAF_BROKER_OUTCOME", new { request.Revision, request.Digest, outcome });
        return outcome == "refused-or-failed"
            ? Results.Conflict(new { error = "Broker refused or failed. Inspect independent operator receipts." })
            : Results.Ok(new { outcome });
    }
    catch (Exception ex)
    {
        await Audit(Actor(ctx), "WAF_BROKER_UNCONFIRMED", new { failureType = ex.GetType().Name });
        return Results.Json(new { error = "Result unconfirmed. Do not retry until independent reconciliation." }, statusCode: 503);
    }
}).WithMetadata(new RequestSizeLimitAttribute(2048))
  .RequireAuthorization(p => p.RequireRole("Administrator"))
  .RequireRateLimiting("waf-dashboard-deployment");
app.MapReverseProxy(proxyPipeline =>
{
#if GATEWAYCORE_COMMERCIAL
    proxyPipeline.Use(async (context, next) =>
    {
        if (!commercialLicense.TrafficAdmitted)
        { context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable; return; }
        await next();
    });
#endif
    GatewayOpenTelemetry.UseProxyTelemetry(proxyPipeline, (context, elapsedMs) =>
    {
        var feature = context.Features.Get<Yarp.ReverseProxy.Model.IReverseProxyFeature>();
        if (feature?.ProxiedDestination is { } destination)
        {
            var id = feature.Cluster.Config.ClusterId + "/" + destination.DestinationId;
            destinationTelemetry.Record(id, context.Response.StatusCode, elapsedMs);
        }
    });
    // Fence new proxy work as soon as the host starts graceful shutdown.
    // Existing forwarded streams are not linked to ApplicationStopping.
    var stopping = app.Lifetime.ApplicationStopping;
    GatewayOpenTelemetry.UseShutdownFence(proxyPipeline, stopping);
    proxyPipeline.Use(async (context, next) =>
    {
        if (!ApplicationAccessFilter.Permits(context.GetReverseProxyFeature().Route.Config, context))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            GatewayOpenTelemetry.MarkLocalRejection(context, "application_access_denied");
            return;
        }
        if (!ApplicationAccessFilter.PermitsMethod(context.GetReverseProxyFeature().Route.Config,
            context.Request.Method, out var allow))
        {
            context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
            context.Response.Headers.Allow = allow;
            context.Response.Headers.CacheControl = "no-store";
            GatewayOpenTelemetry.MarkLocalRejection(context, "traffic_method_denied");
            return;
        }
        await next();
    });
    if (peerStateJournal is not null)
        proxyPipeline.Use(async (context,next) => {
            // Telemetry only. Never use eventual peer counters for strict admission.
            peerStateJournal.Observe(context.Connection.RemoteIpAddress,
                PeerStateJournal.CurrentMinute());
            await next();
        });
    // Opt-in, bounded process-local stick-table-style peer-IP admission.
    // No X-Forwarded-For: only the network-layer peer is trusted.
    if (sharedPeerLimiter is not null)
    {
        proxyPipeline.Use(async (context, next) =>
        {
            try
            {
                if (!await sharedPeerLimiter.TryAdmitAsync(context.Connection.RemoteIpAddress))
                {
                    context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                    return;
                }
            }
            catch (StackExchange.Redis.RedisException)
            {
                // Network partition: do not fall back to per-node quota (double-spend).
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return;
            }
            catch (TimeoutException)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return;
            }
            await next();
        });
    }
    else if (peerRateTable is not null)
    {
        proxyPipeline.Use(async (context, next) =>
        {
            if (!peerRateTable.TryAdmit(context.Connection.RemoteIpAddress,
                    System.Diagnostics.Stopwatch.GetTimestamp()))
            {
                context.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                return;
            }
            await next();
        });
    }
    // Drain filtering runs before affinity and load balancing, for all policies.
    // Existing forwarded requests continue; no in-flight cancellation occurs.
    proxyPipeline.Use(async (context, next) =>
    {
        var feature = context.GetReverseProxyFeature();
        TrafficLifecycle.Observe(feature.AllDestinations, feature.AvailableDestinations);
        if (feature.AvailableDestinations.Any(TrafficLifecycle.IsDraining))
            feature.AvailableDestinations = feature.AvailableDestinations
                .Where(d => !TrafficLifecycle.IsDraining(d)).ToArray();
        await next();
    });
    proxyPipeline.Use(async (context, next) =>
    {
        var feature = context.GetReverseProxyFeature();
        if (feature.Cluster.Config.Metadata?.ContainsKey(ActiveCompoundSettings.ModeKey) == true)
        {
            feature.AvailableDestinations = feature.AvailableDestinations
                .Where(d => CompoundReadinessEvidence.Eligible(feature.Cluster, d)).ToArray();
            if (feature.AvailableDestinations.Count == 0)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                return;
            }
        }
        await next();
    });
    proxyPipeline.Use(async (context, next) =>
    {
        var affinity = context.GetReverseProxyFeature().Cluster.Config.SessionAffinity;
        if (affinity?.Enabled == true && affinity.Policy == ExpiringCookieAffinityPolicy.PolicyName &&
            !context.Request.IsHttps)
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }
        await next();
    });
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
    proxyPipeline.Use(async (context, next) =>
    {
        var feature = context.GetReverseProxyFeature();
        if (feature.Cluster.Config.LoadBalancingPolicy != "FastestResponse" ||
            !(HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)))
        {
            await next();
            return;
        }
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        await next();
        if (!context.RequestAborted.IsCancellationRequested &&
            context.Response.StatusCode is >= 200 and < 300 &&
            feature.ProxiedDestination is { } destination)
            FastestResponsePolicy.Observe(destination, System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds);
    });
    // The selected destination is already fixed. Holding this lease around the
    // entire downstream pipeline covers body streaming, WebSockets and exceptions.
    proxyPipeline.Use(async (context, next) =>
    {
        var feature = context.GetReverseProxyFeature();
        // YARP sets ProxiedDestination in its final forwarding middleware, after
        // this policy stage. Load balancing has already reduced AvailableDestinations
        // to the exact destination that the final forwarder will use.
        var candidates = feature.AvailableDestinations;
        if (candidates.Count == 0)
        {
            await next();
            return;
        }
        if (candidates.Count > 1)
        {
            var admissionEnabled = candidates.Any(candidate =>
                DestinationAdmissionPolicy.TryParse(candidate.Model.Config.Metadata,
                    out var candidatePolicy, out _) && candidatePolicy.Enabled);
            if (admissionEnabled)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                GatewayOpenTelemetry.MarkLocalRejection(context, "admission_destination_unresolved");
                return;
            }
            await next();
            return;
        }

        var selected = candidates[0];
        var selectedConfig = selected.Model.Config;
        var selectedClusterConfig = feature.Cluster.Config;
        var clusterId = selectedClusterConfig.ClusterId;
        var manager = context.RequestServices.GetRequiredService<DestinationAdmissionManager>();
        if (!manager.TryAcquireHandle(clusterId, selected.DestinationId, out var registryHandle, out var policyConflict) || registryHandle is null)
        {
            if (policyConflict)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                GatewayOpenTelemetry.MarkLocalRejection(context, "admission_policy_conflict");
                return;
            }
            if (!DestinationAdmissionPolicy.TryParse(
                    selected.Model.Config.Metadata, out var selectedPolicy, out var policyError))
            {
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                GatewayOpenTelemetry.MarkLocalRejection(context, "invalid_admission_config");
                await context.Response.WriteAsync("Invalid destination admission configuration.");
                return;
            }
            // A disabled snapshot can bypass only when there is no currently
            // reconciled enabled policy. If a newer applied config enabled it,
            // the manager returns its current gate before consulting this snapshot.
            if (!selectedPolicy.Enabled) { await next(); return; }
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.MarkLocalRejection(context, "admission_configuration_unavailable");
            return;
        }
        using (registryHandle)
        {
        var state = registryHandle.State;
        // Use the policy of the exact selected proxy model, not whichever
        // revision the asynchronous registry last reconciled.
        if (!DestinationAdmissionPolicy.TryParse(selectedConfig.Metadata, out var policy, out _) ||
            !policy.Enabled)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.MarkLocalRejection(context, "admission_policy_conflict");
            return;
        }

        var applicationStopping = context.RequestServices.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping;
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted,
            applicationStopping);
        DestinationAdmissionState.DestinationAdmissionLease? lease;
        try
        {
            lease = await state.AcquireForPolicyAsync(waitCancellation.Token, policy);
        }
        catch (DestinationAdmissionPolicyChangedException)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.MarkLocalRejection(context, "admission_policy_conflict");
            return;
        }
        catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
        {
            return;
        }
        catch (OperationCanceledException)
        {
            if (context.RequestServices.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping.IsCancellationRequested)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                GatewayOpenTelemetry.MarkLocalRejection(context, "gateway_shutdown");
            }
            else
            {
                state.RecordTimeout();
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                GatewayOpenTelemetry.MarkLocalRejection(context, "destination_queue_timeout");
            }
            return;
        }
        if (lease is null)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.MarkLocalRejection(context, "destination_queue_full");
            return;
        }

        using (lease)
        {
            // Do not transfer the request to a different backend. If a queued
            // destination was removed, drained or made unhealthy, fail locally.
            var lookup = context.RequestServices.GetRequiredService<IProxyStateLookup>();
            // Atomically fence the queue deadline before forwarding. Stopping
            // the timer and checking its token alone would miss a timer whose
            // callback had not run by the time the permit continuation resumed.
            var failureAfterGrant = DestinationAdmissionForwarding.CompleteQueueWait(
                lease.WasQueued,
                context.RequestAborted,
                applicationStopping,
                lease.QueueStartedTimestamp,
                lease.QueueGrantedTimestamp,
                TimeSpan.FromMilliseconds(policy.QueueTimeoutMs));
            if (failureAfterGrant == DestinationAdmissionFailure.ClientAborted) return;
            if (failureAfterGrant != DestinationAdmissionFailure.None)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                if (failureAfterGrant == DestinationAdmissionFailure.ServiceStopping)
                    GatewayOpenTelemetry.MarkLocalRejection(context, "gateway_shutdown");
                else
                {
                    state.RecordTimeout();
                    GatewayOpenTelemetry.MarkLocalRejection(context, "destination_queue_timeout");
                }
                return;
            }
            if (!lookup.TryGetCluster(clusterId, out var currentCluster) ||
                !ReferenceEquals(currentCluster.Model.Config, selectedClusterConfig) ||
                !DestinationAdmissionForwarding.IsStillEligibleAfterWait(
                    selected.DestinationId,
                    currentCluster.DestinationsState.AvailableDestinations,
                    static destination => destination.DestinationId,
                    TrafficLifecycle.IsDraining,
                    destination => ReferenceEquals(destination, selected) &&
                        ReferenceEquals(destination.Model.Config, selectedConfig)))
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                GatewayOpenTelemetry.MarkLocalRejection(context, "destination_unavailable_after_queue");
                return;
            }
            await next();
        }
        }
    });
    // A request might have passed the first fence before shutdown while
    // queued or during selection. Recheck immediately before forwarding,
    // including destinations without an admission policy.
    proxyPipeline.Use(async (context, next) =>
    {
        if (stopping.IsCancellationRequested)
        {
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.MarkLocalRejection(context, "gateway_shutdown");
            return;
        }
        await next();
    });
    proxyPipeline.Use(next =>
    {
        var provider = new PublicAssetCompression(app.Services.GetRequiredService<Microsoft.AspNetCore.ResponseCompression.IResponseCompressionProvider>());
        var middleware = new Microsoft.AspNetCore.ResponseCompression.ResponseCompressionMiddleware(next, provider);
        return async context =>
        {
            if (!PublicAssetCompression.RequestEligible(context))
            {
                await next(context);
                return;
            }
            // Identity representations must also vary on the encoding request.
            context.Response.OnStarting(() =>
            {
                if (PublicAssetCompression.ResponseEligible(context) &&
                    !context.Response.Headers.Vary.ToString().Split(',', StringSplitOptions.TrimEntries)
                        .Any(value => value.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase)))
                    context.Response.Headers.Append("Vary", "Accept-Encoding");
                return Task.CompletedTask;
            });
            await middleware.Invoke(context);
        };
    });
    proxyPipeline.UsePassiveHealthChecks();
}).RequireRateLimiting("proxy-concurrency");
app.Run();

static bool ValidId(string s) => s.Length is > 0 and <= 80 && Regex.IsMatch(s, "^[a-zA-Z0-9_-]+$");
static string Csv(string value)
{
    var firstNonWhitespace = value.TrimStart();
    if (firstNonWhitespace.Length > 0 && firstNonWhitespace[0] is '=' or '+' or '-' or '@')
        value = "'" + value;
    return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
}
static bool ValidAddress(string? s) => Uri.TryCreate(s, UriKind.Absolute, out var u) && (u.Scheme == "http" || u.Scheme == "https") && !string.IsNullOrWhiteSpace(u.Host) && u.UserInfo.Length == 0;
static bool ValidPath(string? s) => !string.IsNullOrEmpty(s) && s.StartsWith('/') && s.Length <= 300 && !s.Contains('\\');


static AdminUser NewUser(string username, string role, string password, string? email = null)
{
    var salt = RandomNumberGenerator.GetBytes(24);
    var hash = Rfc2898DeriveBytes.Pbkdf2(password, salt, 310_000, HashAlgorithmName.SHA256, 32);
    return new AdminUser(username, role, Convert.ToBase64String(salt), Convert.ToBase64String(hash), email, true, Convert.ToHexString(RandomNumberGenerator.GetBytes(24)));
}
static bool VerifyPassword(string password, AdminUser user)
{
    try
    {
        var hash = Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(user.Salt), 310_000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromBase64String(user.Hash));
    }
    catch { return false; }
}
static bool ValidUser(string? username) => username is not null && Regex.IsMatch(username, "^[A-Za-z0-9_.-]{3,40}$");
static bool ValidEmail(string? email) => !string.IsNullOrWhiteSpace(email) && email.Length <= 254 && MailAddress.TryCreate(email, out _);
static string MaskEmail(string email) { var at = email.IndexOf('@'); return at < 2 ? "***" : email[..2] + "***" + email[at..]; }
static bool ValidPassword(string? password) => password is not null && password.Length >= 16 && password.Length <= 256;

record LoginInput(string Username, string Password, string? Email = null, string Provider = "local");
record VerifyOtpInput(string ChallengeId, string Code);
record SetupEnrollmentInput(string? Action, string? SetupCode, string? FlowId = null, string? Code = null,
    string? Email = null, string? Username = null, string? Password = null, MailSettingsInput? Mail = null);
record SetupEnrollment(string Id, MailSettings Mail, string Email, string Stage, string Nonce, string Hash,
    DateTimeOffset ExpiresAt, int Attempts)
{
    public static SetupEnrollment Issue(string id, MailSettings mail, string email, string stage, string code)
    {
        var nonce = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        return new(id, mail, email, stage, nonce,
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce + code))), DateTimeOffset.UtcNow.AddMinutes(5), 0);
    }
    public bool Matches(string? code) => Attempts < 5 && code is not null && Regex.IsMatch(code, "^[0-9]{6}$") &&
        CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(Nonce + code)), Convert.FromHexString(Hash));
}
record OtpChallenge(string Username, string Nonce, string Hash, DateTimeOffset ExpiresAt, int Attempts);
record MailSettings(bool Enabled = false, string Host = "", int Port = 25, string From = "", string Username = "", string EncryptedPassword = "", bool StartTls = false,
    string AuthMode = "password", string OAuthClientId = "", string EncryptedOAuthClientSecret = "", string EncryptedOAuthRefreshToken = "", string OAuthTenant = "");
record MailSettingsInput(bool Enabled, string Host, int Port, string From, string Username, string Password, bool StartTls,
    string AuthMode = "password", string OAuthClientId = "", string OAuthClientSecret = "", string OAuthRefreshToken = "", string OAuthTenant = "");
record EmployeeInvitationInput(string? Username, string? Email, string? Role);
sealed class EmployeeInvitationRedemptionEndpoint { }
record EmployeeInvitationRedeem(string? Action, string? Code, string? Password = null);
record StagedActivationInput(string? CandidateDigest, string? ActiveDigest, string? Confirmation);
sealed class StagedActivationGateLease(SemaphoreSlim gate) : IDisposable
{
    private SemaphoreSlim? held = gate;
    public void Dispose() => Interlocked.Exchange(ref held, null)?.Release();
}
record EmployeeInvitation(string Id, string Username, string Email, string Role, string Issuer, string IssuerStamp,
    string MailFingerprint, byte[] CodeHash, DateTimeOffset ExpiresUtc, bool Verified)
{
    public static byte[] Digest(string code) => SHA256.HashData(Encoding.ASCII.GetBytes(code));
}
record UserInput(string Username, string Role, string Password, string? Email);
record PasswordInput(string Password);
record ChangeDecision(string Decision, string? Reason);
record InventoryInput(string Id, string Name, string Type, string Address, string Notes);
record VipDrainInput(bool? Draining,string? Reason);
record VipMachineDrainInput(string Scope,long Epoch,string Nonce,bool Drain);
record AdminUser(string Username, string Role, string Salt, string Hash, string? Email = null, bool Enabled = true, string SecurityStamp = "", string Provider = "Local", string DistinguishedName = "", long OidcRevokedBefore = 0, long OidcLogoutAuditThrough = 0);

record FleetGateway(string Id, string Url, string ClientCertificateThumbprint);

sealed record GatewayDestinationHealthRow(string ClusterId, string DestinationId, string ActiveHealth,
    string PassiveHealth, int InflightRequests, long Requests, long Http4xx, long Http5xx);
