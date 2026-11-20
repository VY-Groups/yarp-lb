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
using System.Threading.RateLimiting;
using Yarp.ReverseProxy.LoadBalancing;

// Windows neutral-identity deployments use a new ProgramData root. Refuse
// silent re-bootstrap when another YARP control plane already has identities.
// Disposable EC2 CI uses a private workspace; production Linux state is
// explicitly selected and owned through YARP_CONTROL_PLANE_DIR.
var ec2Lab = Ec2WorkflowLab.Enabled;
var privateDir = ec2Lab ? Ec2WorkflowLab.PrivateDirectory()
    : OperatingSystem.IsLinux() ? LinuxKeyProtection.InitializeStateDirectory()
    : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "GatewayCoreYarp", "ControlPlane");
if (OperatingSystem.IsWindows() && !ec2Lab)
    LegacyStateGuard.RejectUnmigratedWindowsState(privateDir);
if (OperatingSystem.IsWindows() && !ec2Lab)
    WindowsStateProtection.InitializeStateDirectory(Path.GetDirectoryName(privateDir)!, privateDir);
if (!OperatingSystem.IsLinux() || ec2Lab)
    Directory.CreateDirectory(privateDir);
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
if (auditOutbox is not null)
    builder.Services.AddHostedService(sp => new AuditOutboxWorker(auditOutbox, sp.GetRequiredService<ILogger<AuditOutboxWorker>>()));
GatewayOpenTelemetry.Configure(builder.Services);
// Explicit v0.1 multi-socket mode; legacy loopback remains CI migration-only.
var isolatedListeners = GatewayListenerIsolation.FromEnvironment();
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
    if (ec2Lab || !acmeHttp01PublicEntrypointEnabled || isolatedListeners is null)
        throw new InvalidOperationException("ACME renewal requires production data protection and an explicitly enabled isolated public HTTP-01 listener.");
    acmeRenewalSettings = AcmeRenewalSettings.Load(acmeConfigurationPath,
        isolatedListeners.Config.TrafficPfxPath, isolatedListeners.Config.TrafficPfxPasswordFile,
        isolatedListeners.Config.TrafficCertificateDnsNames);
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
    dataProtection.ProtectKeysWithDpapi(protectToLocalMachine: true);
else if (OperatingSystem.IsLinux() && !ec2Lab)
    LinuxKeyProtection.Configure(dataProtection, privateDir);
else if (ec2Lab)
    Console.Error.WriteLine("WARNING: CI-only EC2 lab uses temporary, unencrypted local Data Protection keys. Never use in production.");
else
    throw new PlatformNotSupportedException("Unsupported OS Data Protection mode");
if (acmeRenewalSettings is { } renewalSettings)
{
    var accountKeyPath = Path.Combine(privateDir, "acme-account.encrypted");
    builder.Services.AddSingleton<IAcmeCertificateIssuer>(services => new CertesAcmeCertificateIssuer(
        new AcmeAccountKeyStore(accountKeyPath,
            services.GetRequiredService<IDataProtectionProvider>().CreateProtector("GatewayCore.AcmeAccountKeyProtector.v1")),
        renewalSettings.AgreeToTermsOfService));
    builder.Services.AddSingleton<AcmeRenewalCoordinator>(services => new AcmeRenewalCoordinator(
        services.GetRequiredService<IAcmeCertificateIssuer>(),
        services.GetRequiredService<AcmeHttp01ChallengeStore>(),
        isCertificateActive: isolatedListeners.IsTrafficCertificateActive));
    builder.Services.AddHostedService(services => new AcmeRenewalBackgroundService(renewalSettings,
        services.GetRequiredService<AcmeRenewalCoordinator>(), null,
        services.GetRequiredService<ILogger<AcmeRenewalBackgroundService>>()));
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
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
    .ConfigureHttpClient(BackendMutualTls.Configure)
    .AddConfigFilter<DestinationAdmissionConfigFilter>();
builder.Services.AddSingleton<DestinationAdmissionManager>();
builder.Services.AddHostedService<DestinationAdmissionRegistryReconciler>();
// Custom policies are registered on every serving YARP instance, never on the UI alone.
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
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
                        : active.Role == "Administrator" && oidcPolicy.IsBreakGlass(active.Username) &&
                          principal.FindFirst(EnterpriseOidcPolicy.RecoveryClaim)?.Value == oidcPolicy.Fingerprint);
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
    options.AddFixedWindowLimiter("login", cfg =>
    {
        cfg.PermitLimit = 8;
        cfg.Window = TimeSpan.FromMinutes(5);
        cfg.QueueLimit = 0;
        cfg.AutoReplenishment = true;
    });
});
builder.Services.AddHttpClient("probe").ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { AllowAutoRedirect = false });
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
    Environment.GetEnvironmentVariable("GATEWAY_PEER_SYNC_INTERVAL_SECONDS"));
if (peerSyncSettings is not null)
{
    builder.Services.AddSingleton(peerSyncSettings);
    builder.Services.AddSingleton(sp => new PeerStateJournal(peerSyncSettings.NodeId,
        peerSyncSettings.RemoteId, peerSyncSettings.Secret, peerSyncSettings.Capacity,
        TimeSpan.FromSeconds(Math.Clamp(peerSyncSettings.IntervalSeconds * 3, 6, 60))));
    builder.Services.AddSingleton(sp => new PeerSignedMessages(peerSyncSettings.Secret));
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
var accessLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayCore.AccessLog");
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
var inventoryPath = Path.Combine(privateDir, "inventory.json");
var backupFolder = Path.Combine(privateDir, "config-backups");
Directory.CreateDirectory(backupFolder);
var jsonOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
var loginGate = new SemaphoreSlim(1, 1);
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
        accessLogger.LogInformation(
            "GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} clientIpSource={ClientIpSource} method={Method} routeId={RouteId} statusCode={StatusCode} durationMs={DurationMs}",
            timestampUtc, clientAddress.Address?.ToString() ?? "unknown", clientAddress.Source,
            ctx.Request.Method, routeId, ctx.Response.StatusCode,
            Math.Round(elapsed * 1000.0 / System.Diagnostics.Stopwatch.Frequency, 3));
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
        !ctx.Request.Path.StartsWithSegments("/admin/api/login"))
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
        if (ctx.Request.Path != "/admin/api/logout" && ctx.User.IsInRole("Viewer")) { ctx.Response.StatusCode = 403; return; }
        // All authenticated administrative mutations require recent verified IdP
        // authentication in enterprise mode, except the explicitly named recovery account.
        // The recovery account must have signed in with local password + delivered OTP.
        if (oidcPolicy is not null && ctx.Request.Path != "/admin/api/logout" &&
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
         ctx.Request.Path.StartsWithSegments("/admin/api/fleet/rollout")) &&
        SetupCenter.ReadFreeze(privateDir).Frozen)
    {
        ctx.Response.StatusCode = 423;
        await ctx.Response.WriteAsJsonAsync(new { error = "Local routing change freeze is active. Unfreeze with administrator approval/reason before modifying configuration." });
        return;
    }
    await next();
});

string Actor(HttpContext context) => context.User.Identity?.Name ?? "unknown";
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
    if (externalAuditIntent is null) return (null, null);
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
    return (null, intentId);
}
// Call only under the writer lock for the target file. The proposed bytes
// are persisted verbatim, so the signed digest describes the actual state.
byte[] AuditStateBytes(string path) => File.Exists(path) ? File.ReadAllBytes(path) : [];
async Task<bool> AuditActorCurrent(HttpContext ctx, bool administratorOnly)
{
    var active = ReadUsers().SingleOrDefault(x => x.Username.Equals(Actor(ctx), StringComparison.OrdinalIgnoreCase));
    if (active is null || !active.Enabled || active.SecurityStamp != ctx.User.FindFirst("stamp")?.Value ||
        active.Role != ctx.User.FindFirst(ClaimTypes.Role)?.Value ||
        (administratorOnly ? active.Role != "Administrator" : active.Role is not ("Administrator" or "Operator")))
        return false;
    if (oidcPolicy is null || oidcPolicy.IsBreakGlass(active.Username)) return true;
    if (!oidcPolicy.SessionValid(ctx.User, active.Username, active.Role, DateTimeOffset.UtcNow, stepUp: true) ||
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
        current.SecurityStamp == active.SecurityStamp &&
        current.OidcRevokedBefore == active.OidcRevokedBefore &&
        oidcPolicy.SessionValid(ctx.User, current.Username, current.Role, DateTimeOffset.UtcNow, stepUp: true);
}
async Task<IResult?> ConfirmStateMutation(HttpContext ctx, string path, byte[] before, byte[] proposed,
    string operation, bool administratorOnly)
{
    if (externalAuditIntent is null) return null;
    if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
    if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
        return Results.Conflict(new { error = "State changed before external audit confirmation" });
    if (!await externalAuditIntent.ConfirmAsync(Actor(ctx), operation,
        Convert.ToHexString(SHA256.HashData(before)), Convert.ToHexString(SHA256.HashData(proposed)),
        ctx.RequestAborted) || ctx.RequestAborted.IsCancellationRequested)
        return Results.Json(new { error = "External audit receipt unavailable; state unchanged" }, statusCode: 503);
    if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
    if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
        return Results.Conflict(new { error = "State changed during external audit confirmation" });
    return null;
}
// The caller holds the resource gate, never loginGate. Obtain the account
// gate after collector I/O and retain it through the exact state commit.
async Task<IResult?> ConfirmAndWriteResourceMutation(HttpContext ctx, string path,
    byte[] before, byte[] proposed, string operation, bool administratorOnly)
{
    if (externalAuditIntent is null)
    {
        WriteAuditedState(path, proposed);
        return null;
    }
    var denied = await ConfirmStateMutation(ctx, path, before, proposed, operation, administratorOnly);
    if (denied is not null) return denied;
    try { await loginGate.WaitAsync(ctx.RequestAborted); }
    catch (OperationCanceledException)
    { return Results.Json(new { error = "Account mutation commit cancelled; state unchanged" }, statusCode: 503); }
    try
    {
        if (ctx.RequestAborted.IsCancellationRequested)
            return Results.Json(new { error = "Account mutation commit cancelled; state unchanged" }, statusCode: 503);
        if (!await AuditActorCurrent(ctx, administratorOnly)) return Results.StatusCode(403);
        if (!AuditStateBytes(path).AsSpan().SequenceEqual(before))
            return Results.Conflict(new { error = "State changed during external audit confirmation" });
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
    authenticated = ctx.User.Identity?.IsAuthenticated == true,
    username = ctx.User.Identity?.Name,
    role = ctx.User.FindFirst(ClaimTypes.Role)?.Value,
    csrf = ctx.User.FindFirst("csrf")?.Value,
    federatedOidc = oidcPolicy is not null && ctx.User.HasClaim(c => c.Type == EnterpriseOidcPolicy.SubjectClaim),
    mode = "Local administrative test console — not certified for CA production"
}));

app.MapPost("/admin/api/bootstrap", async (HttpContext ctx, LoginInput input) =>
{
    if (oidcPolicy is not null)
        return Results.Json(new { error = "Provision local recovery and mapped accounts before enabling enterprise SSO" }, statusCode: 403);
    await loginGate.WaitAsync();
    try
    {
        if (ReadUsers().Count > 0) return Results.Conflict(new { error = "Already initialized" });
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

app.MapGet("/admin/api/auth-methods", () => Results.Ok(new {
    local = true, activeDirectory = oidcPolicy is null && directoryAuth.Read().Enabled,
    mailOtp = ReadMail().Enabled, enterpriseOidc = oidcPolicy is not null,
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AccountSnapshot();
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
app.MapPost("/admin/api/users/{username}/password", async (HttpContext ctx, string username, PasswordInput input) =>
{
    if (!ValidPassword(input.Password)) return Results.BadRequest(new { error = "Password must contain at least 16 characters" });
    await loginGate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AccountSnapshot();
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AccountSnapshot();
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AccountSnapshot();
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(mailPath);
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(mailProofPath);
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(directoryPath);
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
app.MapPost("/admin/api/inventory", async (HttpContext ctx, InventoryInput input) =>
{
    if (!ValidId(input.Id) || input.Name.Length is < 1 or > 100 ||
        input.Type is not ("YARP Gateway" or "Application Server" or "Pgpool" or "Database" or "Service") ||
        input.Address.Length > 255) return Results.BadRequest(new { error = "Invalid inventory entry" });
    await gate.WaitAsync();
    try
    {
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(inventoryPath);
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(inventoryPath);
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
app.MapGet("/dashboard/app.js", () => Results.File(Path.Combine(root, "wwwroot", "app.js"), "text/javascript; charset=utf-8"));
app.MapGet("/dashboard/style.css", () => Results.File(Path.Combine(root, "wwwroot", "style.css"), "text/css; charset=utf-8"));
app.MapGet("/gateway/health", () => Results.Ok(new { status = "healthy", gateway = Environment.MachineName, utc = DateTimeOffset.UtcNow }));
app.MapHttp01Challenge(acmeHttp01PublicEntrypointEnabled,
    ctx => isolatedListeners?.OnTrafficHttp(ctx) == true);
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
        mode = "Authenticated local management", telemetry = "Local HTTP counters only; no backend or fleet metrics", revision = Convert.ToHexString(SHA256.HashData(snapshot)) });
}).RequireAuthorization();

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
app.MapPost("/admin/api/probe", async (IHttpClientFactory factory) =>
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
            var status = "unreachable"; int? code = null;
            try
            {
                if (Uri.TryCreate(addr, UriKind.Absolute, out var baseUri) && (baseUri.Scheme == "https" || baseUri.Scheme == "http"))
                {
                    using var client = factory.CreateClient("probe");
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    var target = new Uri(baseUri, path.TrimStart('/'));
                    using var response = await client.GetAsync(target, cts.Token);
                    code = (int)response.StatusCode;
                    status = response.IsSuccessStatusCode ? "reachable" : "http-error";
                }
            }
            catch { }
            results.Add(new { cluster = cluster.Key, destination = dest.Key, address = addr, status, httpStatus = code });
        }
    }
    return Results.Ok(new { checkedAt = DateTimeOffset.UtcNow, type = "On-demand HTTP readiness probe (not YARP health state)", results });
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
    foreach (var (key, clusterNode) in clusters)
    {
        if (!ValidId(key) || clusterNode is not JsonObject c) return Results.BadRequest(new { error = "Invalid cluster ID" });
        // Refuse proxy settings that bypass trust checks or produce unexpected insecure forwarding.
        if (string.Equals(c["HttpClient"]?["DangerousAcceptAnyServerCertificate"]?.ToString(), "true", StringComparison.OrdinalIgnoreCase))
            return Results.BadRequest(new { error = "Backend TLS certificate validation cannot be disabled" });
        if (c["HttpClient"]?["MaxConnectionsPerServer"] is JsonNode maxConnections &&
            (!int.TryParse(maxConnections.ToString(), out var maxConn) || maxConn < 1 || maxConn > 50000))
            return Results.BadRequest(new { error = "MaxConnectionsPerServer must be 1..50000" });
        if (string.Equals(c["SessionAffinity"]?["Enabled"]?.ToString(), "true", StringComparison.OrdinalIgnoreCase))
        {
            var affinityPolicy = c["SessionAffinity"]?["Policy"]?.ToString() ?? "HashCookie";
            if (affinityPolicy is not ("HashCookie" or "Cookie" or "ArrCookie" or "CustomHeader"))
                return Results.BadRequest(new { error = "Unsupported session-affinity policy" });
        }
        if (c["HttpRequest"]?["Version"] is JsonNode version && version.ToString() is not ("1.0" or "1.1" or "2" or "3"))
            return Results.BadRequest(new { error = "Unsupported outbound HTTP version" });
        var policy = c["LoadBalancingPolicy"]?.ToString() ?? "RoundRobin";
        if (policy is not ("RoundRobin" or "PowerOfTwoChoices" or "LeastRequests" or "Random" or "FirstAlphabetical" or "WeightedRandom" or "SourceIpHash" or "PrimaryBackup")) return Results.BadRequest(new { error = "Unsupported load-balancing policy" });
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
        doc["ReverseProxy"] = proxy;
        var newConfig = doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        if (externalAuditIntent is not null)
        {
            if (!await externalAuditIntent.ConfirmAsync(Actor(ctx), "CONFIG_APPLY_INTENT", currentRevision,
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(newConfig))), ctx.RequestAborted) ||
                ctx.RequestAborted.IsCancellationRequested)
                return Results.Json(new { error = "External audit receipt unavailable; configuration unchanged" }, statusCode: 503);
            if (!File.ReadAllBytes(configPath).AsSpan().SequenceEqual(snapshot))
                return Results.Conflict(new { error = "Configuration changed during external audit confirmation" });
        }
        Directory.CreateDirectory(backupFolder);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffffffZ");
        var backup = Path.Combine(backupFolder, $"appsettings-{stamp}.json");
        using (var backupStream = new FileStream(backup, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            await backupStream.WriteAsync(snapshot);
        var temp = configPath + ".tmp";
        await File.WriteAllTextAsync(temp, newConfig);
        File.Move(temp, configPath, overwrite: true);
        await Audit(Actor(ctx), "CONFIG_APPLIED", new { routes = routes.Count, clusters = clusters.Count, backup = Path.GetFileName(backup) });
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
        request["payload"] is not JsonObject payload || payload.Count != 4 ||
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
            disabled = Diff(current["AdminDisabledDestinations"] as JsonObject, disabled) });
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
        if (externalAuditIntent is not null)
        {
            var restoreSnapshot = File.ReadAllBytes(configPath);
            if (!await externalAuditIntent.ConfirmAsync(Actor(ctx), "CONFIG_RESTORE_INTENT",
                    Convert.ToHexString(SHA256.HashData(restoreSnapshot)),
                    Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(json))), ctx.RequestAborted) ||
                ctx.RequestAborted.IsCancellationRequested)
                return Results.Json(new { error = "External audit receipt unavailable; configuration unchanged" }, statusCode: 503);
            if (!File.ReadAllBytes(configPath).AsSpan().SequenceEqual(restoreSnapshot))
                return Results.Conflict(new { error = "Configuration changed during external audit confirmation" });
        }
        var safety = Path.Combine(backupFolder, $"appsettings-{DateTimeOffset.UtcNow:yyyyMMddTHHmmssfffffff}Z.json");
        File.Copy(configPath, safety);
        await File.WriteAllTextAsync(configPath + ".tmp", json);
        File.Move(configPath + ".tmp", configPath, true);
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(fleetPath);
        var list = ReadFleet();
        if (list.Any(x => x.Id.Equals(row.Id, StringComparison.OrdinalIgnoreCase))) return Results.Conflict(new { error = "Duplicate gateway ID" });
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
        var before = externalAuditIntent is null ? Array.Empty<byte>() : AuditStateBytes(fleetPath);
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
                System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
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
async Task<List<string>> RollbackAttempted(string logPath, JsonObject journal, List<FleetGateway> gateways)
{
    var errors = new List<string>();
    foreach (var target in FleetRolloutJournal.Targets(journal).Where(FleetRolloutJournal.NeedsRollback))
    {
        var id = target["id"]!.GetValue<string>();
        try
        {
            var row = gateways.Single(x => x.Id == id);
            FleetRolloutJournal.Log(logPath, journal, id, "rollback", "dispatching");
            using var client = CreateFleetClient(row);
            using var response = await client.PostAsJsonAsync(new Uri(new Uri(row.Url), "agent/v1/config/rollback"),
                new { TransactionId = journal["id"]!.GetValue<string>() });
            response.EnsureSuccessStatusCode();
            var reply = JsonNode.Parse(await response.Content.ReadAsStringAsync());
            using var status = await client.GetAsync(new Uri(new Uri(row.Url), "agent/v1/status"));
            status.EnsureSuccessStatusCode();
            var observed = JsonNode.Parse(await status.Content.ReadAsStringAsync())?["revision"]?.ToString();
            if (reply?["state"]?.ToString() != "rolled-back" || reply["rollbackFenced"]?.GetValue<bool>() != true ||
                reply["revision"]?.ToString() != observed ||
                !FleetRolloutJournal.CompleteRollback(target, observed))
                throw new InvalidOperationException("Rollback revision not independently confirmed");
            FleetRolloutJournal.Log(logPath, journal, id, "rollback", "verified", observed);
        }
        catch (Exception ex)
        {
            errors.Add(id + ": " + ex.GetType().Name);
            FleetRolloutJournal.Log(logPath, journal, id, "rollback", "unresolved", ex.GetType().Name);
        }
    }
    journal["status"] = errors.Count == 0 ? "rollback-verified" : "manual-intervention-required";
    FleetRolloutJournal.Log(logPath, journal, "fleet", "finish", journal["status"]!.GetValue<string>());
    return errors;
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
        var fleetDigest = FleetDigest();
        var proxy = new JsonObject { ["Routes"] = routes.DeepClone(), ["Clusters"] = clusters.DeepClone() };
        var signingKeyPath = Path.Combine(privateDir, "fleet-signing-private.pem");
        if (!File.Exists(signingKeyPath))
            return Results.Conflict(new { error = "Fleet signing key not provisioned" });
        var signingKeyPem = await File.ReadAllTextAsync(signingKeyPath, ctx.RequestAborted);
        var targets = new JsonArray();
        // Preflight every target before authorizing or dispatching any mutation.
        foreach (var row in gateways)
        {
            using var client = CreateFleetClient(row);
            using var statusResponse = await client.GetAsync(new Uri(new Uri(row.Url), "agent/v1/status"), ctx.RequestAborted);
            statusResponse.EnsureSuccessStatusCode();
            var status = JsonNode.Parse(await statusResponse.Content.ReadAsStringAsync(ctx.RequestAborted));
            var revision = status?["revision"]?.ToString();
            if (!FleetRolloutJournal.IsDigest(revision) || status?["rollbackFenceProtocol"]?.GetValue<int>() != 1)
                throw new InvalidOperationException("Agent configuration revision unavailable");
            targets.Add(new JsonObject { ["id"] = row.Id, ["originalRevision"] = revision,
                ["prepareSent"] = false, ["activateSent"] = false, ["rollbackVerified"] = false });
        }
        journal = new JsonObject { ["schema"] = 2, ["id"] = txId, ["changeId"] = changeId,
            ["initiator"] = Actor(ctx), ["createdUtc"] = DateTimeOffset.UtcNow.ToString("O"),
            ["status"] = "starting", ["fleetDigest"] = fleetDigest,
            ["changeDigest"] = Convert.ToHexString(SHA256.HashData(changeBytes)), ["targets"] = targets,
            ["details"] = new JsonArray() };
        var initial = JsonSerializer.SerializeToUtf8Bytes(journal);
        var denied = await ConfirmStateMutation(ctx, logPath, Array.Empty<byte>(), initial, "FLEET_ROLLOUT_INTENT", true);
        if (denied is not null) return denied;
        async Task<bool> CurrentPlan() => await AuditActorCurrent(ctx, true) && !ctx.RequestAborted.IsCancellationRequested &&
            OnboardingApi.IsMultiGatewayDesign(privateDir) && FleetDigest() == fleetDigest &&
            File.Exists(changePath) && File.ReadAllBytes(changePath).AsSpan().SequenceEqual(changeBytes);
        if (!await CurrentPlan()) return Results.Conflict(new { error = "Rollout authorization or plan changed" });
        WriteAuditedState(logPath, initial);
        persisted = true;
        var sequence = FleetSequenceState.AllocateNext(Path.Combine(privateDir, "fleet-sequence.txt"));
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
            target["activateSent"] = true;
            FleetRolloutJournal.Log(logPath, journal, row.Id, "activate", "dispatching");
            using var response = await client.PostAsJsonAsync(new Uri(new Uri(row.Url), "agent/v1/config/activate"),
                new { TransactionId = txId, PreparedRevision = prepared }, ctx.RequestAborted);
            response.EnsureSuccessStatusCode();
            var activated = JsonNode.Parse(await response.Content.ReadAsStringAsync(ctx.RequestAborted));
            if (activated?["transactionId"]?.ToString() != txId || activated["revision"]?.ToString() != prepared)
                throw new InvalidOperationException("Invalid activation acknowledgment");
            FleetRolloutJournal.Log(logPath, journal, row.Id, "activate", "ok", prepared);
        }
        journal["status"] = "activated-pending-health-validation";
        FleetRolloutJournal.Log(logPath, journal, "fleet", "finish", "activation-complete", "Live application health is not verified");
        await Audit(Actor(ctx), "FLEET_ROLLOUT_ACTIVATED", new { txId, changeId });
        return Results.Ok(journal);
    }
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
        System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine);
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
app.MapOnboardingApi(privateDir, ConfirmStateMutation, WriteAuditedState, Audit);
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
app.MapReverseProxy(proxyPipeline =>
{
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
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
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
        var policy = state.Policy;

        var applicationStopping = context.RequestServices.GetRequiredService<IHostApplicationLifetime>().ApplicationStopping;
        using var waitCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted,
            applicationStopping);
        DestinationAdmissionState.DestinationAdmissionLease? lease;
        try
        {
            lease = await state.AcquireAsync(waitCancellation.Token,
                TimeSpan.FromMilliseconds(policy.QueueTimeoutMs));
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
record OtpChallenge(string Username, string Nonce, string Hash, DateTimeOffset ExpiresAt, int Attempts);
record MailSettings(bool Enabled = false, string Host = "", int Port = 25, string From = "", string Username = "", string EncryptedPassword = "", bool StartTls = false,
    string AuthMode = "password", string OAuthClientId = "", string EncryptedOAuthClientSecret = "", string EncryptedOAuthRefreshToken = "", string OAuthTenant = "");
record MailSettingsInput(bool Enabled, string Host, int Port, string From, string Username, string Password, bool StartTls,
    string AuthMode = "password", string OAuthClientId = "", string OAuthClientSecret = "", string OAuthRefreshToken = "", string OAuthTenant = "");
record UserInput(string Username, string Role, string Password, string? Email);
record PasswordInput(string Password);
record ChangeDecision(string Decision, string? Reason);
record InventoryInput(string Id, string Name, string Type, string Address, string Notes);
record AdminUser(string Username, string Role, string Salt, string Hash, string? Email = null, bool Enabled = true, string SecurityStamp = "", string Provider = "Local", string DistinguishedName = "", long OidcRevokedBefore = 0, long OidcLogoutAuditThrough = 0);

record FleetGateway(string Id, string Url, string ClientCertificateThumbprint);

sealed record GatewayDestinationHealthRow(string ClusterId, string DestinationId, string ActiveHealth,
    string PassiveHealth, int InflightRequests, long Requests, long Http4xx, long Http5xx);
