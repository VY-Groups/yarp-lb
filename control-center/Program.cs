Warning: truncated output (original token count: 27626)
Total output lines: 1797

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
if (!OperatingSystem.IsLinux() || ec2Lab)
    Directory.CreateDirectory(privateDir);
var keyDir = Path.Combine(privateDir, "data-protection-keys");
if (!OperatingSystem.IsLinux() || ec2Lab)
    Directory.CreateDirectory(keyDir);
var builder = WebApplication.CreateBuilder(args);
GatewayOpenTelemetry.Configure(builder.Services);
// Explicit v0.1 multi-socket mode; legacy loopback remains CI migration-only.
var isolatedListeners = GatewayListenerIsolation.FromEnvironment();
isolatedListeners?.Configure(builder.WebHost);
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
    .ConfigureHttpClient(BackendMutualTls.Configure);
// Custom policies are registered on every serving YARP instance, never on the UI alone.
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, PrimaryBackupPolicy>();
// Poll YARP active-health state independently of incoming requests.
builder.Services.AddHostedService<AutonomousRecoveryObserver>();
// Opt-in by cluster.HealthCheck.Passive.Policy only. No request replay.
builder.Services.AddSingleton<IPassiveHealthCheckPolicy, BoundedTransportFailureHealthPolicy>();
builder.Services.AddSingleton<IActiveHealthCheckPolicy, RiseFallActiveHealthPolicy>();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "GatewayCoreYarpAdmin";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
        options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest; // local HTTP TEST only; mandate HTTPS for remote administration
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
    builder.Services.AddHttpClient("peer-sync", client => client.Timeout = TimeSpan.FromSeconds(5))
        .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler {
            AllowAutoRedirect = false, UseCookies = false
        });
    builder.Services.AddHostedService<PeerSyncPublisher>();
}
var app = builder.Build();
var accessLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayCore.AccessLog");
var trustedAccessLogProxies = GatewayClientAddress.ParseTrustedProxyAddresses(
    Environment.GetEnvironmentVariable("GATEWAY_TRUSTED_PROXY_IPS"));
var peerStateJournal = app.Services.GetService<PeerStateJournal>();
var peerSigner = app.Services.GetService<PeerSignedMessages>();
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
var protector = app.Services.GetRequiredService<IDataProtectionProvider>().CreateProtector("GatewayCoreYarp.AdminMail.v1");
MailSettings ReadMail() => File.Exists(mailPath)
    ? JsonSerializer.Deserialize<MailSettings>(File.ReadAllText(mailPath), jsonOptions) ?? new MailSettings()
    : new MailSettings();
string MailFingerprint(MailSettings cfg) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
    $"{cfg.Host.ToLowerInvariant()}|{cfg.Port}|{cfg.From.ToLowerInvariant()}|{cfg.Username}|{cfg.StartTls}|{cfg.EncryptedPassword}|{cfg.AuthMode}|{cfg.OAuthClientId}|{cfg.OAuthTenant}|{cfg.EncryptedOAuthClientSecret}|{cfg.EncryptedOAuthRefreshToken}")));
bool MailDeliveryVerified(MailSettings cfg) => File.Exists(mailProofPath) &&
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(File.ReadAllText(mailProofPath).Trim()),
        Encoding.UTF8.GetBytes(MailFingerprint(cfg)));
async Task SendMailMessage(string recipient, string subject, string body)
{
    var cfg = ReadMail();
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
                errors, string.Join(",", chain?.ChainStatus.Select(x …19626 tokens truncated…ion=status?["revision"]?.ToString();
            if (string.IsNullOrWhiteSpace(revision)) throw new InvalidOperationException(row.Id+": no revision / deployment disabled");
            var expires = DateTimeOffset.UtcNow.AddMinutes(3).ToUnixTimeSeconds();
            var signed = FleetConfigSignature.SignV2(signingKeyPem, txId, revision, proxy, expires, sequence);
            using var response=await client.PostAsJsonAsync(new Uri(new Uri(row.Url),"agent/v1/config/prepare"),
                new {TransactionId=txId,ExpectedRevision=revision,ReverseProxy=proxy,
                    signed.ExpiresUnixSeconds, signed.Sequence, signed.KeyId, signed.Signature});
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException(row.Id+": prepare HTTP "+(int)response.StatusCode);
            var staged=JsonNode.Parse(await response.Content.ReadAsStringAsync());
            var revisionStaged=staged?["preparedRevision"]?.ToString();
            if (string.IsNullOrWhiteSpace(revisionStaged)) throw new InvalidOperationException("Missing staged hash");
            prepared.Add((row,revisionStaged));
            await Log(row.Id,"prepare","ok",revisionStaged);
        }
        foreach (var item in prepared)
        {
            using var client=CreateFleetClient(item.Gateway);
            using var response=await client.PostAsJsonAsync(new Uri(new Uri(item.Gateway.Url),"agent/v1/config/activate"),
                new {TransactionId=txId,PreparedRevision=item.Revision});
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException(item.Gateway.Id+": activation HTTP "+(int)response.StatusCode);
            await Log(item.Gateway.Id,"activate","ok");
        }
        result["status"]="activated-pending-health-validation";
        await Log("fleet","finish","activation-complete","Verify real application health and failover before treating as successful");
        await Audit(Actor(ctx),"FLEET_ROLLOUT_ACTIVATED",new {txId,changeId});
        return Results.Ok(result);
    }
    catch(Exception ex)
    {
        var rollbackErrors=new List<string>();
        foreach(var row in gateways)
        {
            try
            {
                using var client=CreateFleetClient(row);
                using var response=await client.PostAsJsonAsync(new Uri(new Uri(row.Url),"agent/v1/config/rollback"),
                    new {TransactionId=txId});
                if (!response.IsSuccessStatusCode) rollbackErrors.Add(row.Id+": HTTP "+(int)response.StatusCode);
                await Log(row.Id,"rollback",response.IsSuccessStatusCode?"ok":"failed");
            }
            catch(Exception rollbackEx)
            {rollbackErrors.Add(row.Id+": "+rollbackEx.GetType().Name);await Log(row.Id,"rollback","failed",rollbackEx.GetType().Name);}
        }
        result["status"]=rollbackErrors.Count==0?"rollback-attempted":"manual-intervention-required";
        await Log("fleet","error","failed",ex.GetType().Name+"; "+string.Join("; ",rollbackErrors));
        await Audit(Actor(ctx),"FLEET_ROLLOUT_FAILED",new {txId,changeId,rollbackErrors});
        return Results.Json(new {transactionId=txId,status=result["status"]?.ToString(),
            error="Deployment failed. Inspect journal and verify both gateways.",rollbackErrors},statusCode:502);
    }
    finally {rolloutGate.Release();}
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
    return new HttpClient(handler,disposeHandler:true) {Timeout=TimeSpan.FromSeconds(8)};
}

// Version 0.1 setup APIs and independently verified YARP runtime state.
app.MapSetupCenter(privateDir);
app.MapCapabilityRegistry();
app.MapOnboardingApi(privateDir);
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
        if (!peerStateJournal.Apply(frame, PeerStateJournal.CurrentMinute()))
            return Results.StatusCode(409);
        return Results.NoContent();
    });
}
app.MapOrganizationProfile(privateDir);
app.MapTlsInventory();
app.MapReverseProxy(proxyPipeline =>
{
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
        var clock = System.Diagnostics.Stopwatch.GetTimestamp();
        var activity = GatewayOpenTelemetry.StartProxyActivity(context);
        try
        {
            await next();
        }
        catch (Exception ex)
        {
            GatewayOpenTelemetry.RecordProxyException(activity, ex);
            throw;
        }
        finally
        {
            var elapsedMs = (System.Diagnostics.Stopwatch.GetTimestamp() - clock) * 1000.0 /
                System.Diagnostics.Stopwatch.Frequency;
            var feature = context.GetReverseProxyFeature();
            var destination = feature.ProxiedDestination;
            GatewayOpenTelemetry.CompleteProxyActivity(activity, context, destination?.DestinationId);
            GatewayOpenTelemetry.RecordProxyResult(context, elapsedMs);
            if (destination != null)
            {
                var id = feature.Cluster.Config.ClusterId + "/" + destination.DestinationId;
                var stats = destinationTelemetry.GetOrAdd(id, _ => new DestinationCounters());
                stats.Record(context.Response.StatusCode, elapsedMs);
            }
        }
    });
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
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
record AdminUser(string Username, string Role, string Salt, string Hash, string? Email = null, bool Enabled = true, string SecurityStamp = "", string Provider = "Local", string DistinguishedName = "");

record FleetGateway(string Id, string Url, string ClientCertificateThumbprint);

// Managed destination metrics: no request paths, tokens, subjects or other high-cardinality labels.
sealed class DestinationCounters
{
    public long Requests, ServerErrors, ClientErrors, TotalMicros;
    public double MeanLatencyMs => Interlocked.Read(ref Requests) is var r && r > 0
        ? Interlocked.Read(ref TotalMicros) / 1000.0 / r : 0;
    public void Record(int status, double elapsedMs)
    {
        Interlocked.Increment(ref Requests);
        if (status >= 500) Interlocked.Increment(ref ServerErrors);
        else if (status >= 400) Interlocked.Increment(ref ClientErrors);
        Interlocked.Add(ref TotalMicros, (long)(elapsedMs * 1000));
    }
}

sealed record GatewayDestinationHealthRow(string ClusterId, string DestinationId, string ActiveHealth,
    string PassiveHealth, int InflightRequests, long Requests, long Http4xx, long Http5xx);

