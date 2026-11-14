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
// Opt-in by cluster.HealthCheck.Passive.Policy only. No request replay.
builder.Services.AddSingleton<IPassiveHealthCheckPolicy, BoundedTransportFailureHealthPolicy>();
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
var app = builder.Build();
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
    $"{cfg.Host.ToLowerInvariant()}|{cfg.Port}|{cfg.From.ToLowerInvariant()}|{cfg.Username}|{cfg.StartTls}|{cfg.EncryptedPassword}")));
bool MailDeliveryVerified(MailSettings cfg) => File.Exists(mailProofPath) &&
    CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(File.ReadAllText(mailProofPath).Trim()),
        Encoding.UTF8.GetBytes(MailFingerprint(cfg)));
async Task SendMailMessage(string recipient, string subject, string body)
{
    var cfg = ReadMail();
    if (string.IsNullOrWhiteSpace(cfg.Host) || cfg.Port is < 1 or > 65535 ||
        cfg.Port == 465 || !ValidEmail(cfg.From) || !ValidEmail(recipient))
        throw new InvalidOperationException("SMTP host, supported port, sender and recipient must be configured.");
    // SmtpClient supports STARTTLS, but not implicit TLS on port 465.
    // In a CA environment, authenticated SMTP must never send credentials in cleartext.
    if (!cfg.StartTls) throw new InvalidOperationException("STARTTLS is required for management OTP mail.");
    using var smtp = new SmtpClient(cfg.Host, cfg.Port) { EnableSsl = true, Timeout = 10000 };
    if (!string.IsNullOrWhiteSpace(cfg.Username))
        smtp.Credentials = new NetworkCredential(cfg.Username, protector.Unprotect(cfg.EncryptedPassword));
    using var message = new MailMessage(cfg.From, recipient, subject, body);
    await smtp.SendMailAsync(message);
}
async Task SendOtp(string recipient, string code)
{
    if (!ReadMail().Enabled) throw new InvalidOperationException("OTP not enabled");
    await SendMailMessage(recipient, "YARP Control Center sign-in code",
        $"Your one-time sign-in code is {code}. It expires in 5 minutes. Do not share this code.");
}
var configPath = applicationConfigPath;
var auditPath = Path.Combine(privateDir, "admin-audit.jsonl");
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
            if (!ctx.Request.HasJsonContentType()) { ctx.Response.StatusCode = 415; return; }
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
app.Use(async (ctx, next) =>
{
    if (ctx.Request.Path.StartsWithSegments("/admin") || ctx.Request.Path.StartsWithSegments("/dashboard") ||
        ctx.Request.Path.StartsWithSegments("/gateway")) { await next(); return; }
    var started = System.Diagnostics.Stopwatch.GetTimestamp();
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
    }
});
var destinationTelemetry = new ConcurrentDictionary<string, DestinationCounters>();
app.MapGet("/admin/api/destination-metrics", () => Results.Ok(new {
    scope = "This gateway instance; routed requests only; counters reset after restart",
    timestampUtc = DateTimeOffset.UtcNow,
    destinations = destinationTelemetry.OrderBy(x => x.Key).Select(x => new {
        id = x.Key, requests = Interlocked.Read(ref x.Value.Requests),
        failures5xx = Interlocked.Read(ref x.Value.ServerErrors),
        clientErrors4xx = Interlocked.Read(ref x.Value.ClientErrors),
        meanLatencyMs = x.Value.MeanLatencyMs
    }).ToArray()
})).RequireAuthorization();
app.MapGet("/admin/api/metrics", () =>
{
    var total = Interlocked.Read(ref requestsTotal);
    var elapsed = Interlocked.Read(ref durationTicks);
    return Results.Ok(new { gateway = Environment.MachineName, collectedUtc = DateTimeOffset.UtcNow,
       totalRequests = total, success2xx = Interlocked.Read(ref requests2xx),
       clientErrors4xx = Interlocked.Read(ref requests4xx), serverErrors5xx = Interlocked.Read(ref requests5xx),
       meanDurationMs = total == 0 ? 0 : Math.Round(elapsed * 1000.0 / System.Diagnostics.Stopwatch.Frequency / total, 2),
       scope = "local process; all non-administrative HTTP requests; includes YARP and unmatched paths; resets on restart" });
}).RequireAuthorization();
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
    output.AppendLine("# HELP yarp_logging_dropped_high_priority_total Warning/Error console messages dropped");
    output.AppendLine("# TYPE yarp_logging_dropped_high_priority_total counter");
    output.Append("yarp_logging_dropped_high_priority_total ").Append(boundedConsole.DroppedHighPriorityMessages).Append('\n');
    output.AppendLine("# HELP yarp_logging_write_errors_total Console writer failures");
    output.AppendLine("# TYPE yarp_logging_write_errors_total counter");
    output.Append("yarp_logging_write_errors_total ").Append(boundedConsole.WriteErrors).Append('\n');
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
    foreach (var pair in destinationTelemetry)
    {
        var escaped = pair.Key.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        output.Append("yarp_control_destination_requests_total{destination=\"").Append(escaped)
            .Append("\"} ").Append(Interlocked.Read(ref pair.Value.Requests)).Append('\n');
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
        if (string.IsNullOrWhiteSpace(token) ||
            !CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(token), Encoding.UTF8.GetBytes(provided)))
        { ctx.Response.StatusCode = 403; return; }
        if (ctx.User.IsInRole("Viewer")) { ctx.Response.StatusCode = 403; return; }
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
    var tmp = usersPath + ".tmp";
    File.WriteAllText(tmp, JsonSerializer.Serialize(users));
    File.Move(tmp, usersPath, true);
}
async Task Audit(string actor, string action, object? details = null)
{
    await File.AppendAllTextAsync(auditPath,
        JsonSerializer.Serialize(new { utc = DateTimeOffset.UtcNow, actor, action, details }) + Environment.NewLine);
}
IResult SignInResult(AdminUser user, HttpContext ctx)
{
    return Results.Ok(new { authenticated = true, username = user.Username, role = user.Role });
}
async Task SignIn(AdminUser user, HttpContext ctx)
{
    var claims = new[] {
        new Claim(ClaimTypes.Name, user.Username),
        new Claim(ClaimTypes.Role, user.Role),
        new Claim("csrf", Convert.ToHexString(RandomNumberGenerator.GetBytes(32))),
        new Claim("stamp", user.SecurityStamp)
    };
    await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme)));
}

app.MapGet("/admin/api/session", (HttpContext ctx) => Results.Ok(new {
    initialized = ReadUsers().Count != 0,
    authenticated = ctx.User.Identity?.IsAuthenticated == true,
    username = ctx.User.Identity?.Name,
    role = ctx.User.FindFirst(ClaimTypes.Role)?.Value,
    csrf = ctx.User.FindFirst("csrf")?.Value,
    mode = "Local administrative test console — not certified for CA production"
}));

app.MapPost("/admin/api/bootstrap", async (HttpContext ctx, LoginInput input) =>
{
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
    local = true, activeDirectory = directoryAuth.Read().Enabled,
    mailOtp = ReadMail().Enabled,
    info = "AD sign-in requires LDAPS, mapped groups and email OTP"
}));

app.MapPost("/admin/api/login", async (HttpContext ctx, LoginInput input) =>
{
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
    var mail = ReadMail();
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
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
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
        var users = ReadUsers();
        if (users.Any(x => x.Username.Equals(input.Username, StringComparison.OrdinalIgnoreCase)))
            return Results.Conflict(new { error = "Username exists" });
        users.Add(NewUser(input.Username, input.Role, input.Password, input.Email));
        WriteUsers(users);
        await Audit(Actor(ctx), "USER_CREATED", new { input.Username, input.Role });
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
        var users = ReadUsers();
        var user = users.FirstOrDefault(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (user is null) return Results.NotFound();
        if (user.Provider == "AD") return Results.BadRequest(new { error = "Reset directory passwords in Active Directory, not this console" });
        var updated = NewUser(user.Username, user.Role, input.Password, user.Email) with { Enabled = user.Enabled };
        users[users.IndexOf(user)] = updated;
        WriteUsers(users);
        await Audit(Actor(ctx), "PASSWORD_RESET", new { username });
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
        var users = ReadUsers(); var i = users.FindIndex(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return Results.NotFound();
        if (users[i].Role == "Administrator" && users.Count(x => x.Enabled && x.Role == "Administrator") <= 1)
            return Results.BadRequest(new { error = "Last active administrator cannot be disabled" });
        users[i] = users[i] with { Enabled = false, SecurityStamp = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) }; WriteUsers(users);
        await Audit(Actor(ctx), "USER_OFFBOARDED", new { username });
        return Results.Ok(new { disabled = username });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/users/{username}/enable", async (HttpContext ctx, string username) =>
{
    await loginGate.WaitAsync();
    try
    {
        var users = ReadUsers(); var i = users.FindIndex(x => x.Username.Equals(username, StringComparison.OrdinalIgnoreCase));
        if (i < 0) return Results.NotFound();
        users[i] = users[i] with { Enabled = true, SecurityStamp = Convert.ToHexString(RandomNumberGenerator.GetBytes(24)) }; WriteUsers(users);
        await Audit(Actor(ctx), "USER_REENABLED", new { username });
        return Results.Ok(new { enabled = username });
    }
    finally { loginGate.Release(); }
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/mail", () => {
    var m = ReadMail();
    return Results.Ok(new { m.Enabled, m.Host, m.Port, m.From, m.Username, m.StartTls,
        passwordConfigured = !string.IsNullOrEmpty(m.EncryptedPassword), deliveryVerified = MailDeliveryVerified(m) });
}).RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/mail", async (HttpContext ctx, MailSettingsInput input) =>
{
    if (input.Host is null || input.From is null || input.Username is null || input.Password is null ||
        input.Port is < 1 or > 65535 || input.Port == 465 || input.Host.Length > 255 || input.From.Length > 254 || input.Username.Length > 254 ||
        (input.Enabled && (string.IsNullOrWhiteSpace(input.Host) || !ValidEmail(input.From) || !input.StartTls)))
        return Results.BadRequest(new { code = "SMTP_INVALID_SETTINGS", error = "Check SMTP host, port (465 unsupported), sender address, and STARTTLS before enabling OTP." });
    var existing = ReadMail();
    var encrypted = string.IsNullOrEmpty(input.Password) ? existing.EncryptedPassword : protector.Protect(input.Password);
    var mail = new MailSettings(input.Enabled, input.Host, input.Port, input.From, input.Username, encrypted, input.StartTls);
    if (input.Enabled && !MailDeliveryVerified(mail))
        return Results.Json(new { code = "SMTP_TEST_REQUIRED", error = "Save SMTP settings with OTP disabled, send a successful test to the administrator email, then enable OTP." }, statusCode: 409);
    File.WriteAllText(mailPath + ".tmp", JsonSerializer.Serialize(mail)); File.Move(mailPath + ".tmp", mailPath, true);
    await Audit(Actor(ctx), "MAIL_SETTINGS_UPDATED", new { input.Enabled, input.Host, input.Port, input.StartTls });
    return Results.Ok(new { saved = true, otpRequiredOnNextLogin = mail.Enabled });
}).RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapPost("/admin/api/mail/test", async (HttpContext ctx) =>
{
    var admin = ReadUsers().FirstOrDefault(x => x.Username.Equals(Actor(ctx), StringComparison.OrdinalIgnoreCase));
    if (admin is null || !ValidEmail(admin.Email)) return Results.BadRequest(new { code = "SMTP_ADMIN_EMAIL_REQUIRED", error = "Set a valid administrator email under Administrators and roles before sending a test." });
    try
    {
        var cfg = ReadMail();
        if (string.IsNullOrWhiteSpace(cfg.Host) || !ValidEmail(cfg.From) || !cfg.StartTls)
            return Results.Json(new { code = "SMTP_NOT_CONFIGURED", error = "Save a valid SMTP relay, sender, and STARTTLS configuration with OTP disabled before testing." }, statusCode: 409);
        await SendMailMessage(admin.Email!, "YARP Control Center SMTP test", "This is a test message from your local YARP administration console.");
        File.WriteAllText(mailProofPath + ".tmp", MailFingerprint(cfg));
        File.Move(mailProofPath + ".tmp", mailProofPath, true);
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
        app.Logger.LogWarning("SMTP_DELIVERY_TEST_FAILED errorType={ErrorType} innerType={InnerType}",
            failureType, innerType);
        await Audit(Actor(ctx), "SMTP_DELIVERY_TEST_FAILED", new { failureType, innerType });
        return Results.Json(new { code = "SMTP_RELAY_UNAVAILABLE", error = "SMTP relay test failed. Check reachability, STARTTLS certificate trust, credentials and relay permissions. No OTP settings were enabled." }, statusCode: 503);
    }
}).RequireRateLimiting("mailtest").RequireAuthorization(p => p.RequireRole("Administrator"));

app.MapGet("/admin/api/directory", () => Results.Ok(directoryAuth.PublicSettings()))
    .RequireAuthorization(p => p.RequireRole("Administrator"));
app.MapPost("/admin/api/directory", async (HttpContext ctx, DirectorySettingsInput input) =>
{
    if (input.Enabled && (!ReadMail().Enabled || !MailDeliveryVerified(ReadMail())))
        return Results.BadRequest(new { error = "Enable verified SMTP email OTP before enabling AD login" });
    try
    {
        directoryAuth.Save(input);
        await Audit(Actor(ctx), "DIRECTORY_SETTINGS_UPDATED", new { input.Enabled, input.Host, input.Port, input.SearchBaseDn });
        return Results.Ok(new { saved = true, enabled = input.Enabled, note = "Existing AD sessions are revalidated on requests" });
    }
    catch (Exception ex) when (ex is ArgumentException or LdapException or InvalidOperationException or DirectoryOperationException)
    { return Results.BadRequest(new { error = "LDAPS configuration not accepted: check hostname, certificate, bind identity, base DN and mapped group DNs" }); }
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
        var entries = ReadInventory();
        if (entries.Any(x => x.Id == input.Id)) return Results.Conflict(new { error = "ID already exists" });
        entries.Add(input);
        File.WriteAllText(inventoryPath, JsonSerializer.Serialize(entries));
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
        var items = ReadInventory();
        var changed = items.RemoveAll(x => x.Id == id);
        if (changed == 0) return Results.NotFound();
        File.WriteAllText(inventoryPath, JsonSerializer.Serialize(items));
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
// Readiness is on the DATA listener only in isolated mode; unknown/empty backends fail closed.
app.MapGet("/gateway/health/ready", (IProxyStateLookup proxy) =>
    GatewayListenerIsolation.AnyDestinationHealthy(proxy)
        ? Results.Ok(new { ready = true })
        : Results.StatusCode(503));

JsonObject ReadConfig() => JsonNode.Parse(File.ReadAllText(configPath))!.AsObject();
JsonObject ReadProxy() => (ReadConfig()["ReverseProxy"]?.DeepClone() as JsonObject) ?? new JsonObject();

app.MapGet("/admin/api/state", () =>
{
    var proxy = ReadProxy();
    var disabled = (proxy["AdminDisabledDestinations"] as JsonObject)?.DeepClone() as JsonObject ?? new JsonObject();
    proxy.Remove("AdminDisabledDestinations");
    return Results.Ok(new { name = "YARP Control Center", gateway = "online", time = DateTimeOffset.UtcNow,
        routes = proxy["Routes"] ?? new JsonObject(), clusters = proxy["Clusters"] ?? new JsonObject(), disabled,
        mode = "Authenticated local management", telemetry = "Local HTTP counters only; no backend or fleet metrics", revision = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(configPath))) });
}).RequireAuthorization();

app.MapGet("/admin/api/audit", () =>
{
    if (!File.Exists(auditPath)) return Results.Ok(Array.Empty<object>());
    var entries = File.ReadLines(auditPath).TakeLast(80).Reverse().Select(x => JsonNode.Parse(x)).ToArray();
    return Results.Ok(entries);
}).RequireAuthorization();

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
async Task<IResult> CommitReviewedChange(HttpContext ctx, JsonObject submitted)
{
    var routes = submitted["routes"] as JsonObject;
    var clusters = submitted["clusters"] as JsonObject;
    var disabled = submitted["disabled"] as JsonObject ?? new JsonObject();
    var expectedRevision = submitted["revision"]?.ToString() ?? "";
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
        if (policy is not ("RoundRobin" or "PowerOfTwoChoices" or "LeastRequests" or "Random" or "FirstAlphabetical" or "WeightedRandom" or "SourceIpHash")) return Results.BadRequest(new { error = "Unsupported load-balancing policy" });
        if (c["Destinations"] is not JsonObject dests || dests.Count > 40) return Results.BadRequest(new { error = "Invalid destinations" });
        foreach (var (destId, node) in dests)
        {
            if (!ValidId(destId) || !ValidAddress(node?["Address"]?.ToString()))
                return Results.BadRequest(new { error = $"Invalid destination {destId} in {key}" });
            if (node?["Metadata"]?["Weight"] is JsonNode weightValue &&
                !LoadBalancingCore.TryWeight(weightValue.ToString(), out _))
                return Results.BadRequest(new { error = $"Destination {destId} Weight must be integer 1..100" });
            var trafficState = node?["Metadata"]?["TrafficState"]?.ToString() ?? "active";
            if (trafficState is not ("active" or "draining"))
                return Results.BadRequest(new { error = $"Destination {destId} TrafficState must be active or draining" });
            if (node?["Metadata"]?["SlowStartSeconds"] is JsonNode secondsNode &&
                !LoadBalancingCore.TrySlowStartSeconds(secondsNode.ToString(), out _))
                return Results.BadRequest(new { error = $"Destination {destId} SlowStartSeconds must be 0..600" });
        }
        if (c["Metadata"]?[BackendMutualTls.MetadataKey] is JsonNode clientCertificate)
        {
            if (!BackendMutualTls.TryNormalizeThumbprint(clientCertificate.ToString(), out _))
                return Results.BadRequest(new { error = $"Cluster {key}: client certificate thumbprint must be 40 hex characters" });
            if (dests.Any(d => !(d.Value?["Address"]?.ToString() ?? "").StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
                return Results.BadRequest(new { error = $"Cluster {key}: backend mTLS requires all HTTPS destinations" });
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
    await gate.WaitAsync();
    try
    {
        var currentRevision = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(configPath)));
        if (!string.Equals(expectedRevision, currentRevision, StringComparison.Ordinal))
            return Results.Conflict(new { error = "Configuration changed since loading. Refresh before saving." });
        var doc = ReadConfig();
        var proxy = (doc["ReverseProxy"] as JsonObject) ?? new JsonObject();
        proxy["Routes"] = routes.DeepClone();
        proxy["Clusters"] = clusters.DeepClone();
        proxy["AdminDisabledDestinations"] = disabled.DeepClone();
        doc["ReverseProxy"] = proxy;
        Directory.CreateDirectory(backupFolder);
        var stamp = DateTimeOffset.UtcNow.ToString("yyyyMMddTHHmmssfffffffZ");
        var backup = Path.Combine(backupFolder, $"appsettings-{stamp}.json");
        File.Copy(configPath, backup, overwrite: false);
        var temp = configPath + ".tmp";
        await File.WriteAllTextAsync(temp, doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temp, configPath, overwrite: true);
        await Audit(Actor(ctx), "CONFIG_APPLIED", new { routes = routes.Count, clusters = clusters.Count, backup = Path.GetFileName(backup) });
        return Results.Ok(new { saved = true, backup = Path.GetFileName(backup), message = "Saved to appsettings.json; YARP config reload typically occurs automatically. Verify gateway logs." });
    }
    catch (Exception) { return Results.Problem("Configuration write failed. Check server logs."); }
    finally { gate.Release(); }
}

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
    await changeGate.WaitAsync();
    try { await File.WriteAllTextAsync(Path.Combine(changeFolder, id + ".json"), item.ToJsonString()); }
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
        var item = JsonNode.Parse(await File.ReadAllTextAsync(path))!.AsObject();
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
        await File.WriteAllTextAsync(path + ".tmp", item.ToJsonString());
        File.Move(path + ".tmp", path, overwrite: true);
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
List<FleetGateway> ReadFleet() => File.Exists(fleetPath)
    ? JsonSerializer.Deserialize<List<FleetGateway>>(File.ReadAllText(fleetPath), jsonOptions) ?? new()
    : new();
void WriteFleet(List<FleetGateway> rows)
{
    var temp = fleetPath + ".tmp";
    File.WriteAllText(temp, JsonSerializer.Serialize(rows));
    File.Move(temp, fleetPath, true);
}
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
        var list = ReadFleet();
        if (list.Any(x => x.Id.Equals(row.Id, StringComparison.OrdinalIgnoreCase))) return Results.Conflict(new { error = "Duplicate gateway ID" });
        list.Add(row); WriteFleet(list);
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
        var list = ReadFleet();
        if (list.RemoveAll(x => x.Id == id) != 1) return Results.NotFound();
        WriteFleet(list);
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
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(4) };
            using var response = await client.GetAsync(new Uri(new Uri(row.Url), "agent/v1/status"));
            if (!response.IsSuccessStatusCode)
            { responses.Add(new { row.Id, state = "http-error", httpStatus = (int)response.StatusCode }); continue; }
            var result = await response.Content.ReadAsStringAsync();
            responses.Add(new { row.Id, state = "connected", report = JsonNode.Parse(result) });
        }
        catch (Exception ex)
        { responses.Add(new { row.Id, state = "unavailable", errorType = ex.GetType().Name }); }
    }
    return Results.Ok(new { checkedUtc = DateTimeOffset.UtcNow, type = "mTLS authenticated agent reports; not authoritative YARP destination health", gateways = responses });
}).RequireAuthorization();

// Per-destination request observations are recorded after YARP chooses its target.
// Counters are process-local, not durable, and health is reported separately.

// Controlled fleet rollout: the only accepted payload comes from a previously
// approved two-person local change request. Every agent validates its revision.
// No general-purpose remote shell or arbitrary filesystem access is exposed.
var rolloutGate = new SemaphoreSlim(1, 1);
var rolloutFolder = Path.Combine(privateDir, "fleet-rollouts");
Directory.CreateDirectory(rolloutFolder);
app.MapPost("/admin/api/fleet/rollout/{changeId}", async (HttpContext ctx, string changeId) =>
{
    if (!Regex.IsMatch(changeId, "^change-[0-9]{8}T[0-9]{13,}Z-[A-F0-9]{10}$"))
        return Results.BadRequest(new { error = "Invalid change ID" });
    var changePath = Path.Combine(changeFolder,changeId+".json");
    if (!File.Exists(changePath)) return Results.NotFound();
    var change = JsonNode.Parse(await File.ReadAllTextAsync(changePath))?.AsObject();
    if (change?["status"]?.ToString() != "Approved" || change["reviewedBy"] is null ||
        string.Equals(change["requestedBy"]?.ToString(),change["reviewedBy"]?.ToString(),StringComparison.OrdinalIgnoreCase))
        return Results.Conflict(new { error="An independent administrator must have approved this change" });
    if (change["payload"] is not JsonObject payload || payload["routes"] is not JsonObject routes ||
        payload["clusters"] is not JsonObject clusters)
        return Results.BadRequest(new {error="Approved change has no route and cluster payload"});
    var gateways=ReadFleet();
    if (gateways.Count < 2 || gateways.Count > 20)
        return Results.Conflict(new {error="Register at least two managed gateways; maximum 20"});
    if (!await rolloutGate.WaitAsync(0)) return Results.Conflict(new {error="Another rollout is running"});
    var txId="rollout_"+Convert.ToHexString(RandomNumberGenerator.GetBytes(12));
    var result=new JsonObject { ["id"]=txId,["changeId"]=changeId,
       ["initiator"]=Actor(ctx),["createdUtc"]=DateTimeOffset.UtcNow.ToString("O"),
       ["status"]="starting",["details"]=new JsonArray() };
    var logPath=Path.Combine(rolloutFolder,txId+".json");
    async Task Log(string gateway,string stage,string state,string? detail=null)
    {
        ((JsonArray)result["details"]!).Add(new JsonObject { ["utc"]=DateTimeOffset.UtcNow.ToString("O"),
            ["gateway"]=gateway,["stage"]=stage,["state"]=state,["detail"]=detail });
        await File.WriteAllTextAsync(logPath+".tmp",result.ToJsonString());
        File.Move(logPath+".tmp",logPath,true);
    }
    try
    {
        var proxy = new JsonObject { ["Routes"]=routes.DeepClone(),["Clusters"]=clusters.DeepClone() };
        var signingKeyPath = Path.Combine(privateDir, "fleet-signing-private.pem");
        if (!File.Exists(signingKeyPath))
            throw new InvalidOperationException("Fleet signing key not provisioned. Signed deployment is required.");
        var signingKeyPem = await File.ReadAllTextAsync(signingKeyPath);
        // Monotonic independent of application config revision or rollback.
        // The rolloutGate serializes allocation for this single controller instance.
        var sequence = FleetSequenceState.AllocateNext(Path.Combine(privateDir, "fleet-sequence.txt"));
        var prepared = new List<(FleetGateway Gateway,string Revision)>();
        foreach (var row in gateways)
        {
            using var client = CreateFleetClient(row);
            var statusResponse=await client.GetAsync(new Uri(new Uri(row.Url),"agent/v1/status"));
            statusResponse.EnsureSuccessStatusCode();
            var status=JsonNode.Parse(await statusResponse.Content.ReadAsStringAsync());
            var revision=status?["revision"]?.ToString();
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


app.MapOrganizationProfile(privateDir);
app.MapTlsInventory();
app.MapReverseProxy(proxyPipeline =>
{
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
        await next();
        var feature = context.GetReverseProxyFeature();
        var destination = feature.ProxiedDestination;
        if (destination != null)
        {
            var id = feature.Cluster.Config.ClusterId + "/" + destination.DestinationId;
            var stats = destinationTelemetry.GetOrAdd(id, _ => new DestinationCounters());
            stats.Record(context.Response.StatusCode,
                (System.Diagnostics.Stopwatch.GetTimestamp() - clock) * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
        }
    });
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
    proxyPipeline.UsePassiveHealthChecks();
});
app.Run();

static bool ValidId(string s) => s.Length is > 0 and <= 80 && Regex.IsMatch(s, "^[a-zA-Z0-9_-]+$");
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
record MailSettings(bool Enabled = false, string Host = "", int Port = 25, string From = "", string Username = "", string EncryptedPassword = "", bool StartTls = false);
record MailSettingsInput(bool Enabled, string Host, int Port, string From, string Username, string Password, bool StartTls);
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
