using System.Diagnostics;
using System.Runtime;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Yarp.ReverseProxy.Model;
using Yarp.ReverseProxy.LoadBalancing;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Forwarder;
using OpenTelemetry.Trace;
using OpenTelemetry.Metrics;
using OpenTelemetry.Logs;

// Enabled only by the HA fault-injection harness, not general k6 traffic.
using var haHeartbeat = HaProcessHeartbeat.StartFromEnvironment();
var builder = WebApplication.CreateBuilder(args);
// Ephemeral loopback-only TLS identity. Never deploy this certificate for real clients.
using var tlsKey = RSA.Create(2048);
var certRequest = new CertificateRequest(new X500DistinguishedName("CN=localhost"),
    tlsKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
certRequest.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
    new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") }, false));
var san = new SubjectAlternativeNameBuilder();
san.AddDnsName("localhost");
san.AddIpAddress(IPAddress.Loopback);
certRequest.CertificateExtensions.Add(san.Build());
using var issuedCert = certRequest.CreateSelfSigned(
    DateTimeOffset.UtcNow.AddMinutes(-10), DateTimeOffset.UtcNow.AddHours(6));
// Windows Schannel needs private-key material imported into a key store that
// the Kestrel process can access. The hosted CI machine is disposable.
var pfxPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(16));
var keyFlags = OperatingSystem.IsWindows()
    ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable
    : X509KeyStorageFlags.EphemeralKeySet;
using var loopbackCert = X509CertificateLoader.LoadPkcs12(
    issuedCert.Export(X509ContentType.Pfx, pfxPassword), pfxPassword, keyFlags);
// Include ordinary INFO/Warning/Error traffic as in the shipping gateway.
// Exercise the IDENTICAL product logging bootstrap under real k6 load.
var boundedConsole = GatewayLoggingConfiguration.Install(builder.Logging, Console.Out);
var httpPort = int.TryParse(Environment.GetEnvironmentVariable("YARP_LAB_HTTP_PORT"), out var h) ? h : 18080;
var tlsPort = int.TryParse(Environment.GetEnvironmentVariable("YARP_LAB_TLS_PORT"), out var t) ? t : 18443;
if (httpPort is < 1025 or > 65535 || tlsPort is < 1025 or > 65535 || httpPort == tlsPort)
    throw new ArgumentException("Lab listener ports invalid.");
builder.WebHost.ConfigureKestrel(k =>
{
    k.ListenLocalhost(httpPort);
    k.ListenLocalhost(tlsPort, listen => listen.UseHttps(loopbackCert));
});

var configPath = Environment.GetEnvironmentVariable("YARP_LAB_CONFIG_FILE")
    ?? Path.Combine(AppContext.BaseDirectory, "lab.json");
builder.Configuration.AddJsonFile(configPath, optional: false, reloadOnChange: true);
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRandomPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedLeastRequestsPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, WeightedRoundRobinPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, SourceIpHashPolicy>();
builder.Services.AddSingleton<ILoadBalancingPolicy, PrimaryBackupPolicy>();
builder.Services.AddHostedService<AutonomousRecoveryObserver>();
// Aggressive *test ingress only* transport-failure policy. Normal gateways
// retain default policy behavior unless their cluster explicitly opts in.
builder.Services.AddSingleton<IPassiveHealthCheckPolicy, ImmediateTransportFailureHealthPolicy>();
builder.Services.AddSingleton<IPassiveHealthCheckPolicy, BoundedTransportFailureHealthPolicy>();
builder.Services.AddSingleton<IActiveHealthCheckPolicy, RiseFallActiveHealthPolicy>();
var otelOverheadMode = string.Equals(Environment.GetEnvironmentVariable("YARP_LAB_OTEL_OVERHEAD"), "1", StringComparison.Ordinal);
if (otelOverheadMode) GatewayOpenTelemetry.Configure(builder.Services, "gatewaylab-otel-overhead");

var app = builder.Build();
if (otelOverheadMode)
{
    var accessLogger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("GatewayCore.AccessLog");
    var telemetryAccessLogger = app.Services.GetRequiredService<ILoggerFactory>()
        .CreateLogger("GatewayCore.TelemetryAccess");
    app.Use(async (ctx, next) =>
    {
        if (ctx.Request.Path.StartsWithSegments("/lab")) { await next(); return; }
        var started = Stopwatch.GetTimestamp();
        var clientAddress = GatewayClientAddress.ForAccessLog(ctx.Connection.RemoteIpAddress,
            ctx.Request.Headers["X-Forwarded-For"].ToString(), new HashSet<string>(StringComparer.Ordinal));
        try { await next(); }
        finally
        {
            var routeCandidate = ctx.Features.Get<IReverseProxyFeature>()?.Route?.Config.RouteId;
            var routeId = routeCandidate is { Length: > 0 and <= 80 } &&
                          routeCandidate.All(static c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-')
                ? routeCandidate : "unmatched";
            var elapsed = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            var now = DateTimeOffset.UtcNow;
            var durationMs = Math.Round(elapsed, 3);
            GatewayOpenTelemetry.LogAccess(accessLogger,
                now, clientAddress.Address?.ToString() ?? "unknown", clientAddress.Source,
                ctx.Request.Method, routeId, ctx.Response.StatusCode, durationMs);
            GatewayOpenTelemetry.LogTelemetryAccess(telemetryAccessLogger,
                now, GatewayOpenTelemetry.BoundedTelemetryMethod(ctx.Request.Method),
                GatewayOpenTelemetry.IsSafeTelemetryId(routeId) ? routeId : "_other",
                ctx.Response.StatusCode, durationMs);
        }
    });
}
var gatewayId = Environment.GetEnvironmentVariable("YARP_LAB_GATEWAY_ID") ?? "";
var lifecycle = new LabLifecycle();
bool OnLoopback(HttpContext ctx) => ctx.Connection.RemoteIpAddress is { } address && IPAddress.IsLoopback(address);
app.MapGet("/lab/ping", () => Volatile.Read(ref lifecycle.Draining) != 0
    ? Results.StatusCode(503) : Results.Ok(new { lab = true }));
app.MapPost("/lab/drain", (HttpContext ctx) =>
{
    if (!OnLoopback(ctx)) return Results.StatusCode(403);
    Interlocked.Exchange(ref lifecycle.Draining, 1);
    return Results.Ok(new { draining = true });
});
app.MapPost("/lab/graceful-stop", (HttpContext ctx, IHostApplicationLifetime life) =>
{
    if (!OnLoopback(ctx)) return Results.StatusCode(403);
    if (Volatile.Read(ref lifecycle.Draining) == 0)
        return Results.Conflict(new { error = "Drain readiness first" });
    _ = Task.Run(async () => { await Task.Delay(250); life.StopApplication(); });
    return Results.Ok(new { stopping = true, graceful = true });
});
app.MapGet("/lab/stats", () => Results.Ok(new
{
    processId = Environment.ProcessId,
    serverGc = GCSettings.IsServerGC,
    allocatedBytesTotal = GC.GetTotalAllocatedBytes(false),
    processCpuTimeMs = Process.GetCurrentProcess().TotalProcessorTime.TotalMilliseconds,
    threadPoolThreadCount = ThreadPool.ThreadCount,
    loggingQueueCapacity = boundedConsole.Capacity,
    loggingQueueDepth = boundedConsole.QueuedMessages,
    loggingEnqueuedTotal = boundedConsole.EnqueuedMessages,
    loggingWrittenTotal = boundedConsole.WrittenMessages,
    loggingDroppedTotal = boundedConsole.DroppedMessages,
    loggingDroppedLowPriorityTotal = boundedConsole.DroppedLowPriorityMessages,
    loggingDroppedHighPriorityTotal = boundedConsole.DroppedHighPriorityMessages,
    loggingWriteErrorsTotal = boundedConsole.WriteErrors,
    processWorkingSetBytes = Environment.WorkingSet,
    gcManagedHeapBytes = GC.GetTotalMemory(false),
    gc0Collections = GC.CollectionCount(0),
    gc1Collections = GC.CollectionCount(1),
    gc2Collections = GC.CollectionCount(2),
    timeUtc = DateTimeOffset.UtcNow
}));
if (otelOverheadMode)
{
    app.MapPost("/lab/otel-flush", (HttpContext ctx) =>
    {
        if (!OnLoopback(ctx)) return Results.StatusCode(403);
        var flushed = app.Services.GetRequiredService<TracerProvider>().ForceFlush(10000) &&
                      app.Services.GetRequiredService<MeterProvider>().ForceFlush(10000) &&
                      app.Services.GetRequiredService<LoggerProvider>().ForceFlush(10000);
        return flushed ? Results.Ok(new { flushed = true }) : Results.StatusCode(503);
    });
}
app.MapReverseProxy(proxyPipeline =>
{
    proxyPipeline.Use(async (ctx, next) =>
    {
        if (!string.IsNullOrEmpty(gatewayId))
            ctx.Response.OnStarting(() =>
            {
                ctx.Response.Headers["X-Lab-Gateway"] = gatewayId;
                return Task.CompletedTask;
            });
        var proxy = ctx.GetReverseProxyFeature();
        TrafficLifecycle.Observe(proxy.AllDestinations, proxy.AvailableDestinations);
        if (proxy.AvailableDestinations.Any(TrafficLifecycle.IsDraining))
            proxy.AvailableDestinations = proxy.AvailableDestinations
                .Where(d => !TrafficLifecycle.IsDraining(d)).ToArray();
        await next();
    });
    if (otelOverheadMode)
    {
        // Use the same telemetry middleware as the shipping Control Center for
        // the optional end-to-end overhead measurement.
        proxyPipeline.Use(async (ctx, next) =>
        {
            var started = Stopwatch.GetTimestamp();
            var activity = GatewayOpenTelemetry.StartProxyActivity(ctx);
            try { await next(); }
            catch (Exception exception)
            {
                GatewayOpenTelemetry.RecordProxyException(activity, exception);
                throw;
            }
            finally
            {
                var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                var feature = ctx.GetReverseProxyFeature();
                var destination = feature.ProxiedDestination;
                GatewayOpenTelemetry.CompleteProxyActivity(activity, ctx, destination?.DestinationId);
                GatewayOpenTelemetry.RecordProxyResult(ctx, elapsedMs,
                    feature.Route.Config.RouteId, feature.Cluster.Config.ClusterId,
                    destination?.DestinationId);
            }
        });
    }
    proxyPipeline.UseSessionAffinity();
    proxyPipeline.UseLoadBalancing();
    proxyPipeline.UsePassiveHealthChecks();
});
app.Run();

sealed class LabLifecycle { internal int Draining; }

/// <summary>
/// A deliberately aggressive TEST-ONLY passive policy. A transport failure
/// can eject a node before the next active health probe; a 5xx response from
/// an application does NOT eject it. Production needs policy tuning and
/// false-positive analysis, not the one-error threshold used here.
/// </summary>
sealed class ImmediateTransportFailureHealthPolicy : IPassiveHealthCheckPolicy
{
    private readonly IDestinationHealthUpdater _updater;
    public ImmediateTransportFailureHealthPolicy(IDestinationHealthUpdater updater) => _updater = updater;
    public string Name => "ImmediateTransportFailure";
    public void RequestProxied(HttpContext context, ClusterState cluster, DestinationState destination)
    {
        // Never eject a healthy gateway because a downstream test client,
        // browser or load generator canceled its request.
        if (context.RequestAborted.IsCancellationRequested) return;
        var error = context.Features.Get<IForwarderErrorFeature>()?.Error;
        if (error is not (ForwarderError.Request or ForwarderError.RequestTimedOut or
                          ForwarderError.RequestBodyDestination or ForwarderError.ResponseBodyDestination))
            return;
        var reactivation = cluster.Model.Config.HealthCheck?.Passive?.ReactivationPeriod ?? TimeSpan.FromSeconds(30);
        _updater.SetPassive(cluster, destination, DestinationHealth.Unhealthy, reactivation);
    }
}
