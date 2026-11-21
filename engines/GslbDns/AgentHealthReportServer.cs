using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using GatewayCore.Gslb.Contracts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

internal sealed record AgentReportServerConfig(
    string ListenAddress,
    int ListenPort,
    bool AllowNonLoopbackListener,
    string ServerCertificatePem,
    string ServerKeyPem,
    string ReplayStatePath,
    int MaxTtlSeconds,
    int MaxAgeSeconds,
    int MaxClockSkewSeconds,
    int MaxReportsPerMinute,
    string[] RevokedCertificateSha256,
    AgentTrust[] Agents);

/// <summary>
/// Optional private HTTPS ingress for signed observer snapshots. The listener
/// is separate from DNS UDP/TCP; client identity is pinned by SHA-256, the
/// report has its own P-256 signature, and DNS uses only fresh quorum evidence.
/// </summary>
internal sealed class AgentHealthReportServer : IAsyncDisposable
{
    private static readonly JsonSerializerOptions ReportJsonOptions = new(JsonSerializerDefaults.Web);
    private readonly AgentHealthReportStore store;
    private readonly DnsRuntimeMetrics metrics;
    private readonly AgentReportServerConfig config;
    private readonly HashSet<string> revoked;
    private WebApplication? app;
    private SemaphoreSlim? slots;
    private X509Certificate2? serverCertificate;

    public AgentHealthReportServer(AgentReportServerConfig config, AgentHealthReportStore store,
        DnsRuntimeMetrics metrics)
    {
        this.config = config;
        this.store = store;
        this.metrics = metrics;
        if (!IPAddress.TryParse(config.ListenAddress, out var address) ||
            address.IsIPv4MappedToIPv6 ||
            address.AddressFamily is not (System.Net.Sockets.AddressFamily.InterNetwork or System.Net.Sockets.AddressFamily.InterNetworkV6) ||
            ((address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any)) && !config.AllowNonLoopbackListener) ||
            (IPAddress.IsLoopback(address) && config.AllowNonLoopbackListener) ||
            config.ListenPort is < 1025 or > 65535 ||
            !Path.IsPathFullyQualified(config.ServerCertificatePem) ||
            !Path.IsPathFullyQualified(config.ServerKeyPem) ||
            config.MaxTtlSeconds < 1 || config.MaxAgeSeconds < 1 ||
            config.MaxClockSkewSeconds < 0 || config.MaxReportsPerMinute is < 1 or > 10000 ||
            config.Agents is not { Length: >= 2 and <= 64 } ||
            config.RevokedCertificateSha256 is null || config.RevokedCertificateSha256.Length > 256)
            throw new InvalidDataException("Invalid or unbounded signed health report listener configuration");

        revoked = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in config.RevokedCertificateSha256)
        {
            if (string.IsNullOrWhiteSpace(item)) throw new InvalidDataException("Invalid revoked certificate pin");
            byte[] hash;
            try { hash = Convert.FromHexString(item); }
            catch (FormatException ex) { throw new InvalidDataException("Invalid revoked certificate SHA-256 pin", ex); }
            if (hash.Length != 32 || !revoked.Add(Convert.ToHexString(hash)))
                throw new InvalidDataException("Invalid or duplicate revoked certificate SHA-256 pin");
        }
    }

    public async Task StartAsync(CancellationToken token)
    {
        if (app is not null) throw new InvalidOperationException("Health report server already started");
        var keyPem = PrivateKeyFileSecurity.ReadPrivateKeyPem(config.ServerKeyPem, "Agent report TLS private key");
        using var pem = X509Certificate2.CreateFromPem(File.ReadAllText(config.ServerCertificatePem), keyPem);
        serverCertificate = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
        var address = IPAddress.Parse(config.ListenAddress);
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.ConfigureKestrel(kestrel =>
        {
            kestrel.Limits.MaxRequestBodySize = AgentHealthReportContract.MaximumSerializedBytes;
            kestrel.Limits.MaxRequestHeadersTotalSize = 8192;
            kestrel.Limits.MaxConcurrentConnections = 64;
            kestrel.Listen(address, config.ListenPort, endpoint => endpoint.UseHttps(https =>
            {
                https.ServerCertificate = serverCertificate;
                https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
                // The configured leaf SHA-256 pins are direct trust anchors for
                // agent mTLS. Time, EKU, exact pin and emergency revocation are
                // checked here; deployments rotate by overlapping pins.
                https.ClientCertificateValidation = (certificate, _, _) =>
                    store.AgentIdForCertificate(certificate, revoked) is not null;
            }));
        });
        var web = builder.Build();
        slots = new SemaphoreSlim(32, 32);
        web.MapPost("/agent-health/v1/reports", async (HttpContext context) =>
        {
            if (!slots.Wait(0)) return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
            try
            {
                var authenticatedAgentId = store.AgentIdForCertificate(
                    context.Connection.ClientCertificate, revoked);
                // Authenticate and charge every admitted request before
                // reading or parsing its body. Invalid JSON must not bypass
                // the per-agent work budget or consume another identity's quota.
                if (authenticatedAgentId is null)
                {
                    metrics.AgentReportRejected();
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }
                if (!store.TryReserveRequest(authenticatedAgentId, Environment.TickCount64, config.MaxReportsPerMinute))
                {
                    store.RecordRejectedReport(authenticatedAgentId);
                    metrics.AgentReportRejected();
                    return Results.StatusCode(StatusCodes.Status429TooManyRequests);
                }
                AgentHealthReport? report;
                try
                {
                    using var body = new MemoryStream();
                    var buffer = new byte[2048];
                    while (true)
                    {
                        int read;
                        try { read = await context.Request.Body.ReadAsync(buffer, context.RequestAborted); }
                        catch (Microsoft.AspNetCore.Server.Kestrel.Core.BadHttpRequestException ex)
                            when (ex.StatusCode == StatusCodes.Status413PayloadTooLarge)
                        {
                            // Chunked requests can trip Kestrel's transport
                            // bound before our explicit accumulated-byte check.
                            // Count them as rejected reports instead of letting
                            // an expected size refusal escape as an app error.
                            store.RecordRejectedReport(authenticatedAgentId);
                            metrics.AgentReportRejected();
                            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                        }
                        if (read == 0) break;
                        if (body.Length + read > AgentHealthReportContract.MaximumSerializedBytes)
                        {
                            store.RecordRejectedReport(authenticatedAgentId);
                            metrics.AgentReportRejected();
                            return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
                        }
                        body.Write(buffer, 0, read);
                    }
                    var payload = body.ToArray();
                    if (!StrictJsonPropertyNames.HasNoDuplicates(payload))
                    {
                        store.RecordRejectedReport(authenticatedAgentId);
                        metrics.AgentReportRejected();
                        return Results.BadRequest();
                    }
                    report = JsonSerializer.Deserialize<AgentHealthReport>(payload, ReportJsonOptions);
                }
                catch (JsonException)
                {
                    store.RecordRejectedReport(authenticatedAgentId);
                    metrics.AgentReportRejected();
                    return Results.BadRequest();
                }
                if (report is null)
                {
                    store.RecordRejectedReport(authenticatedAgentId);
                    metrics.AgentReportRejected();
                    return Results.BadRequest();
                }
                var agentId = authenticatedAgentId;
                if (!string.Equals(agentId, report.AgentId, StringComparison.Ordinal))
                {
                    store.RecordRejectedReport(agentId);
                    metrics.AgentReportRejected();
                    return Results.StatusCode(StatusCodes.Status403Forbidden);
                }
                bool accepted;
                try
                {
                    accepted = store.TryAccept(report, context.Connection.ClientCertificate!, DateTimeOffset.UtcNow,
                        Environment.TickCount64);
                }
                catch
                {
                    metrics.AgentReportStorageError();
                    throw;
                }
                if (!accepted)
                {
                    store.RecordRejectedReport(agentId);
                    metrics.AgentReportRejected();
                    return Results.BadRequest(new { error = "Invalid, stale, replayed or unauthorized report" });
                }
                metrics.AgentReportAccepted();
                context.Response.Headers.CacheControl = "no-store";
                return Results.Accepted();
            }
            finally { slots.Release(); }
        });
        app = web;
        try { await web.StartAsync(token); }
        catch
        {
            app = null;
            await web.DisposeAsync();
            slots.Dispose();
            slots = null;
            serverCertificate.Dispose();
            serverCertificate = null;
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        var running = app;
        app = null;
        if (running is not null)
        {
            using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            try { await running.StopAsync(stop.Token); }
            catch (OperationCanceledException) { }
            await running.DisposeAsync();
        }
        slots?.Dispose();
        serverCertificate?.Dispose();
        serverCertificate = null;
    }
}
