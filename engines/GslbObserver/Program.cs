using System.Net;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using GatewayCore.Gslb.Contracts;

// One operator-configured service per observer instance.
if (args.Length != 1) throw new ArgumentException("Expected an observer JSON configuration path");
var config = System.Text.Json.JsonSerializer.Deserialize<ObserverConfig>(File.ReadAllText(args[0]))
    ?? throw new InvalidDataException("Missing observer configuration");
var bind = IPAddress.Parse(config.ListenAddress);
if (bind.Equals(IPAddress.Any) || bind.Equals(IPAddress.IPv6Any) ||
    config.Port is < 1025 or > 65535 || config.PublicUrl.Scheme != "https" ||
    config.PublicUrl.AbsolutePath != "/ready" || config.PublicUrl.Query.Length != 0 ||
    config.PublicUrl.Fragment.Length != 0 || config.PublicUrl.UserInfo.Length != 0 ||
    config.HealthUrl.Scheme is not ("http" or "https") || config.HealthUrl.UserInfo.Length != 0 ||
    config.HealthUrl.Fragment.Length != 0)
    throw new InvalidDataException("Invalid observer listener, public URL or readiness URL");
var pins = config.AllowedClientSha256.Select(Convert.FromHexString).ToArray();
if (pins.Length is < 1 or > 16 || pins.Any(pin => pin.Length != 32))
    throw new InvalidDataException("Expected 1-16 SHA-256 client certificate fingerprints");
using var pem = X509Certificate2.CreateFromPemFile(config.ServerCertificatePem, config.ServerKeyPem);
using var serverCert = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null);
using var signer = ECDsa.Create();
signer.ImportFromPem(File.ReadAllText(config.SigningKeyPem));
if (signer.ExportParameters(false).Curve.Oid.Value != "1.2.840.10045.3.1.7")
    throw new InvalidDataException("A P-256 signing key is required");
// Verify signing capability before advertising readiness.
_ = signer.SignData(Array.Empty<byte>(), HashAlgorithmName.SHA256);
var reportEnabled = !string.IsNullOrWhiteSpace(config.ReportUrl);
var anyReportField = config.ReportUrl is not null || config.AgentId is not null ||
    config.Zone is not null || config.SiteId is not null ||
    config.ReportClientCertificatePem is not null || config.ReportClientKeyPem is not null ||
    config.ReportServerCaPem is not null || config.ReportSequenceStatePath is not null;
if (anyReportField != reportEnabled)
    throw new InvalidDataException("Asynchronous agent reporting must be configured completely or omitted");
AgentReportSequenceState? reportSequence = null;
HttpClient? reportClient = null;
X509Certificate2? reportClientCertificate = null;
X509Certificate2? reportServerCa = null;
if (reportEnabled)
{
    if (!Uri.TryCreate(config.ReportUrl, UriKind.Absolute, out var reportUrl) ||
        reportUrl.Scheme != "https" || reportUrl.UserInfo.Length != 0 ||
        reportUrl.Query.Length != 0 || reportUrl.Fragment.Length != 0 ||
        reportUrl.AbsolutePath != "/agent-health/v1/reports" ||
        !AgentHealthReportContract.IsValidIdentifier(config.AgentId) ||
        string.IsNullOrWhiteSpace(config.Zone) ||
        !AgentHealthReportContract.IsValidIdentifier(config.SiteId) ||
        !Path.IsPathFullyQualified(config.SigningKeyPem) ||
        !Path.IsPathFullyQualified(config.ReportClientCertificatePem ?? "") ||
        !Path.IsPathFullyQualified(config.ReportClientKeyPem ?? "") ||
        !Path.IsPathFullyQualified(config.ReportSequenceStatePath ?? "") ||
        config.ReportIntervalSeconds is < 1 or > 60 ||
        config.ReportTtlSeconds < config.ReportIntervalSeconds || config.ReportTtlSeconds > 300 ||
        (config.ReportServerCaPem is not null && !Path.IsPathFullyQualified(config.ReportServerCaPem)))
        throw new InvalidDataException("Invalid asynchronous agent report configuration");
    var zoneName = config.Zone.TrimEnd('.');
    if (!AgentHealthReportContract.IsValidZone(zoneName))
        throw new InvalidDataException("Invalid asynchronous agent zone name");
    reportSequence = new AgentReportSequenceState(config.ReportSequenceStatePath!);
    using var clientPem = X509Certificate2.CreateFromPemFile(
        config.ReportClientCertificatePem!, config.ReportClientKeyPem!);
    reportClientCertificate = X509CertificateLoader.LoadPkcs12(
        clientPem.Export(X509ContentType.Pkcs12), null);
    if (!reportClientCertificate.Extensions.OfType<X509EnhancedKeyUsageExtension>()
        .Any(extension => extension.EnhancedKeyUsages.Cast<Oid>()
            .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")))
        throw new InvalidDataException("Agent report client certificate requires clientAuth EKU");
    if (config.ReportServerCaPem is not null)
    {
        reportServerCa = X509CertificateLoader.LoadCertificateFromFile(config.ReportServerCaPem);
        if (!reportServerCa.Extensions.OfType<X509BasicConstraintsExtension>()
            .Any(extension => extension.CertificateAuthority))
            throw new InvalidDataException("Health report server trust anchor must be a CA certificate");
    }
    var reportHandler = new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false,
        UseCookies = false, ConnectTimeout = TimeSpan.FromSeconds(3) };
    reportHandler.SslOptions.ClientCertificates = new X509CertificateCollection { reportClientCertificate };
    reportHandler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, errors) =>
    {
        if (certificate is null || errors.HasFlag(SslPolicyErrors.RemoteCertificateNameMismatch))
        {
            Console.Error.WriteLine($"Health report server certificate rejected by TLS name check: {errors}");
            return false;
        }
        if (reportServerCa is null) return errors == SslPolicyErrors.None;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(reportServerCa);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(1);
        using var serverLeaf = new X509Certificate2(certificate);
        var valid = chain.Build(serverLeaf);
        if (!valid)
            Console.Error.WriteLine("Health report server certificate rejected: " +
                string.Join(",", chain.ChainStatus.Select(status => status.Status.ToString())));
        return valid;
    };
    reportClient = new HttpClient(reportHandler) { Timeout = TimeSpan.FromSeconds(2) };
}
var builder = WebApplication.CreateSlimBuilder();
builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxConcurrentConnections = 64;
    k.Limits.MaxRequestHeadersTotalSize = 8192;
    k.Listen(bind, config.Port, endpoint => endpoint.UseHttps(options =>
    {
        options.ServerCertificate = serverCert;
        options.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        options.ClientCertificateValidation = (cert, _, errors) =>
            errors == SslPolicyErrors.None &&
            pins.Any(pin => CryptographicOperations.FixedTimeEquals(pin, cert.GetCertHash(HashAlgorithmName.SHA256)));
    }));
});
await using var app = builder.Build();
using var client = new HttpClient(new SocketsHttpHandler { UseProxy = false, AllowAutoRedirect = false,
    UseCookies = false }) { Timeout = TimeSpan.FromMilliseconds(900) };
using var slots = new SemaphoreSlim(8);
app.MapGet("/ready", async (HttpContext context) =>
{
    var challenge = context.Request.Headers["Gslb-Challenge"].ToString();
    if (context.Request.QueryString.HasValue || challenge.Length != 64 ||
        challenge.Any(ch => ch is not (>= '0' and <= '9' or >= 'A' and <= 'F')))
        return Results.BadRequest();
    if (!slots.Wait(0)) return Results.StatusCode(503);
    try
    {
        using var probe = new HttpRequestMessage(HttpMethod.Get, config.HealthUrl);
        probe.Headers.CacheControl = new() { NoCache = true, NoStore = true };
        using var response = await client.SendAsync(probe, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);
        if (!response.IsSuccessStatusCode) return Results.StatusCode(503);
        var message = Encoding.UTF8.GetBytes($"GatewayCore.Health.v1\n{config.PublicUrl.AbsoluteUri}\n{challenge}\n200");
        byte[] signature;
        lock (signer) signature = signer.SignData(message, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
        context.Response.Headers["Gslb-Signature"] = Convert.ToBase64String(signature);
        context.Response.Headers.CacheControl = "no-store";
        return Results.Ok();
    }
    catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
    {
        return Results.StatusCode(503);
    }
    finally { slots.Release(); }
});
using var reportStop = new CancellationTokenSource();
app.Lifetime.ApplicationStopping.Register(() => reportStop.Cancel());
var serverTask = app.RunAsync();
var reportTask = reportEnabled ? PublishReports(reportStop.Token) : Task.CompletedTask;
try { await Task.WhenAll(serverTask, reportTask); }
finally
{
    reportStop.Cancel();
    reportSequence?.Dispose();
    reportClient?.Dispose();
    reportClientCertificate?.Dispose();
    reportServerCa?.Dispose();
}

async Task PublishReports(CancellationToken token)
{
    var endpoint = new Uri(config.ReportUrl!);
    while (!token.IsCancellationRequested)
    {
        var observed = DateTimeOffset.UtcNow;
        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        var verdict = "unknown";
        int? latencyMs = null;
        try
        {
            using var readiness = new HttpRequestMessage(HttpMethod.Get, config.HealthUrl);
            readiness.Headers.CacheControl = new() { NoCache = true, NoStore = true };
            using var response = await client.SendAsync(readiness,
                HttpCompletionOption.ResponseHeadersRead, token);
            verdict = response.IsSuccessStatusCode ? "healthy" : "unhealthy";
            latencyMs = checked((int)Math.Min(int.MaxValue,
                System.Diagnostics.Stopwatch.GetElapsedTime(started).TotalMilliseconds));
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException)
        { if (!token.IsCancellationRequested) app.Logger.LogWarning("Agent readiness observation failed: {ErrorType}", ex.GetType().Name); }

        try
        {
            var (epoch, sequence) = reportSequence!.Next();
            var report = new AgentHealthReport(AgentHealthReportContract.CurrentVersion,
                config.AgentId!, AgentHealthReportContract.KeyId(signer),
                config.Zone!.TrimEnd('.').ToLowerInvariant(), config.SiteId!,
                epoch, sequence, observed.ToUnixTimeSeconds(),
                observed.AddSeconds(config.ReportTtlSeconds).ToUnixTimeSeconds(),
                "http", verdict, verdict == "unknown" ? 0 : 1000,
                verdict == "unknown" ? null : latencyMs, "pending");
            lock (signer) report = report with { Signature = AgentHealthReportContract.Sign(report, signer) };
            using var response = await reportClient!.PostAsJsonAsync(endpoint, report, token);
            if (!response.IsSuccessStatusCode)
                app.Logger.LogWarning("Health report rejected by configured receiver with HTTP {StatusCode}",
                    (int)response.StatusCode);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException)
        {
            if (!token.IsCancellationRequested)
                app.Logger.LogWarning("Health report delivery failed: {ErrorType}, inner={InnerType}, detail={Detail}",
                    ex.GetType().Name, ex.InnerException?.GetType().Name ?? "none",
                    ex.InnerException?.Message ?? ex.Message);
        }
        catch (Exception ex) when (ex is InvalidDataException or CryptographicException)
        { app.Logger.LogCritical("Health report sequence/signing state failed: {ErrorType}", ex.GetType().Name); }

        try { await Task.Delay(TimeSpan.FromSeconds(config.ReportIntervalSeconds), token); }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { }
    }
}

sealed record ObserverConfig(string ListenAddress, int Port, Uri PublicUrl, Uri HealthUrl,
    string ServerCertificatePem, string ServerKeyPem, string SigningKeyPem, string[] AllowedClientSha256)
{
    public string? ReportUrl { get; init; }
    public string? AgentId { get; init; }
    public string? Zone { get; init; }
    public string? SiteId { get; init; }
    public string? ReportClientCertificatePem { get; init; }
    public string? ReportClientKeyPem { get; init; }
    public string? ReportServerCaPem { get; init; }
    public string? ReportSequenceStatePath { get; init; }
    public int ReportIntervalSeconds { get; init; } = 2;
    public int ReportTtlSeconds { get; init; } = 10;
}
