using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Core;

// Independent management service. No mutation, read or delete API; a gateway
// holds only its own HMAC key, never the collector signing key.
static string Required(string name) => Environment.GetEnvironmentVariable(name)
    ?? throw new InvalidOperationException("Set " + name);
static void PrivatePath(string path, bool directory)
{
    if (!Path.IsPathFullyQualified(path) || (directory ? !Directory.Exists(path) : !File.Exists(path)) ||
        (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        throw new InvalidOperationException("Expected existing absolute non-link collector path");
    if (!OperatingSystem.IsWindows() &&
        (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite |
         UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite |
         UnixFileMode.OtherExecute)) != 0)
        throw new InvalidOperationException("Collector keys/state require owner-only permission");
}
static byte[] ReadPrivate(string path, int max)
{
    PrivatePath(path, false);
    using var f = File.OpenRead(path);
    if (f.Length is < 1 || f.Length > max) throw new InvalidOperationException("Invalid secret file length");
    var bytes = new byte[(int)f.Length];
    f.ReadExactly(bytes);
    if (f.ReadByte() != -1) throw new InvalidOperationException("Secret file changed during read");
    return bytes;
}
var listen = IPAddress.Parse(Required("AUDIT_LISTEN_ADDRESS"));
if (listen.Equals(IPAddress.Any) || listen.Equals(IPAddress.IPv6Any) || listen.IsIPv4MappedToIPv6)
    throw new InvalidOperationException("Use an explicit management listener address");
if (!int.TryParse(Required("AUDIT_LISTEN_PORT"), out var port) || port is < 1025 or > 65535)
    throw new InvalidOperationException("Audit port must be 1025..65535");
var statePath = Required("AUDIT_LEDGER_FILE");
PrivatePath(statePath, false);
PrivatePath(Path.GetDirectoryName(statePath)!, true);
var keysDirectory = Required("AUDIT_NODE_KEYS_DIR");
PrivatePath(keysDirectory, true);
var keys = new Dictionary<string, byte[]>(StringComparer.Ordinal);
foreach (var path in Directory.EnumerateFiles(keysDirectory).Take(33))
{
    var id = Path.GetFileNameWithoutExtension(path);
    if (Path.GetExtension(path) != ".key" || !AuditContract.ValidNode(id) || keys.Count >= 32)
        throw new InvalidOperationException("Expected 1..32 independently provisioned node .key files");
    var key = ReadPrivate(path, 32);
    if (key.Length != 32 || keys.Values.Any(x => CryptographicOperations.FixedTimeEquals(x, key)))
        throw new InvalidOperationException("Node keys must be unique 32-byte secrets");
    keys.Add(id, key);
}
if (keys.Count == 0) throw new InvalidOperationException("At least one node key is required");
using var signingKey = RSA.Create();
signingKey.ImportFromPem(Encoding.ASCII.GetString(ReadPrivate(Required("AUDIT_SIGNING_PEM"), 8192)));
if (signingKey.KeySize is < 2048 or > 4096)
    throw new InvalidOperationException("RSA signing key must be 2048..4096 bits");
// Verify private-key availability at startup, before accepting any write.
_ = signingKey.SignData(new byte[] { 1 }, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
var wormVariables = new[] { "AUDIT_WORM_ENDPOINT", "AUDIT_WORM_REGION", "AUDIT_WORM_BUCKET",
    "AUDIT_WORM_PREFIX", "AUDIT_WORM_DAYS", "AUDIT_WORM_ACCESS_FILE", "AUDIT_WORM_SECRET_FILE", "AUDIT_WORM_PENDING_FILE" };
var wormEnabled = wormVariables.Any(v => Environment.GetEnvironmentVariable(v) is not null);
string? pendingPath = null;
ObjectLockRetention? worm = null;
if (wormEnabled)
{
    foreach (var name in wormVariables) _ = Required(name);
    pendingPath = Required("AUDIT_WORM_PENDING_FILE");
    PrivatePath(pendingPath, false);
    PrivatePath(Path.GetDirectoryName(pendingPath)!, true);
    if (!int.TryParse(Required("AUDIT_WORM_DAYS"), NumberStyles.None, CultureInfo.InvariantCulture, out var days))
        throw new InvalidDataException("Invalid retention days");
    worm = ObjectLockRetention.Create(Required("AUDIT_WORM_ENDPOINT"), Required("AUDIT_WORM_REGION"),
        Required("AUDIT_WORM_BUCKET"), Required("AUDIT_WORM_PREFIX"), days,
        Encoding.UTF8.GetString(ReadPrivate(Required("AUDIT_WORM_ACCESS_FILE"), 256)).TrimEnd('\r','\n'),
        Encoding.UTF8.GetString(ReadPrivate(Required("AUDIT_WORM_SECRET_FILE"), 256)).TrimEnd('\r','\n'));
}
using var retention = worm;
using var ledger = new AuditLedger(statePath, signingKey, retention, pendingPath);
if (args.Length > 0 && args[0] == "--verify-ledger")
{
    // Operators can compare against an independently retained checkpoint.
    // An unanchored valid prefix is not proof against privileged truncation.
    if (args.Length != 1 &&
        (args.Length != 3 || !int.TryParse(args[1], out var expectedCount) ||
         expectedCount != ledger.Count || !string.Equals(args[2], ledger.Head, StringComparison.Ordinal)))
        throw new InvalidDataException("Ledger differs from external checkpoint");
    Console.WriteLine($"Verified {ledger.Count} chained audit intents; head {ledger.Head}");
    return;
}
if (args.Length != 0) throw new InvalidOperationException("Unknown collector argument");
var password = Encoding.UTF8.GetString(ReadPrivate(Required("AUDIT_TLS_PASSWORD_FILE"), 1024)).TrimEnd('\r', '\n');
var pfx = ReadPrivate(Required("AUDIT_TLS_PFX"), 65536);
using var tls = X509CertificateLoader.LoadPkcs12(pfx, password,
    OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet);
CryptographicOperations.ZeroMemory(pfx);
if (!tls.HasPrivateKey || tls.NotBefore.ToUniversalTime() > DateTime.UtcNow ||
    tls.NotAfter.ToUniversalTime() <= DateTime.UtcNow)
    throw new InvalidOperationException("Valid TLS identity required");
var builder = WebApplication.CreateSlimBuilder();
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = AuditContract.MaxBody;
    options.Limits.MaxRequestHeadersTotalSize = 8192;
    options.Limits.MaxConcurrentConnections = 32;
    options.Limits.RequestHeadersTimeout = TimeSpan.FromSeconds(5);
    options.Limits.KeepAliveTimeout = TimeSpan.FromSeconds(10);
    options.Listen(listen, port, ep =>
    {
        ep.Protocols = HttpProtocols.Http1AndHttp2;
        ep.UseHttps(tls);
    });
});
builder.Logging.SetMinimumLevel(LogLevel.Warning);
if (retention is not null) builder.Services.AddHostedService(_ => new RetentionRetryWorker(ledger));
var app = builder.Build();
using var slots = new SemaphoreSlim(8, 8);
app.MapPost("/audit/v1/intents", async (HttpContext ctx) =>
{
    if (!await slots.WaitAsync(0, ctx.RequestAborted)) return Results.StatusCode(503);
    try
    {
        if (ctx.Request.ContentLength is not long n || n < 1 || n > AuditContract.MaxBody)
            return Results.StatusCode(413);
        if (!string.Equals(ctx.Request.ContentType, "application/json", StringComparison.OrdinalIgnoreCase))
            return Results.StatusCode(415);
        if (!ctx.Request.Headers.TryGetValue("X-GC-Audit-Event-Id", out var ids) || ids.Count != 1 ||
            !ctx.Request.Headers.TryGetValue("X-GC-Audit-Signature", out var macs) || macs.Count != 1)
            return Results.StatusCode(401);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
        deadline.CancelAfter(TimeSpan.FromSeconds(3));
        var bytes = new byte[(int)n];
        await ctx.Request.Body.ReadExactlyAsync(bytes, deadline.Token);
        var intent = AuditContract.Parse(bytes);
        if (intent is null || !string.Equals(intent.EventId, ids[0], StringComparison.Ordinal) ||
            !keys.TryGetValue(intent.Node, out var sender) ||
            !AuditContract.VerifyMac(intent.EventId, bytes, macs[0], sender))
            return Results.StatusCode(403);
        if ((DateTimeOffset.UtcNow - intent.Utc).Duration() > TimeSpan.FromSeconds(60))
            return Results.StatusCode(409);
        var result = ledger.Append(intent.EventId, bytes);
        if (result.Status != 201) return Results.StatusCode(result.Status);
        ctx.Response.Headers["X-GC-Audit-Receipt"] = result.Receipt;
        ctx.Response.Headers.CacheControl = "no-store";
        return Results.StatusCode(201);
    }
    catch (Exception ex) when (ex is IOException or OperationCanceledException or JsonException)
    { return Results.StatusCode(503); }
    finally { slots.Release(); }
});
await app.RunAsync();

internal sealed class RetentionRetryWorker(AuditLedger ledger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(5));
        try
        {
            do { ledger.RetryPending(); }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }
}
