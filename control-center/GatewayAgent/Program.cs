using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// Separate, least-privileged gateway-agent reference implementation.
// Fail-closed: no trusted controller certificate = no remote access.
var builder = WebApplication.CreateBuilder(args);
var allowedThumbprints = builder.Configuration.GetSection("Agent:TrustedClientThumbprints").Get<string[]>() ?? [];
var allowedServices = builder.Configuration.GetSection("Agent:AllowedServices").Get<string[]>() ?? [];
var allowActions = builder.Configuration.GetValue<bool>("Agent:EnableServiceActions");
var allowConfigChanges = builder.Configuration.GetValue<bool>("Agent:EnableConfigChanges");
var gatewayConfigPath = builder.Configuration["Agent:GatewayConfigPath"] ?? "";
var stageRoot = builder.Configuration["Agent:StageDirectory"] ?? "";
if (allowConfigChanges && (!Path.IsPathFullyQualified(gatewayConfigPath) ||
    !Path.IsPathFullyQualified(stageRoot) || !File.Exists(gatewayConfigPath)))
    throw new InvalidOperationException("Config changes require an existing absolute gateway config path and absolute stage directory");
if (allowConfigChanges) Directory.CreateDirectory(stageRoot);
var revisionLock = new SemaphoreSlim(1,1);
static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
static bool ValidTx(string id) => Regex.IsMatch(id, "^[A-Za-z0-9_-]{12,80}$");
if (allowedThumbprints.Length == 0) throw new InvalidOperationException("No trusted client certificates configured");
if (allowedServices.Any(x => !Regex.IsMatch(x, "^[A-Za-z0-9_.-]{1,64}$")))
    throw new InvalidOperationException("Invalid allowlisted Windows service name");
builder.WebHost.ConfigureKestrel(server =>
{
    server.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        https.CheckCertificateRevocation = true;
    });
});
var app = builder.Build();
var normalized = allowedThumbprints.Select(x => x.Replace(" ", "").ToUpperInvariant()).ToHashSet();
app.Use(async (ctx, next) =>
{
    // Kestrel performs TLS chain validation. This additionally pins controller identities.
    var cert = ctx.Connection.ClientCertificate;
    if (!ctx.Request.IsHttps || cert is null || !normalized.Contains(cert.Thumbprint.ToUpperInvariant()))
    { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return; }
    ctx.Response.Headers.CacheControl = "no-store";
    await next();
});

app.MapGet("/agent/v1/status", () => Results.Ok(new
{
    machine = Environment.MachineName,
    utc = DateTimeOffset.UtcNow,
    serviceManagementEnabled = allowActions,
    configDeploymentEnabled = allowConfigChanges,
    revision = allowConfigChanges ? Sha(File.ReadAllBytes(gatewayConfigPath)) : null,
    allowedServiceNames = allowedServices,
    // This reports agent responsiveness only. NOT YARP's internal destination health.
    kind = "authenticated-agent-status"
}));

app.MapGet("/agent/v1/services/{serviceName}", async (string serviceName) =>
{
    if (!allowedServices.Contains(serviceName, StringComparer.OrdinalIgnoreCase)) return Results.NotFound();
    var result = await RunSc("query", serviceName);
    return Results.Ok(new { serviceName, result.exitCode, output = result.output[..Math.Min(result.output.Length, 4000)] });
});

app.MapPost("/agent/v1/services/{serviceName}/action", async (HttpContext ctx, string serviceName, ServiceAction body) =>
{
    if (!allowActions) return Results.Problem("Service actions disabled by local policy", statusCode: 403);
    if (!allowedServices.Contains(serviceName, StringComparer.OrdinalIgnoreCase)) return Results.NotFound();
    if (body.Action is not ("start" or "stop")) return Results.BadRequest(new { error = "Only start and stop are permitted" });
    // Integrate with two-person signed approval and central immutable audit before enabling in CA production.
    var result = await RunSc(body.Action, serviceName);
    app.Logger.LogWarning("Agent service action {Action} on {Service} by controller {Cert}: exit {Code}",
        body.Action, serviceName, ctx.Connection.ClientCertificate?.Thumbprint, result.exitCode);
    return Results.Ok(new { serviceName, action = body.Action, result.exitCode, output = result.output[..Math.Min(result.output.Length, 4000)] });
});
// Only ReverseProxy routing configuration may be remotely changed.
// Each gateway retains a per-transaction original; no arbitrary file paths or commands supplied by callers.
app.MapPost("/agent/v1/config/prepare", async (ConfigPrepare input) =>
{
    if (!allowConfigChanges) return Results.Problem("Configuration rollout is disabled", statusCode:403);
    if (!ValidTx(input.TransactionId) || input.ReverseProxy is not JsonObject candidate ||
        candidate["Routes"] is not JsonObject || candidate["Clusters"] is not JsonObject ||
        Encoding.UTF8.GetByteCount(candidate.ToJsonString()) > 524288)
        return Results.BadRequest(new { error = "Invalid transaction or proxy configuration" });
    await revisionLock.WaitAsync();
    try
    {
        var current = await File.ReadAllBytesAsync(gatewayConfigPath);
        var hash = Sha(current);
        if (!hash.Equals(input.ExpectedRevision, StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new { error = "Gateway config drift detected", currentRevision = hash });
        var txDir = Path.Combine(stageRoot, input.TransactionId);
        if (Directory.Exists(txDir)) return Results.Conflict(new { error = "Transaction already exists" });
        Directory.CreateDirectory(txDir);
        await File.WriteAllBytesAsync(Path.Combine(txDir, "original.json"), current);
        var doc = JsonNode.Parse(current)!.AsObject();
        doc["ReverseProxy"] = candidate.DeepClone();
        var proposed = Encoding.UTF8.GetBytes(doc.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        await File.WriteAllBytesAsync(Path.Combine(txDir, "prepared.json"), proposed);
        return Results.Ok(new { transactionId = input.TransactionId, originalRevision = hash,
            preparedRevision = Sha(proposed), state = "prepared" });
    }
    finally { revisionLock.Release(); }
});
app.MapPost("/agent/v1/config/activate", async (ConfigActivate input) =>
{
    if (!allowConfigChanges) return Results.Problem("Configuration rollout is disabled", statusCode:403);
    if (!ValidTx(input.TransactionId)) return Results.BadRequest();
    await revisionLock.WaitAsync();
    try
    {
        var tx = Path.Combine(stageRoot,input.TransactionId);
        var prepared = Path.Combine(tx,"prepared.json");
        if (!File.Exists(prepared)) return Results.NotFound();
        var proposed = await File.ReadAllBytesAsync(prepared);
        if (!Sha(proposed).Equals(input.PreparedRevision,StringComparison.OrdinalIgnoreCase)) return Results.Conflict();
        var original = await File.ReadAllBytesAsync(Path.Combine(tx,"original.json"));
        var actual = await File.ReadAllBytesAsync(gatewayConfigPath);
        if (!Sha(actual).Equals(Sha(original),StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new { error = "Config changed since preparation" });
        await File.WriteAllBytesAsync(gatewayConfigPath + ".next", proposed);
        File.Move(gatewayConfigPath + ".next",gatewayConfigPath,true);
        return Results.Ok(new { state="activated", revision=Sha(proposed), transactionId=input.TransactionId });
    }
    finally { revisionLock.Release(); }
});
app.MapPost("/agent/v1/config/rollback", async (ConfigRollback input) =>
{
    if (!allowConfigChanges) return Results.Problem("Configuration rollout is disabled", statusCode:403);
    if (!ValidTx(input.TransactionId)) return Results.BadRequest();
    await revisionLock.WaitAsync();
    try
    {
        var tx = Path.Combine(stageRoot,input.TransactionId);
        var originalPath = Path.Combine(tx,"original.json");
        var stagedPath = Path.Combine(tx,"prepared.json");
        if (!File.Exists(originalPath) || !File.Exists(stagedPath)) return Results.NotFound();
        var actual = await File.ReadAllBytesAsync(gatewayConfigPath);
        var original = await File.ReadAllBytesAsync(originalPath);
        var staged = await File.ReadAllBytesAsync(stagedPath);
        // Never overwrite config mutated by another operator since rollout.
        if (Sha(actual)!=Sha(staged) && Sha(actual)!=Sha(original))
            return Results.Conflict(new {error="Cannot rollback: gateway has diverged"});
        await File.WriteAllBytesAsync(gatewayConfigPath+".next", original);
        File.Move(gatewayConfigPath+".next",gatewayConfigPath,true);
        return Results.Ok(new {state="rolled-back",revision=Sha(original)});
    }
    finally {revisionLock.Release();}
});
app.Run();

static async Task<(int exitCode, string output)> RunSc(string command, string serviceName)
{
    var info = new ProcessStartInfo("sc.exe") { RedirectStandardOutput = true, RedirectStandardError = true,
        UseShellExecute = false, CreateNoWindow = true };
    info.ArgumentList.Add(command); info.ArgumentList.Add(serviceName);
    using var process = Process.Start(info) ?? throw new InvalidOperationException("sc.exe launch failed");
    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
    var outputTask = process.StandardOutput.ReadToEndAsync();
    var errorTask = process.StandardError.ReadToEndAsync();
    try { await process.WaitForExitAsync(cts.Token); }
    catch (OperationCanceledException) { if (!process.HasExited) process.Kill(entireProcessTree: true); throw; }
    return (process.ExitCode, (await outputTask) + (await errorTask));
}
record ServiceAction(string Action);

record ConfigPrepare(string TransactionId, string ExpectedRevision, JsonObject ReverseProxy);
record ConfigActivate(string TransactionId, string PreparedRevision);
record ConfigRollback(string TransactionId);
