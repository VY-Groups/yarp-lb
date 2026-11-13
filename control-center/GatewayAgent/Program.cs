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
var allowEngineConfigChanges = builder.Configuration.GetValue<bool>("Agent:EnableEngineConfigChanges");
var allowEnginePublicBind = builder.Configuration.GetValue<bool>("Agent:AllowEngineNonLoopbackListeners");
var enginePaths = builder.Configuration.GetSection("Agent:EngineConfigPaths")
    .Get<Dictionary<string,string>>() ?? new Dictionary<string,string>();
var gatewayConfigPath = builder.Configuration["Agent:GatewayConfigPath"] ?? "";
var stageRoot = builder.Configuration["Agent:StageDirectory"] ?? "";
var keyPaths = builder.Configuration.GetSection("Agent:TrustedSigningPublicKeyPaths").Get<string[]>() ?? [];
// Legacy single-key path remains a migration input only. V1 signatures are rejected.
if (keyPaths.Length == 0 && !string.IsNullOrWhiteSpace(builder.Configuration["Agent:ControllerSigningPublicKeyPath"]))
    keyPaths = [builder.Configuration["Agent:ControllerSigningPublicKeyPath"]!];
if ((allowConfigChanges || allowEngineConfigChanges) && (keyPaths.Length is < 1 or > 3 ||
    keyPaths.Any(p => !Path.IsPathFullyQualified(p) || !File.Exists(p))))
    throw new InvalidOperationException("Config rollout requires 1-3 existing absolute pinned public-key paths");
var signingKeys = new Dictionary<string, string>(StringComparer.Ordinal);
if (allowConfigChanges || allowEngineConfigChanges)
foreach (var path in keyPaths)
{
    var pem = File.ReadAllText(path);
    var keyId = FleetConfigSignature.KeyIdFromPublicKey(pem);
    if (!signingKeys.TryAdd(keyId, pem))
        throw new InvalidOperationException("Duplicate pinned controller signing identity");
}
if (allowConfigChanges && (!Path.IsPathFullyQualified(gatewayConfigPath) ||
    !Path.IsPathFullyQualified(stageRoot) || !File.Exists(gatewayConfigPath)))
    throw new InvalidOperationException("Config changes require an existing absolute gateway config path and absolute stage directory");
if (allowEngineConfigChanges &&
    (enginePaths.Count is < 1 or > 2 || !Path.IsPathFullyQualified(stageRoot) ||
     enginePaths.Any(e => !EngineConfigContract.ValidEngineId(e.Key) ||
         !Path.IsPathFullyQualified(e.Value) || !File.Exists(e.Value))))
    throw new InvalidOperationException("Engine changes require explicit allowlisted L4/GSLB file paths and an absolute staging directory");
if (allowConfigChanges || allowEngineConfigChanges) Directory.CreateDirectory(stageRoot);
var sequencePath = Path.Combine(stageRoot, "last-accepted-sequence.txt");
var revisionLock = new SemaphoreSlim(1,1);
static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
static bool ValidTx(string id) => Regex.IsMatch(id, "^[A-Za-z0-9_-]{12,80}$");
var normalized = AgentClientCertificatePolicy.ParsePinnedThumbprints(allowedThumbprints);
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

app.Use(async (ctx, next) =>
{
    // Kestrel performs TLS chain validation. This additionally pins controller identities.
    if (!AgentClientCertificatePolicy.IsAuthorized(ctx, normalized))
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
    engineConfigStagingEnabled = allowEngineConfigChanges,
    revision = allowConfigChanges ? Sha(File.ReadAllBytes(gatewayConfigPath)) : null,
    allowedServiceNames = allowedServices,
    highestAcceptedSequence = allowConfigChanges ? FleetSequenceState.Read(sequencePath) : 0,
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
    var signed = new FleetConfigSignature.SignedV2(input.KeyId, input.Sequence,
        input.ExpiresUnixSeconds, input.Signature);
    if (!FleetConfigSignature.VerifyV2(signingKeys, input.TransactionId, input.ExpectedRevision,
        candidate, signed, DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
        return Results.Problem("Missing, expired, stale-version or invalid controller signature", statusCode: 403);
    await revisionLock.WaitAsync();
    try
    {
        var current = await File.ReadAllBytesAsync(gatewayConfigPath);
        var hash = Sha(current);
        if (!hash.Equals(input.ExpectedRevision, StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new { error = "Gateway config drift detected", currentRevision = hash });
        var txDir = Path.Combine(stageRoot, input.TransactionId);
        if (Directory.Exists(txDir)) return Results.Conflict(new { error = "Transaction already exists" });
        if (input.Sequence <= FleetSequenceState.Read(sequencePath))
            return Results.Conflict(new { error = "Older or repeated signed configuration sequence" });
        // Reserve the sequence BEFORE staging: a crash cannot make old signed configs eligible.
        FleetSequenceState.Accept(sequencePath, input.Sequence);
        Directory.CreateDirectory(txDir);
        await File.WriteAllTextAsync(Path.Combine(txDir, "sequence.txt"),
            input.Sequence.ToString(System.Globalization.CultureInfo.InvariantCulture));
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
        var seqFile = Path.Combine(tx, "sequence.txt");
        if (!File.Exists(seqFile) ||
            !long.TryParse(await File.ReadAllTextAsync(seqFile), out var preparedSequence) ||
            preparedSequence != FleetSequenceState.Read(sequencePath))
            return Results.Conflict(new { error = "Prepared transaction superseded by newer sequence" });
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
        var seqFile = Path.Combine(tx, "sequence.txt");
        if (!File.Exists(seqFile) ||
            !long.TryParse(await File.ReadAllTextAsync(seqFile), out var preparedSequence) ||
            preparedSequence != FleetSequenceState.Read(sequencePath))
            return Results.Conflict(new { error = "Rollback of an obsolete transaction is prohibited" });
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

app.MapGet("/agent/v1/engines", () =>
{
    if (!allowEngineConfigChanges) return Results.Problem("Engine management disabled",statusCode:403);
    return Results.Ok(enginePaths.Select(row => new {
        engineId=row.Key, revision=Sha(File.ReadAllBytes(row.Value)),
        mode="signed-file-staging-only", serviceRestarted=false
    }).ToArray());
});

app.MapPost("/agent/v1/engines/{engineId}/config/prepare", async (string engineId, EnginePrepare input) =>
{
    if (!allowEngineConfigChanges) return Results.Problem("Engine management disabled",statusCode:403);
    if (!enginePaths.TryGetValue(engineId,out var configPath)) return Results.NotFound();
    if (!ValidTx(input.TransactionId) || input.Config is not JsonObject candidate ||
        !EngineConfigContract.Validate(engineId,candidate,allowEnginePublicBind))
        return Results.BadRequest(new { error="Invalid engine config or listener binding policy" });
    var signature=new FleetConfigSignature.SignedV2(input.KeyId,input.Sequence,
        input.ExpiresUnixSeconds,input.Signature);
    if (!EngineConfigContract.Verify(signingKeys,engineId,input.TransactionId,
        input.ExpectedRevision,candidate,signature,DateTimeOffset.UtcNow.ToUnixTimeSeconds()))
        return Results.Problem("Invalid, expired or wrong-engine signed payload",statusCode:403);
    await revisionLock.WaitAsync();
    try
    {
        var original=await File.ReadAllBytesAsync(configPath);
        var revision=Sha(original);
        if (!revision.Equals(input.ExpectedRevision,StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new {error="Engine config drift",currentRevision=revision});
        var staging=Path.Combine(stageRoot,"engines",engineId);
        Directory.CreateDirectory(staging);
        var tx=Path.Combine(staging,input.TransactionId);
        if (Directory.Exists(tx)) return Results.Conflict(new {error="Duplicate transaction"});
        var seqPath=Path.Combine(staging,"last-accepted-sequence.txt");
        if (input.Sequence <= FleetSequenceState.Read(seqPath))
            return Results.Conflict(new {error="Signed sequence reused"});
        FleetSequenceState.Accept(seqPath,input.Sequence);
        Directory.CreateDirectory(tx);
        var proposed=Encoding.UTF8.GetBytes(candidate.ToJsonString(new JsonSerializerOptions{WriteIndented=true}));
        await File.WriteAllBytesAsync(Path.Combine(tx,"original.json"),original);
        await File.WriteAllBytesAsync(Path.Combine(tx,"prepared.json"),proposed);
        await File.WriteAllTextAsync(Path.Combine(tx,"sequence.txt"),input.Sequence.ToString(
            System.Globalization.CultureInfo.InvariantCulture));
        return Results.Ok(new {state="prepared",engineId,transactionId=input.TransactionId,
            originalRevision=revision,preparedRevision=Sha(proposed)});
    }
    finally {revisionLock.Release();}
});

app.MapPost("/agent/v1/engines/{engineId}/config/activate", async (string engineId, EngineActivate input) =>
{
    if (!allowEngineConfigChanges) return Results.Problem("Engine management disabled",statusCode:403);
    if (!enginePaths.TryGetValue(engineId,out var configPath)) return Results.NotFound();
    if (!ValidTx(input.TransactionId)) return Results.BadRequest();
    await revisionLock.WaitAsync();
    try
    {
        var stage=Path.Combine(stageRoot,"engines",engineId);
        var tx=Path.Combine(stage,input.TransactionId);
        var prepared=Path.Combine(tx,"prepared.json");
        var originalPath=Path.Combine(tx,"original.json");
        var seqFile=Path.Combine(tx,"sequence.txt");
        if (!File.Exists(prepared) || !File.Exists(originalPath) || !File.Exists(seqFile))
            return Results.NotFound();
        if (!long.TryParse(await File.ReadAllTextAsync(seqFile),out var sequence) ||
            sequence != FleetSequenceState.Read(Path.Combine(stage,"last-accepted-sequence.txt")))
            return Results.Conflict(new {error="Transaction superseded"});
        var proposed=await File.ReadAllBytesAsync(prepared);
        if (!Sha(proposed).Equals(input.PreparedRevision,StringComparison.OrdinalIgnoreCase))
            return Results.Conflict(new {error="Prepared revision mismatch"});
        var original=await File.ReadAllBytesAsync(originalPath);
        if (Sha(await File.ReadAllBytesAsync(configPath)) != Sha(original))
            return Results.Conflict(new {error="Engine config changed after prepare"});
        await File.WriteAllBytesAsync(configPath+".next",proposed);
        File.Move(configPath+".next",configPath,true);
        app.Logger.LogWarning("Engine {Engine} config activated transaction {Tx}; restart NOT performed",engineId,input.TransactionId);
        return Results.Ok(new {engineId,state="activated-file-only",revision=Sha(proposed),requiresRestart=true});
    }
    finally {revisionLock.Release();}
});

app.MapPost("/agent/v1/engines/{engineId}/config/rollback", async (string engineId, EngineRollback input) =>
{
    if (!allowEngineConfigChanges) return Results.Problem("Engine management disabled",statusCode:403);
    if (!enginePaths.TryGetValue(engineId,out var configPath)) return Results.NotFound();
    if (!ValidTx(input.TransactionId)) return Results.BadRequest();
    await revisionLock.WaitAsync();
    try
    {
        var stage=Path.Combine(stageRoot,"engines",engineId);
        var tx=Path.Combine(stage,input.TransactionId);
        var originalPath=Path.Combine(tx,"original.json");
        var preparedPath=Path.Combine(tx,"prepared.json");
        var seqFile=Path.Combine(tx,"sequence.txt");
        if (!File.Exists(originalPath) || !File.Exists(preparedPath) || !File.Exists(seqFile))
            return Results.NotFound();
        if (!long.TryParse(await File.ReadAllTextAsync(seqFile),out var sequence) ||
            sequence != FleetSequenceState.Read(Path.Combine(stage,"last-accepted-sequence.txt")))
            return Results.Conflict(new {error="Cannot roll back superseded transaction"});
        var original=await File.ReadAllBytesAsync(originalPath);
        var proposed=await File.ReadAllBytesAsync(preparedPath);
        var actual=Sha(await File.ReadAllBytesAsync(configPath));
        if (actual != Sha(original) && actual != Sha(proposed))
            return Results.Conflict(new {error="Engine config drift; manual recovery required"});
        await File.WriteAllBytesAsync(configPath+".next",original);
        File.Move(configPath+".next",configPath,true);
        app.Logger.LogWarning("Engine {Engine} config rolled back transaction {Tx}; restart NOT performed",engineId,input.TransactionId);
        return Results.Ok(new {engineId,state="rolled-back-file-only",revision=Sha(original),requiresRestart=true});
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

record ConfigPrepare(string TransactionId, string ExpectedRevision, JsonObject ReverseProxy,
    long ExpiresUnixSeconds, long Sequence, string KeyId, string Signature);
record ConfigActivate(string TransactionId, string PreparedRevision);
record ConfigRollback(string TransactionId);

record EnginePrepare(string TransactionId,string ExpectedRevision,JsonObject Config,
    long ExpiresUnixSeconds,long Sequence,string KeyId,string Signature);
record EngineActivate(string TransactionId,string PreparedRevision);
record EngineRollback(string TransactionId);
