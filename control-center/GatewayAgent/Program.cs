using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Server.Kestrel.Https;

#if GATEWAYCORE_COMMERCIAL
if(EngineLicenseGate.VerifyReleaseOrExit(args,out var releaseExit)){Environment.ExitCode=releaseExit;return;}
if(EngineLicenseGate.Command(args,out var licenseExit)){Environment.ExitCode=licenseExit;return;}
// Local service operator can explicitly start an authenticated rollback-only
// process even when normal startup is blocked by revoked/unreadable state.
// This is never a remote setting and never grants deployment/service actions.
var recoveryOnly=string.Equals(Environment.GetEnvironmentVariable("GATEWAYCORE_AGENT_RECOVERY_ONLY"),"true",StringComparison.Ordinal);
using var engineLicense=recoveryOnly?null:EngineLicenseGate.Start("ha","fleet");
#endif
// Separate, least-privileged gateway-agent reference implementation.
// Fail-closed: no trusted controller certificate = no remote access.
var builder = WebApplication.CreateBuilder(args);
var allowedThumbprints = builder.Configuration.GetSection("Agent:TrustedClientThumbprints").Get<string[]>() ?? [];
var allowedServices = builder.Configuration.GetSection("Agent:AllowedServices").Get<string[]>() ?? [];
var allowActions = builder.Configuration.GetValue<bool>("Agent:EnableServiceActions");
var allowConfigChanges = builder.Configuration.GetValue<bool>("Agent:EnableConfigChanges");
#if GATEWAYCORE_COMMERCIAL
using var fleetQuorum=FleetQuorum.Open(Environment.GetEnvironmentVariable("GATEWAYCORE_AGENT_QUORUM_CONFIG"),false);
if(allowConfigChanges && fleetQuorum is null)
    throw new InvalidOperationException("Commercial gateway config changes require authenticated quorum configuration.");
if(allowConfigChanges && !recoveryOnly && fleetQuorum!.Scope!=engineLicense!.FleetScope())
    throw new InvalidOperationException("Agent quorum scope differs from signed deployment.");
async Task<bool> VerifyFleetFence(string tx,long epoch,bool rollback=false)
{
    try
    {
        if(fleetQuorum is null || (!rollback && (engineLicense is null || fleetQuorum.Scope!=engineLicense.FleetScope())))return false;
        await fleetQuorum.Assert(tx,epoch);
        return rollback || (engineLicense!.Allows("ha") && engineLicense.Allows("fleet"));
    }
    catch(Exception ex) when(ex is IOException or HttpRequestException or InvalidOperationException or
        CryptographicException or ArgumentException or JsonException or FormatException or OverflowException)
    {return false;}
}
#endif
var allowEngineConfigChanges = builder.Configuration.GetValue<bool>("Agent:EnableEngineConfigChanges");
var allowEnginePublicBind = builder.Configuration.GetValue<bool>("Agent:AllowEngineNonLoopbackListeners");
var gslbMetricsPort = builder.Configuration.GetValue<int>("Agent:GslbMetricsPort");
var gslbRestartEnabled = builder.Configuration.GetValue<bool>("Agent:EnableGslbSignedRestart");
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
if (gslbMetricsPort != 0 && (gslbMetricsPort is < 1025 or > 65535))
    throw new InvalidOperationException("GSLB runtime metrics port must be 0 (disabled) or 1025..65535");
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
var gslbRestartCommand = gslbRestartEnabled ? GslbServiceRestart.ForHost() : null;
if (gslbRestartEnabled && (!allowEngineConfigChanges || gslbMetricsPort == 0 ||
    !enginePaths.ContainsKey("gslb") || gslbRestartCommand is null))
    throw new InvalidOperationException("Signed GSLB restart requires explicit engine staging, loopback revision metrics and supported host service control.");
#if GATEWAYCORE_COMMERCIAL
if (allowEngineConfigChanges && (fleetQuorum is null ||
    (!recoveryOnly && fleetQuorum.Scope != engineLicense!.FleetScope())))
    throw new InvalidOperationException("Commercial engine changes require the authenticated deployment quorum.");
#endif
if (allowConfigChanges || allowEngineConfigChanges) Directory.CreateDirectory(stageRoot);
var sequencePath = Path.Combine(stageRoot, "last-accepted-sequence.txt");
var revisionLock = new SemaphoreSlim(1,1);
static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data));
static bool ValidTx(string id) => Regex.IsMatch(id, "^[A-Za-z0-9_-]{12,80}$");
// Keep request-derived fields on a single physical log record. Do not change the operation input.
static string SafeLogField(string value) => value.Replace("\\", "\\\\").Replace("\r", "\\r").Replace("\n", "\\n")
    .Replace("\u0085", "\\u0085").Replace("\u2028", "\\u2028").Replace("\u2029", "\\u2029");
_ = AgentClientCertificatePolicy.ParsePinnedThumbprints(allowedThumbprints); // Fail closed at startup
if (allowedServices.Any(x => !Regex.IsMatch(x, "^[A-Za-z0-9_.-]{1,64}$")))
    throw new InvalidOperationException("Invalid allowlisted Windows service name");
// Isolated self-signed test CA is allowed ONLY on loopback with ALL mutating
// management features disabled. It is not a production PKI trust shortcut.
var labCaPath = builder.Configuration["Agent:LabOnlyClientCaCertificatePath"];
var labCaCheckRevocation = builder.Configuration.GetValue<bool>("Agent:LabOnlyClientCaCheckRevocation");
if (labCaCheckRevocation && string.IsNullOrWhiteSpace(labCaPath))
    throw new InvalidOperationException("Lab-only CRL checking requires an explicit loopback test CA");
X509Certificate2? labRoot = null;
ILogger? clientCertificateLogger = null;
static void AddPeerPresentedChainCertificates(
    X509Chain target, X509Chain? peerChain, X509Certificate2 leaf, X509Certificate2? trustAnchor)
{
    if (peerChain is null) return;
    var added = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        leaf.Thumbprint
    };
    if (trustAnchor is not null) added.Add(trustAnchor.Thumbprint);
    foreach (var element in peerChain.ChainElements.Cast<X509ChainElement>())
    {
        var candidate = element.Certificate;
        if (added.Add(candidate.Thumbprint))
            target.ChainPolicy.ExtraStore.Add(candidate);
    }
}
if (!string.IsNullOrWhiteSpace(labCaPath))
{
    var listener = builder.Configuration["Kestrel:Endpoints:AgentHttps:Url"] ?? "";
    static bool IsLoopbackHttpsUrl(string? value)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) ||
            uri.Scheme != Uri.UriSchemeHttps || !string.IsNullOrEmpty(uri.UserInfo) ||
            !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) ||
            uri.AbsolutePath != "/" ||
            !IPAddress.TryParse(uri.IdnHost, out var address))
            return false;
        return IPAddress.IsLoopback(address);
    }
    var configuredEndpoints = builder.Configuration.GetSection("Kestrel:Endpoints")
        .GetChildren().ToArray();
    var everyEndpointIsLoopback = configuredEndpoints.Length > 0 &&
        configuredEndpoints.All(endpoint => IsLoopbackHttpsUrl(
            builder.Configuration[$"Kestrel:Endpoints:{endpoint.Key}:Url"]));
    // Kestrel may also receive URL bindings from ASPNETCORE_URLS. Reject an
    // unsafe secondary binding even when explicit named endpoints are present.
    var configuredUrls = builder.Configuration["urls"];
    var everyUrlIsLoopback = string.IsNullOrWhiteSpace(configuredUrls) ||
        configuredUrls.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .All(IsLoopbackHttpsUrl);
    // ASPNETCORE_HTTP_PORTS / ASPNETCORE_HTTPS_PORTS are WebHost defaults that
    // bind wildcard listeners. They do not flow through the `urls` setting, so
    // reject them explicitly while the isolated lab trust root is enabled.
    var configuredHttpPorts = builder.Configuration["http_ports"];
    var configuredHttpsPorts = builder.Configuration["https_ports"];
    var hasDefaultPortBindings = !string.IsNullOrWhiteSpace(configuredHttpPorts) ||
        !string.IsNullOrWhiteSpace(configuredHttpsPorts);
    if (!Path.IsPathFullyQualified(labCaPath) || !File.Exists(labCaPath) ||
        !IsLoopbackHttpsUrl(listener) || !everyEndpointIsLoopback || !everyUrlIsLoopback ||
        hasDefaultPortBindings ||
        allowConfigChanges || allowEngineConfigChanges ||
        allowActions)
        throw new InvalidOperationException(
            "Isolated client test CA is restricted to HTTPS loopback-only listeners with all management changes disabled");
    // Public test-root PEM has NO private key; do not call CreateFromPemFile,
    // which attempts to load a corresponding key from the same PEM path.
    labRoot = X509CertificateLoader.LoadCertificateFromFile(labCaPath);
    if (!labRoot.Extensions.OfType<X509BasicConstraintsExtension>().Any(x=>x.CertificateAuthority))
        throw new InvalidOperationException("Lab trust anchor is not a CA certificate");
}
builder.WebHost.ConfigureKestrel(server =>
{
    server.ConfigureHttpsDefaults(https =>
    {
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        https.CheckCertificateRevocation = labRoot is null;
        if (labRoot is not null)
        {
            https.ClientCertificateValidation = (cert, peerChain, _) =>
            {
                if (cert is null) return false;
                clientCertificateLogger?.LogInformation(
                    "Validating lab TLS client certificate {CertificateThumbprint} with online revocation {RevocationEnabled}",
                    cert.Thumbprint.ToUpperInvariant(), labCaCheckRevocation);
                // Revocation stays disabled for the ordinary lab trust root;
                // dedicated loopback CRL acceptance opts in to online checks.
                using var custom = new X509Chain();
                custom.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                custom.ChainPolicy.CustomTrustStore.Add(labRoot);
                custom.ChainPolicy.RevocationMode = labCaCheckRevocation
                    ? X509RevocationMode.Online
                    : X509RevocationMode.NoCheck;
                if (labCaCheckRevocation)
                {
                    custom.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    custom.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                    custom.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                }
                custom.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                // The TLS peer may send intermediate certificates that are not
                // installed in the machine store. They are chain candidates only;
                // CustomRootTrust and normal chain validation still determine trust.
                AddPeerPresentedChainCertificates(custom, peerChain, cert, labRoot);
                var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>()
                    .Any(ext => ext.EnhancedKeyUsages.Cast<Oid>()
                        .Any(oid => oid.Value=="1.3.6.1.5.5.7.3.2"));
                var built = custom.Build(cert);
                if (!built)
                {
                    var statuses = string.Join(",", custom.ChainStatus
                        .Select(status => status.Status.ToString()).Distinct().Order(StringComparer.Ordinal));
                    clientCertificateLogger?.LogWarning(
                        "Rejected lab TLS client certificate {CertificateThumbprint} during chain validation; chain statuses: {ChainStatuses}",
                        cert.Thumbprint.ToUpperInvariant(), statuses);
                }
                return eku && built;
            };
        }
        else
        {
            // Explicitly build the production client chain with online revocation
            // before any HTTP request reaches the application pipeline. Do not
            // rely solely on platform-specific Kestrel revocation defaults.
            https.ClientCertificateValidation = (cert, peerChain, _) =>
            {
                if (cert is null) return false;
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                // Check the leaf and intermediate certificates; a trust anchor
                // does not need a revocation CRL of its own.
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.2"));
                // Peer certificates remain untrusted chain candidates: the OS
                // trust store, EKU, time validity and online revocation checks
                // continue to govern admission.
                AddPeerPresentedChainCertificates(chain, peerChain, cert, null);
                var result = chain.Build(cert);
                if (!result)
                {
                    var statuses = string.Join(",", chain.ChainStatus
                        .Select(status => status.Status.ToString()).Distinct().Order(StringComparer.Ordinal));
                    clientCertificateLogger?.LogWarning(
                        "Rejected TLS client certificate {CertificateThumbprint} during chain validation; chain statuses: {ChainStatuses}",
                        cert.Thumbprint.ToUpperInvariant(), statuses);
                }
                return result;
            };
        }
    });
});
var app = builder.Build();
clientCertificateLogger = app.Services.GetRequiredService<ILoggerFactory>()
    .CreateLogger("GatewayAgent.ClientCertificate");
var pinSetRevisionAudit = new AgentPinSetRevisionAudit(clientCertificateLogger);
if (labRoot is not null)
    clientCertificateLogger.LogInformation(
        "Loopback lab client CA configured; online revocation checks enabled {RevocationEnabled}",
        labCaCheckRevocation);

app.Use(async (ctx, next) =>
{
    // Kestrel performs TLS chain validation. This additionally pins controller identities.
    if (!AgentClientCertificatePolicy.IsAuthorizedLive(ctx, builder.Configuration,
        pinSetRevisionAudit.RecordRevision))
    { ctx.Response.StatusCode = StatusCodes.Status403Forbidden; return; }
    ctx.Response.Headers.CacheControl = "no-store";
#if GATEWAYCORE_COMMERCIAL
    // Permit authenticated rollback as a compensating safety operation.
    var path=ctx.Request.Path.Value??"";
    var rollback=ctx.Request.Method=="POST" &&
        (path.Equals("/agent/v1/config/rollback",StringComparison.OrdinalIgnoreCase) ||
         path.Equals("/agent/v1/engines/l4/config/rollback",StringComparison.OrdinalIgnoreCase) ||
         path.Equals("/agent/v1/engines/gslb/config/rollback",StringComparison.OrdinalIgnoreCase));
    var recoveryStatus=ctx.Request.Method=="GET" && path.Equals("/agent/v1/status",StringComparison.OrdinalIgnoreCase);
    if(!rollback && !recoveryStatus &&
        (recoveryOnly || engineLicense is null || !engineLicense.Allows("ha") || !engineLicense.Allows("fleet") ||
        (ctx.Request.Path.StartsWithSegments("/agent/v1/engines/l4") && !engineLicense.Allows("l4")) ||
        (ctx.Request.Path.StartsWithSegments("/agent/v1/engines/gslb") && !engineLicense.Allows("gslb"))))
    {ctx.Response.StatusCode=402;return;}
#endif
    await next();
});

#if GATEWAYCORE_COMMERCIAL
// mTLS identity middleware runs first. Fresh challenge is signed using the
// installation identity and exact persisted issuer envelope, never the TLS key.
app.MapPost("/agent/v1/license/proof",(FleetLicenseChallenge input)=>
{
    if(engineLicense is null)return Results.StatusCode(402);
    try{return Results.Ok(new {proof=engineLicense.CreateFleetProof(input.Challenge)});}
    catch(Exception e) when(e is IOException or CryptographicException or InvalidDataException or
        JsonException or ArgumentException or InvalidOperationException or UnauthorizedAccessException or FormatException)
    {return Results.StatusCode(402);}
});
#endif

app.MapGet("/agent/v1/status", () => Results.Ok(new
{
    machine = Environment.MachineName,
    utc = DateTimeOffset.UtcNow,
    serviceManagementEnabled = allowActions,
    configDeploymentEnabled = allowConfigChanges,
    rollbackFenceProtocol = 1,
    engineConfigStagingEnabled = allowEngineConfigChanges,
    revision = allowConfigChanges ? Sha(File.ReadAllBytes(gatewayConfigPath)) : null,
    allowedServiceNames = allowedServices,
    highestAcceptedSequence = allowConfigChanges ? FleetSequenceState.Read(sequencePath) : 0,
#if GATEWAYCORE_COMMERCIAL
    quorumFenceProtocol = fleetQuorum is not null ? 1 : 0,
    quorumScope = fleetQuorum?.Scope,
#endif
    // This reports agent responsiveness only. NOT YARP's internal destination health.
    kind = "authenticated-agent-status"
}));

app.MapGet("/agent/v1/engines/gslb/runtime-status", async (CancellationToken cancellationToken) =>
{
    if (gslbMetricsPort == 0) return Results.NotFound();
    using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
    using var client = new HttpClient(handler)
    {
        Timeout = TimeSpan.FromSeconds(2),
        MaxResponseContentBufferSize = 16_384
    };
    try
    {
        using var response = await client.GetAsync(
            $"http://127.0.0.1:{gslbMetricsPort}/metrics", cancellationToken);
        if (!response.IsSuccessStatusCode ||
            response.Content.Headers.ContentType?.MediaType != "text/plain")
            return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
        var body = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!GslbRuntimeMetricsParser.TryParse(body, out var snapshot) || snapshot is null)
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        using var statusResponse = await client.GetAsync(
            $"http://127.0.0.1:{gslbMetricsPort}/agent-report-status", cancellationToken);
        if (!statusResponse.IsSuccessStatusCode ||
            statusResponse.Content.Headers.ContentType?.MediaType != "application/json")
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        var statusBody = await statusResponse.Content.ReadAsStringAsync(cancellationToken);
        if (!GslbAgentReportStatusParser.TryParse(statusBody, out var agentStatus) || agentStatus is null)
            return Results.StatusCode(StatusCodes.Status502BadGateway);
        return Results.Ok(new
        {
            type = "loopback-gslb-runtime-metrics",
            checkedUtc = DateTimeOffset.UtcNow,
            quorumTargets = new { configured = snapshot.ConfiguredTargets,
                quorum = snapshot.QuorumTargets, belowQuorum = snapshot.BelowQuorumTargets },
            observerReports = new { healthy = snapshot.HealthyReports,
                unhealthy = snapshot.UnhealthyReports, unknown = snapshot.UnknownReports,
                staleOrMissing = snapshot.StaleOrMissingReports },
            observerAgentsCheckedUtc = agentStatus.CheckedUtc,
            observerAgents = agentStatus.Agents
        });
    }
    catch (HttpRequestException)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
    catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
    {
        return Results.StatusCode(StatusCodes.Status503ServiceUnavailable);
    }
});

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
        SafeLogField(body.Action), SafeLogField(serviceName), ctx.Connection.ClientCertificate?.Thumbprint, result.exitCode);
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
#if GATEWAYCORE_COMMERCIAL
        if(!await VerifyFleetFence(input.TransactionId,input.Sequence))
            return Results.StatusCode(409);
#endif
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
        if (File.Exists(Path.Combine(tx, "rollback-fence")))
            return Results.Conflict(new { error = "Transaction fenced by rollback" });
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
#if GATEWAYCORE_COMMERCIAL
        if(!await VerifyFleetFence(input.TransactionId,preparedSequence))
        {File.Delete(gatewayConfigPath+".next");return Results.StatusCode(409);}
#endif
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
#if GATEWAYCORE_COMMERCIAL
        if(!await VerifyFleetFence(input.TransactionId,preparedSequence,rollback:true))
            return Results.StatusCode(409);
#endif
        // Fence activation BEFORE restoring the original. A crash cannot make
        // this transaction eligible for a delayed activation after rollback.
        var fence = Path.Combine(tx, "rollback-fence");
        if (!File.Exists(fence))
        {
            using var journal = new FileStream(fence, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            journal.WriteByte(1);
            journal.Flush(flushToDisk: true);
        }
        if (Sha(actual) != Sha(original))
        {
            var next = gatewayConfigPath + ".next";
            using (var journal = new FileStream(next, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                journal.Write(original);
                journal.Flush(flushToDisk: true);
            }
            File.Move(next, gatewayConfigPath, true);
        }
        return Results.Ok(new {state="rolled-back",revision=Sha(original),rollbackFenced=true});
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
        if (engineId == "gslb")
        {
            JsonNode? currentNode;
            try { currentNode = JsonNode.Parse(original); }
            catch (JsonException) { return Results.Conflict(new {error="Current GSLB config is not valid JSON object"}); }
            if (currentNode is not JsonObject current)
                return Results.Conflict(new {error="Current GSLB config is not valid JSON object"});
            if (!EngineConfigContract.ValidSoaSerialTransition(current,candidate))
                return Results.BadRequest(new {error="Changed authoritative GSLB zones require an RFC 1982 SOA serial advance"});
        }
        var staging=Path.Combine(stageRoot,"engines",engineId);
        Directory.CreateDirectory(staging);
        var tx=Path.Combine(staging,input.TransactionId);
        if (Directory.Exists(tx)) return Results.Conflict(new {error="Duplicate transaction"});
        var seqPath=Path.Combine(staging,"last-accepted-sequence.txt");
        if (input.Sequence <= FleetSequenceState.Read(seqPath))
            return Results.Conflict(new {error="Signed sequence reused"});
#if GATEWAYCORE_COMMERCIAL
        if (!await VerifyFleetFence(input.TransactionId,input.Sequence)) return Results.StatusCode(409);
#endif
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
        if (EngineConfigContract.IsRollbackFenced(tx))
            return Results.Conflict(new {error="Engine transaction fenced by rollback"});
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
#if GATEWAYCORE_COMMERCIAL
        if (!await VerifyFleetFence(input.TransactionId,sequence))
        { File.Delete(configPath+".next"); return Results.StatusCode(409); }
#endif
        File.Move(configPath+".next",configPath,true);
        app.Logger.LogWarning("Engine {Engine} config activated transaction {Tx}; restart NOT performed",SafeLogField(engineId),SafeLogField(input.TransactionId));
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
        if (File.Exists(Path.Combine(tx,"restart-intent")))
            return Results.Conflict(new {error="Runtime restart may have published this revision; forward recovery required"});
#if GATEWAYCORE_COMMERCIAL
        if (!await VerifyFleetFence(input.TransactionId,sequence,rollback:true)) return Results.StatusCode(409);
#endif
        // Persist the fence before restoring bytes. Even rollback of a merely
        // prepared transaction must prohibit a delayed activation after restart.
        EngineConfigContract.MarkRollback(tx);
        if (actual != Sha(original))
        {
            var next = configPath+".next";
            using (var journal = new FileStream(next, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                journal.Write(original);
                journal.Flush(flushToDisk: true);
            }
            File.Move(next,configPath,true);
        }
        app.Logger.LogWarning("Engine {Engine} config rolled back transaction {Tx}; restart NOT performed",SafeLogField(engineId),SafeLogField(input.TransactionId));
        return Results.Ok(new {engineId,state="rolled-back-file-only",revision=Sha(original),requiresRestart=true,rollbackFenced=true});
    }
    finally {revisionLock.Release();}
});

async Task<string?> LoadedGslbRevision(CancellationToken token)
{
    if (gslbMetricsPort == 0) return null;
    using var handler = new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false };
    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(2), MaxResponseContentBufferSize = 1024 };
    using var response = await client.GetAsync($"http://127.0.0.1:{gslbMetricsPort}/config-revision", token);
    if (!response.IsSuccessStatusCode) return null;
    using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync(token));
    var root = document.RootElement;
    if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("type",out var type) ||
        type.GetString() != "gslb-loaded-config-revision" || !root.TryGetProperty("revision",out var item))
        return null;
    var digest = item.GetString();
    return digest is not null && Regex.IsMatch(digest,"^[A-F0-9]{64}$") ? digest : null;
}

app.MapGet("/agent/v1/engines/gslb/config/revision", async (CancellationToken token) =>
{
    if (!allowEngineConfigChanges || !enginePaths.TryGetValue("gslb",out var path)) return Results.NotFound();
    try
    {
        var loaded = await LoadedGslbRevision(token);
        return Results.Ok(new { fileRevision=Sha(await File.ReadAllBytesAsync(path,token)),
            loadedRevision=loaded, restartEnabled=gslbRestartEnabled });
    }
    catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or TaskCanceledException or InvalidOperationException)
    { return Results.StatusCode(503); }
});

app.MapPost("/agent/v1/engines/gslb/config/restart", async (EngineActivate input) =>
{
    if (!gslbRestartEnabled || !enginePaths.TryGetValue("gslb",out var path)) return Results.StatusCode(403);
    if (!ValidTx(input.TransactionId)) return Results.BadRequest();
    await revisionLock.WaitAsync();
    try
    {
        var stage=Path.Combine(stageRoot,"engines","gslb");
        var tx=Path.Combine(stage,input.TransactionId);
        var prepared=Path.Combine(tx,"prepared.json");
        var original=Path.Combine(tx,"original.json");
        var sequenceFile=Path.Combine(tx,"sequence.txt");
        if (!File.Exists(prepared) || !File.Exists(original) || !File.Exists(sequenceFile)) return Results.NotFound();
        if (EngineConfigContract.IsRollbackFenced(tx) || File.Exists(Path.Combine(tx,"restart-intent")) ||
            !long.TryParse(await File.ReadAllTextAsync(sequenceFile),out var sequence) ||
            sequence != FleetSequenceState.Read(Path.Combine(stage,"last-accepted-sequence.txt")))
            return Results.Conflict(new {error="Restart superseded, fenced or already attempted"});
        var digest=Sha(await File.ReadAllBytesAsync(prepared));
        var originalDigest=Sha(await File.ReadAllBytesAsync(original));
        if (digest != input.PreparedRevision || digest != Sha(await File.ReadAllBytesAsync(path)) ||
            digest == originalDigest || await LoadedGslbRevision(CancellationToken.None) != originalDigest)
            return Results.Conflict(new {error="File activation or original runtime revision not confirmed"});
#if GATEWAYCORE_COMMERCIAL
        if (!await VerifyFleetFence(input.TransactionId,sequence)) return Results.StatusCode(409);
#endif
        // A restart may publish a new SOA serial. Record uncertainty before
        // dispatch; never automatically replay or restore the older serial.
        using (var intent = new FileStream(Path.Combine(tx,"restart-intent"),FileMode.CreateNew,FileAccess.Write,FileShare.None))
        { intent.WriteByte(1); intent.Flush(flushToDisk:true); }
        using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(60));
        if (!await GslbServiceRestart.RunAsync(gslbRestartCommand!, timeout.Token))
            return Results.StatusCode(503);
        while (!timeout.IsCancellationRequested)
        {
            try
            {
                if (await LoadedGslbRevision(timeout.Token) == digest &&
                    Sha(await File.ReadAllBytesAsync(path,timeout.Token)) == digest)
                {
#if GATEWAYCORE_COMMERCIAL
                    if (!await VerifyFleetFence(input.TransactionId,sequence)) return Results.StatusCode(409);
#endif
                    return Results.Ok(new {state="restarted-revision-confirmed",revision=digest,requiresDnsProbe=true});
                }
            }
            catch (Exception ex) when (ex is HttpRequestException or IOException or JsonException or TaskCanceledException or InvalidOperationException) { }
            await Task.Delay(250,timeout.Token);
        }
        return Results.StatusCode(503);
    }
    catch (Exception ex) when (ex is IOException or HttpRequestException or JsonException or OperationCanceledException or InvalidOperationException or System.ComponentModel.Win32Exception)
    { return Results.StatusCode(503); }
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

#if GATEWAYCORE_COMMERCIAL
record FleetLicenseChallenge(string Challenge);
#endif
