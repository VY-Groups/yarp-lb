using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Npgsql;
using GatewayCore.Licensing;
using GatewayCore.LicenseAuthority;

var builder = WebApplication.CreateBuilder(args);
var config = builder.Configuration;
var pinPath = config["Portal:OperatorPins"] ?? throw new InvalidOperationException("Operator certificate pins required.");
var pinInfo = new FileInfo(pinPath);
if (pinInfo.Length is < 1 or > 32768) throw new InvalidDataException("Invalid operator pin configuration size.");
var operators = JsonSerializer.Deserialize<Dictionary<string, PortalOperator>>(File.ReadAllBytes(pinPath),
    new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
    ?? throw new InvalidDataException("Missing operator identities.");
if (operators.Count is < 2 or > 100 ||
    operators.Any(x => x.Key.Length != 64 || x.Key.Any(c => c is not (>= '0' and <= '9' or >= 'A' and <= 'F')) ||
        !Id(x.Value.Id) || x.Value.Role is not ("requester" or "reviewer")) ||
    operators.Values.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != operators.Count ||
    !operators.Values.Any(x => x.Role == "requester") || !operators.Values.Any(x => x.Role == "reviewer"))
    throw new InvalidDataException("Require distinct pinned operator identities and roles.");

PortalOperator? Identity(X509Certificate2? cert)
{
    if (cert is null || DateTime.UtcNow < cert.NotBefore.ToUniversalTime() ||
        DateTime.UtcNow >= cert.NotAfter.ToUniversalTime()) return null;
    var eku = cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().SingleOrDefault();
    if (eku is null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")) return null;
    return operators.GetValueOrDefault(cert.GetCertHashString(HashAlgorithmName.SHA256));
}

builder.WebHost.ConfigureKestrel(k =>
{
    k.Limits.MaxRequestBodySize = 32768;
    k.ConfigureHttpsDefaults(h =>
    {
        h.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        // Explicit leaf pinning is the trust policy; no generic CA identity
        // or forwarded certificate header is accepted.
        h.ClientCertificateValidation = (cert, _, _) => Identity(cert) is not null;
    });
});
var db = NpgsqlDataSource.Create(config.GetConnectionString("Licensing") ??
    throw new InvalidOperationException("Licensing database required."));
builder.Services.AddSingleton(db);
var app = builder.Build();
var expectedOrigin = new Uri(config["Portal:Origin"] ?? throw new InvalidOperationException("HTTPS portal origin required."));
if (expectedOrigin.Scheme != "https" || expectedOrigin.AbsolutePath != "/" ||
    !string.IsNullOrEmpty(expectedOrigin.UserInfo) || !string.IsNullOrEmpty(expectedOrigin.Query) ||
    !string.IsNullOrEmpty(expectedOrigin.Fragment)) throw new InvalidDataException("Invalid portal origin.");

app.Use(async (ctx, next) =>
{
    if (!ctx.Request.IsHttps || !string.Equals(ctx.Request.Host.Value, expectedOrigin.Authority, StringComparison.OrdinalIgnoreCase))
    { ctx.Response.StatusCode = 403; return; }
    var actor = Identity(await ctx.Connection.GetClientCertificateAsync(ctx.RequestAborted));
    if (actor is null) { ctx.Response.StatusCode = 401; return; }
    ctx.Items["actor"] = actor;
    ctx.Response.Headers.CacheControl = "no-store";
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
    if (ctx.Request.Method != "GET")
    {
        if (ctx.Request.Method != "POST" || !ctx.Request.HasJsonContentType() ||
            ctx.Request.Headers["X-GC-Portal"] != "1" ||
            ctx.Request.Headers.Origin != expectedOrigin.GetLeftPart(UriPartial.Authority))
        { ctx.Response.StatusCode = 403; return; }
    }
    await next();
});
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/api/session", (HttpContext ctx) => Results.Ok(Actor(ctx)));
app.MapGet("/api/customers", async (NpgsqlDataSource ds) => Results.Ok(await ReadRows(ds,
    "SELECT id,name,created_at FROM gc_customers ORDER BY created_at DESC LIMIT 500")));
app.MapGet("/api/subscriptions", async (NpgsqlDataSource ds) => Results.Ok(await ReadRows(ds,
    "SELECT id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features,terms_revision FROM gc_subscriptions ORDER BY created_at DESC LIMIT 500")));
app.MapGet("/api/jobs", async (NpgsqlDataSource ds) => Results.Ok(await ReadRows(ds,
    "SELECT j.id,j.subscription_id,j.kind,j.site_id,j.installation_hash,j.allocation_id,j.requested_by,j.requested_at,j.approved_by,j.approved_at,j.state,j.expected_terms_revision,j.proposed_terms::text AS proposed_terms,r.completed_at FROM gc_license_jobs j LEFT JOIN gc_issuer_results r ON r.job_id=j.id ORDER BY j.requested_at DESC LIMIT 500")));

app.MapPost("/api/customers", async (HttpContext ctx, CustomerInput input) =>
{
    if (Actor(ctx).Role != "requester") return Results.StatusCode(403);
    if (!Id(input.Id) || string.IsNullOrWhiteSpace(input.Name) || input.Name.Length > 200) return Results.BadRequest();
    await using var conn = await db.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();
    try
    {
        await using var cmd = new NpgsqlCommand("INSERT INTO gc_customers(id,name) VALUES($1,$2)", conn, tx);
        cmd.Parameters.AddWithValue(input.Id); cmd.Parameters.AddWithValue(input.Name.Trim());
        await cmd.ExecuteNonQueryAsync();
        await Audit(conn, tx, Actor(ctx).Id, "customer_created", input.Id);
        await tx.CommitAsync();
        return Results.Ok(new { id = input.Id });
    }
    catch (PostgresException e) when (e.SqlState == PostgresErrorCodes.UniqueViolation) { return Results.Conflict(); }
});
app.MapPost("/api/subscriptions", async (HttpContext ctx, Subscription input) =>
{
    if (Actor(ctx).Role != "requester") return Results.StatusCode(403);
    if (!ValidTerms(input)) return Results.BadRequest(new { error = "Invalid subscription terms." });
    await using var conn = await db.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();
    try
    {
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO gc_subscriptions(id,customer_id,deployment_id,edition,max_nodes,max_sites,expires_at,features)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            """, conn, tx);
        cmd.Parameters.AddWithValue(input.LicenseId); cmd.Parameters.AddWithValue(input.CustomerId);
        cmd.Parameters.AddWithValue(input.DeploymentId); cmd.Parameters.AddWithValue(input.Edition);
        cmd.Parameters.AddWithValue(input.MaxNodes); cmd.Parameters.AddWithValue(input.MaxSites);
        cmd.Parameters.AddWithValue(DateTimeOffset.FromUnixTimeSeconds(input.ExpiresAt));
        cmd.Parameters.AddWithValue(input.Features);
        await cmd.ExecuteNonQueryAsync();
        await Audit(conn, tx, Actor(ctx).Id, "subscription_created", input.LicenseId);
        await tx.CommitAsync();
        return Results.Ok(new { id = input.LicenseId });
    }
    catch (PostgresException e) when (e.SqlState is PostgresErrorCodes.UniqueViolation or PostgresErrorCodes.ForeignKeyViolation)
    { return Results.Conflict(); }
});
app.MapPost("/api/jobs", async (HttpContext ctx, JobInput input) =>
{
    if (Actor(ctx).Role != "requester") return Results.StatusCode(403);
    if (!Id(input.SubscriptionId)) return Results.BadRequest();
    ActivationRequest? request = null;
    if (input.Kind == "issue")
    {
        if (!Id(input.SiteId) || input.AllocationId is not null || input.RequestFile is not { Length: >= 1 and <= 4096 } ||
            input.RequestFile.Any(c => c is < (char)33 or > (char)126)) return Results.BadRequest();
        try { request = OfflineActivationRequest.Verify(System.Text.Encoding.ASCII.GetBytes(input.RequestFile)); }
        catch (Exception e) when (e is CryptographicException or InvalidDataException or FormatException or ArgumentException)
        { return Results.BadRequest(new { error = "Invalid signed activation request." }); }
    }
    else if (input.Kind != "revoke" || !Id(input.AllocationId) || input.RequestFile is not null || input.SiteId is not null)
        return Results.BadRequest();
    var id = Guid.NewGuid();
    await using var conn = await db.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();
    try
    {
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO gc_license_jobs(id,subscription_id,kind,site_id,request_id,installation_hash,request_file,allocation_id,requested_by,expected_terms_revision)
            SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,terms_revision FROM gc_subscriptions WHERE id=$2
            """, conn, tx);
        cmd.Parameters.AddWithValue(id); cmd.Parameters.AddWithValue(input.SubscriptionId); cmd.Parameters.AddWithValue(input.Kind);
        foreach (var value in new[] { input.SiteId, request?.RequestId, request?.InstallationKeySha256, input.RequestFile, input.AllocationId })
            cmd.Parameters.Add(new NpgsqlParameter { NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Text, Value = (object?)value ?? DBNull.Value });
        cmd.Parameters.AddWithValue(Actor(ctx).Id);
        if (await cmd.ExecuteNonQueryAsync() != 1) return Results.NotFound();
        await Audit(conn, tx, Actor(ctx).Id, "job_requested", id.ToString());
        await tx.CommitAsync();
        return Results.Ok(new { id });
    }
    catch (PostgresException e) when (e.SqlState is PostgresErrorCodes.UniqueViolation or PostgresErrorCodes.ForeignKeyViolation)
    { return Results.Conflict(new { error = "Unknown subscription or duplicate activation request." }); }
});
app.MapPost("/api/subscriptions/{id}/renew", async (HttpContext ctx, string id, Subscription input) =>
{
    if (Actor(ctx).Role != "requester") return Results.StatusCode(403);
    if (id != input.LicenseId || !ValidTerms(input)) return Results.BadRequest();
    var job = Guid.NewGuid();
    await using var conn = await db.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();
    await using var cmd = new NpgsqlCommand("""
        INSERT INTO gc_license_jobs(id,subscription_id,kind,requested_by,expected_terms_revision,proposed_terms)
        SELECT $1,id,'renew_terms',$2,terms_revision,$3::jsonb FROM gc_subscriptions
        WHERE id=$4 AND customer_id=$5 AND deployment_id=$6
        """,conn,tx);
    cmd.Parameters.AddWithValue(job);cmd.Parameters.AddWithValue(Actor(ctx).Id);
    cmd.Parameters.AddWithValue(JsonSerializer.Serialize(input));cmd.Parameters.AddWithValue(id);
    cmd.Parameters.AddWithValue(input.CustomerId);cmd.Parameters.AddWithValue(input.DeploymentId);
    if(await cmd.ExecuteNonQueryAsync()!=1) return Results.NotFound();
    await Audit(conn,tx,Actor(ctx).Id,"renewal_requested",job.ToString());
    await tx.CommitAsync();
    return Results.Ok(new {id=job});
});
app.MapGet("/api/jobs/{id:guid}/result", async (Guid id) =>
{
    await using var conn = await db.OpenConnectionAsync();
    await using var cmd = new NpgsqlCommand("SELECT envelope,completed_at FROM gc_issuer_results WHERE job_id=$1", conn);
    cmd.Parameters.AddWithValue(id);
    await using var reader=await cmd.ExecuteReaderAsync();
    if(!await reader.ReadAsync()) return Results.NotFound();
    return Results.Ok(Row(reader));
});
app.MapPost("/api/jobs/{id:guid}/decision", async (HttpContext ctx, Guid id, DecisionInput input) =>
{
    var actor = Actor(ctx);
    if (actor.Role != "reviewer") return Results.StatusCode(403);
    if (input.Decision is not ("approved" or "rejected")) return Results.BadRequest();
    await using var conn = await db.OpenConnectionAsync();
    await using var tx = await conn.BeginTransactionAsync();
    await using var cmd = new NpgsqlCommand("""
        UPDATE gc_license_jobs SET state=$1, approved_by=$2, approved_at=now()
        WHERE id=$3 AND state='pending' AND requested_by<>$2
        """, conn, tx);
    cmd.Parameters.AddWithValue(input.Decision); cmd.Parameters.AddWithValue(actor.Id); cmd.Parameters.AddWithValue(id);
    if (await cmd.ExecuteNonQueryAsync() != 1) return Results.Conflict(new { error = "No eligible pending request." });
    await Audit(conn, tx, actor.Id, "job_" + input.Decision, id.ToString());
    await tx.CommitAsync();
    return Results.Ok(new { id, state = input.Decision });
});
app.MapGet("/api/jobs/{id:guid}/approved-package", async (HttpContext ctx, Guid id) =>
{
    if (Actor(ctx).Role != "reviewer") return Results.StatusCode(403);
    await using var conn = await db.OpenConnectionAsync();
    await using var cmd = new NpgsqlCommand("""
        SELECT j.id,j.kind,j.site_id,j.request_file,j.allocation_id,j.requested_by,j.approved_by,
        s.id AS license_id,s.customer_id,s.deployment_id,s.edition,s.max_nodes,s.max_sites,
        extract(epoch from s.expires_at)::bigint AS expires_at,s.features
        FROM gc_license_jobs j JOIN gc_subscriptions s ON s.id=j.subscription_id
        WHERE j.id=$1 AND j.state='approved' AND j.expected_terms_revision=s.terms_revision
        """, conn);
    cmd.Parameters.AddWithValue(id);
    await using var reader = await cmd.ExecuteReaderAsync();
    if (!await reader.ReadAsync()) return Results.NotFound();
    return Results.Ok(Row(reader));
});
app.Run();

static PortalOperator Actor(HttpContext ctx) => (PortalOperator)ctx.Items["actor"]!;
static bool Id(string? value) => value is { Length: >= 1 and <= 80 } && value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_');
static bool ValidTerms(Subscription s)
{
    string[] allowed = ["l7","tls","monitoring","ha","fleet","gslb","waf","l4","dc-dr","enterprise-sso","audit","gitops"];
    return Id(s.LicenseId) && Id(s.CustomerId) && Id(s.DeploymentId) &&
        s.Edition is "evaluation" or "standard" or "professional" or "enterprise" or "custom" &&
        s.MaxNodes is >= 1 and <= 10000 && s.MaxSites >= 1 && s.MaxSites <= s.MaxNodes &&
        s.ExpiresAt > DateTimeOffset.UtcNow.ToUnixTimeSeconds() && s.ExpiresAt <= 4102444800L &&
        s.Features is { Length: >= 1 and <= 12 } && s.Features.Distinct(StringComparer.Ordinal).Count() == s.Features.Length &&
        s.Features.All(x => allowed.Contains(x, StringComparer.Ordinal));
}
static async Task Audit(NpgsqlConnection conn, NpgsqlTransaction tx, string actor, string action, string subject)
{
    await using var cmd = new NpgsqlCommand("INSERT INTO gc_portal_audit(actor,action,subject) VALUES($1,$2,$3)", conn, tx);
    cmd.Parameters.AddWithValue(actor); cmd.Parameters.AddWithValue(action); cmd.Parameters.AddWithValue(subject);
    await cmd.ExecuteNonQueryAsync();
}
static Dictionary<string, object?> Row(NpgsqlDataReader reader)
{
    var row = new Dictionary<string, object?>(StringComparer.Ordinal);
    for (int i = 0; i < reader.FieldCount; i++) row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i);
    return row;
}
static async Task<List<Dictionary<string, object?>>> ReadRows(NpgsqlDataSource ds, string sql)
{
    await using var cmd = ds.CreateCommand(sql);
    await using var reader = await cmd.ExecuteReaderAsync();
    var rows = new List<Dictionary<string, object?>>();
    while (await reader.ReadAsync()) rows.Add(Row(reader));
    return rows;
}
internal sealed record PortalOperator(string Id, string Role);
internal sealed record CustomerInput(string Id, string Name);
internal sealed record JobInput(string SubscriptionId, string Kind, string? SiteId, string? RequestFile, string? AllocationId);
internal sealed record DecisionInput(string Decision);
