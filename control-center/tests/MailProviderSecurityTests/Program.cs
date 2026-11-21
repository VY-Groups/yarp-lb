using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;

static void Check(bool condition, string message)
{
    if (!condition) throw new Exception("FAIL: " + message);
    Console.WriteLine("PASS: " + message);
}
Check(MailProviderAuth.Validate("password", "smtp.internal.example", "", "", "", false, false) == null,
    "trusted internal SMTP relay mode supported");
Check(MailProviderAuth.Validate("password", "smtp.gmail.com", "user@example.com", "", "", false, false) == null,
    "provider app-password mode preserved for authorized mailboxes");
foreach (var bad in new[] { "http://smtp.gmail.com", "smtp.gmail.com/path", "mail@example.org", "localhost\nmail" })
    Check(MailProviderAuth.Validate("password", bad, "u@example.org", "", "", false, false) is not null,
        "host injection rejected");
Check(MailProviderAuth.Validate("google-oauth", "smtp.gmail.com", "u@gmail.com", "", "client-1", true, true) == null,
    "Google XOAUTH2 correct host");
Check(MailProviderAuth.Validate("google-oauth", "smtp.attacker.tld", "u@gmail.com", "", "client-1", true, true) is not null,
    "Google token cannot reach untrusted SMTP host");
Check(MailProviderAuth.Validate("microsoft-oauth", "smtp.office365.com", "u@example.org", "organizations", "app-id", true, true) == null,
    "Microsoft organizational delegated auth accepted");
Check(MailProviderAuth.Validate("microsoft-oauth", "smtp-mail.outlook.com", "u@outlook.com", "consumers", "app-id", true, true) == null,
    "Outlook.com delegated OAuth accepted");
Check(MailProviderAuth.Validate("microsoft-app", "smtp.office365.com", "u@example.org", Guid.NewGuid().ToString(), "app-id", true, false) == null,
    "Microsoft 365 app-only OAuth needs secret but not refresh token");
Check(MailProviderAuth.Validate("microsoft-app", "smtp.office365.com", "u@example.org", "consumers", "app-id", true, false) is not null,
    "app-only tokens cannot use consumer tenant");
Check(MailProviderAuth.Validate("microsoft-oauth", "evil.example", "u@example.org", "organizations", "app-id", true, true) is not null,
    "OAuth2 token cannot be sent to untrusted Microsoft hostname");
Check(MailProviderAuth.Validate("unknown", "smtp.gmail.com", "u@example.org", "", "app-id", true, true) is not null,
    "unexpected authentication mode rejected");
Check(MailProviderAuth.Validate("google-oauth", "smtp.gmail.com", "u@gmail.com", "", "client-1", false, true) is not null,
    "missing Google client secret rejected");
Check(MailProviderAuth.Validate("google-oauth", "smtp.gmail.com", "u@gmail.com", "", "client-1", true, false) is not null,
    "missing refresh token rejected");
Check(MailProviderAuth.TokenEndpoint("google-oauth", "").Host == "oauth2.googleapis.com",
    "Google OAuth endpoint pinned to vendor");
Check(MailProviderAuth.TokenEndpoint("microsoft-app", Guid.NewGuid().ToString()).Host == "login.microsoftonline.com",
    "Microsoft OAuth endpoint pinned to vendor");
try
{
    MailProviderAuth.TokenEndpoint("microsoft-oauth", "../redirect");
    throw new Exception("invalid tenant bypassed");
}
catch (InvalidOperationException) { Console.WriteLine("PASS: tenant path traversal rejected"); }

var capture = new CapturingHandler(HttpStatusCode.OK,
    "{\"access_token\":\"ci-only-token-12345\",\"token_type\":\"Bearer\",\"expires_in\":3600}");
using (var http = new HttpClient(capture))
{
    var token = await MailProviderAuth.FetchAccessTokenAsync(
        "google-oauth", "", "ci-client", "ci-secret", "ci-refresh", http, CancellationToken.None);
    Check(token == "ci-only-token-12345", "token response extracted without exposing auth payload");
    Check(capture.LastUri?.Host == "oauth2.googleapis.com" &&
        capture.LastUri?.Scheme == "https" && capture.LastMethod == "POST",
        "access token request posts only to pinned HTTPS endpoint");
    Check(capture.LastBody?.Contains("refresh_token=ci-refresh") == true &&
        capture.LastBody.Contains("client_secret=ci-secret"),
        "delegated refresh token request uses POST form body");
}
var appCapture = new CapturingHandler(HttpStatusCode.OK, "{\"access_token\":\"token\"}");
using (var http = new HttpClient(appCapture))
{
    await MailProviderAuth.FetchAccessTokenAsync("microsoft-app",Guid.NewGuid().ToString(),
        "app-id", "app-secret", "", http, CancellationToken.None);
    Check(appCapture.LastBody?.Contains("grant_type=client_credentials") == true &&
        appCapture.LastBody.Contains("outlook.office365.com") &&
        !appCapture.LastBody.Contains("refresh_token"),
        "app-only exchange token requests use correct scope and no refresh token");
}
var unauthorized = new CapturingHandler(HttpStatusCode.Unauthorized,"super-sensitive-provider-error");
using (var http = new HttpClient(unauthorized))
{
    try
    {
        await MailProviderAuth.FetchAccessTokenAsync("google-oauth","",
            "ci-client","ci-secret","ci-refresh",http,CancellationToken.None);
        throw new Exception("HTTP 401 unexpectedly succeeded");
    }
    catch (InvalidOperationException ex)
    {
        Check(!ex.Message.Contains("super-sensitive-provider-error"),
            "OAuth provider error body never exposed to operator or logs");
    }
}
EnterpriseOidcPolicyTests.Run();
await ExternalAuditIntentTests.RunAsync();
Console.WriteLine("PASS: ALL mail provider security checks");

var auditRoot = Path.Combine(Path.GetTempPath(), "gatewaycore-audit-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(auditRoot);
try
{
    var auditFile = Path.Combine(auditRoot, "admin-audit.jsonl");
    var audit = new LocalAdminAudit(auditFile);
    Check((await audit.ReadRecentAsync()).Length == 0, "missing local audit returns an empty list");
    var writers = Enumerable.Range(0, 96).Select(id =>
        audit.AppendAsync("ci-actor-" + id, "CI_TEST", new { id })).ToArray();
    var readers = Enumerable.Range(0, 12).Select(async _ =>
    {
        var rows = await audit.ReadRecentAsync();
        Check(rows.Length <= 80 && rows.All(row => row?["action"]?.ToString() == "CI_TEST"),
            "concurrent audit read returns complete records");
    }).ToArray();
    await Task.WhenAll(writers.Concat(readers));
    var allLines = File.ReadAllLines(auditFile);
    var ids = allLines.Select(line => JsonDocument.Parse(line))
        .Select(doc => { using (doc) return doc.RootElement.GetProperty("details").GetProperty("id").GetInt32(); }).ToArray();
    Check(ids.Length == 96 && ids.Distinct().Count() == 96,
        "all concurrent local audit writes persisted as distinct JSONL records");
    var recent = await audit.ReadRecentAsync();
    Check(recent.Length == 80 && recent.Select(row => row!["details"]!["id"]!.GetValue<int>())
        .SequenceEqual(ids.Reverse().Take(80)), "local audit preserves newest-first 80-record contract");

    var blockedPath = Path.Combine(auditRoot, "not-yet-created", "audit.jsonl");
    var recovering = new LocalAdminAudit(blockedPath);
    var failed = false;
    try { await recovering.AppendAsync("ci-actor", "CI_FAILURE"); }
    catch (IOException) { failed = true; }
    Check(failed, "local audit storage failures propagate rather than fake success");
    Directory.CreateDirectory(Path.GetDirectoryName(blockedPath)!);
    await recovering.AppendAsync("ci-actor", "CI_RECOVERY");
    Check((await recovering.ReadRecentAsync()).Single()?["action"]?.ToString() == "CI_RECOVERY",
        "local audit lock is released after a write failure");
}
finally { Directory.Delete(auditRoot, recursive: true); }

var outboxRoot = Directory.CreateTempSubdirectory("gateway-audit-outbox-");
try
{
    using var signing = System.Security.Cryptography.RSA.Create(2048);
    using var transport = new ExternalAuditIntent(new Uri("https://collector.example.invalid/audit/v1/intents"),
        "node-test", new byte[32], signing.ExportSubjectPublicKeyInfoPem(),
        new HttpClient(new CapturingHandler(HttpStatusCode.ServiceUnavailable, "")));
    var digest = new string('A',64);
    string persisted;
    using (var queue = new DurableAuditOutbox(outboxRoot.FullName, transport))
    {
        queue.Enqueue("operator", "LOGIN_SUCCESS", DateTimeOffset.UtcNow, digest);
        persisted = Directory.GetFiles(outboxRoot.FullName, "*.event").Single();
        Check(!await queue.DeliverOneAsync(CancellationToken.None) && File.Exists(persisted) &&
              queue.Status() is { Pending: 1, DeliveryBlocked: true }, "collector outage never deletes queued audit event");
    }
    using (var queue = new DurableAuditOutbox(outboxRoot.FullName, transport))
        Check(queue.Status().Pending == 1, "audit queue survives process disposal and re-open");
    var raw = File.ReadAllText(persisted);
    File.WriteAllText(persisted, raw.Replace("operator", "changed") + "invalid");
    bool rejected = false;
    try { using var bad = new DurableAuditOutbox(outboxRoot.FullName, transport); }
    catch (JsonException) { rejected = true; }
    Check(rejected, "corrupt queued record refuses startup");
    File.WriteAllText(persisted, raw);
    File.WriteAllText(Path.Combine(outboxRoot.FullName, "incomplete.tmp"), "partial");
    rejected = false;
    try { using var bad = new DurableAuditOutbox(outboxRoot.FullName, transport); }
    catch (InvalidDataException) { rejected = true; }
    Check(rejected, "incomplete journal cannot silently disappear");
}
finally { outboxRoot.Delete(recursive: true); }

// Resource changes now require a signed external intent plus a correlated
// durable PREPARED event before any resource bytes are modified. This
// disposable local test validates the spool's exact correlation and its
// fail-closed behavior after partial/corrupt journal state.
var resourceRoot = Directory.CreateTempSubdirectory("gateway-resource-audit-");
try
{
    using var signer = System.Security.Cryptography.RSA.Create(2048);
    using var transport = new ExternalAuditIntent(
        new Uri("https://collector.example.invalid/audit/v1/intents"),
        "node-test", new byte[32], signer.ExportSubjectPublicKeyInfoPem(),
        new HttpClient(new CapturingHandler(HttpStatusCode.ServiceUnavailable, "")));
    var resourceOutbox = Path.Combine(resourceRoot.FullName, "outbox");
    Directory.CreateDirectory(resourceOutbox);
    using var queue = new DurableAuditOutbox(resourceOutbox, transport);
    var local = new LocalAdminAudit(Path.Combine(resourceRoot.FullName, "resource-audit.jsonl"), queue);
    var confirmed = Guid.NewGuid().ToString("N");
    await local.AppendAsync("operator", "RESOURCE_MUTATION_PREPARED",
        new { operation = "INVENTORY_ADD_INTENT", revision = new string('A', 64) },
        confirmed);
    Check(queue.Status() is { Pending: 1, StorageFault: false },
        "verified resource PREPARED event persists before inventory/fleet mutation");
    var eventFile = Directory.GetFiles(resourceOutbox, "*.event").Single();
    var recorded = System.Text.Json.JsonSerializer.Deserialize<ExternalAuditIntent.QueuedEvent>(
        File.ReadAllBytes(eventFile))!;
    using (var json = System.Text.Json.JsonDocument.Parse(recorded.Payload))
    {
        var row = json.RootElement;
        Check(transport.ValidEvent(recorded) &&
              row.GetProperty("operation").GetString() == "RESOURCE_MUTATION_PREPARED" &&
              row.GetProperty("revision").GetString() ==
                  Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(
                      System.Text.Encoding.ASCII.GetBytes(confirmed))),
            "resource preparation is HMAC-authenticated and bound to exact signed intent ID");
    }
    var refused = false;
    try { await local.AppendAsync("operator", "RESOURCE_MUTATION_PREPARED"); }
    catch (InvalidDataException) { refused = true; }
    Check(refused && queue.Status().Pending == 1,
        "unsigned/uncorrelated resource PREPARED cannot enter durable event spool");
    var invalidEvent = Path.Combine(resourceOutbox, "incomplete.tmp");
    File.WriteAllText(invalidEvent, "partial-append");
    refused = false;
    try { await local.AppendAsync("operator", "RESOURCE_MUTATION_PREPARED",
        new { operation = "INVENTORY_DELETE_INTENT" }, confirmed); }
    catch (InvalidDataException) { refused = true; }
    Check(refused && queue.Status().StorageFault,
        "corrupt resource audit queue latches failure and denies further prepared events");
}
finally { resourceRoot.Delete(recursive: true); }

// A symlink in a *parent* component must not let a previously enrolled
// audit queue be reopened through a different directory identity.
if (OperatingSystem.IsLinux())
{
    var ancestry = Directory.CreateTempSubdirectory("gateway-audit-ancestor-");
    try
    {
        var actualParent = Path.Combine(ancestry.FullName, "real");
        var actualSpool = Path.Combine(actualParent, "spool");
        Directory.CreateDirectory(actualSpool);
        File.SetUnixFileMode(actualParent,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        File.SetUnixFileMode(actualSpool,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        using var verifier = System.Security.Cryptography.RSA.Create(2048);
        using var transport = new ExternalAuditIntent(
            new Uri("https://collector.example.invalid/audit/v1/intents"), "node-test",
            new byte[32], verifier.ExportSubjectPublicKeyInfoPem(),
            new HttpClient(new CapturingHandler(HttpStatusCode.ServiceUnavailable, "")));
        using (var queue = new DurableAuditOutbox(actualSpool, transport))
            queue.Enqueue("operator", "LOGIN_SUCCESS", DateTimeOffset.UtcNow, new string('A', 64));
        var linkedParent = Path.Combine(ancestry.FullName, "linked");
        Directory.CreateSymbolicLink(linkedParent, actualParent);
        var refused = false;
        try { using var _ = new DurableAuditOutbox(Path.Combine(linkedParent, "spool"), transport); }
        catch (InvalidDataException) { refused = true; }
        Check(refused, "Linux audit queue refuses a symlinked ancestor even if final spool has mode 0700");
        using (var queue = new DurableAuditOutbox(actualSpool, transport))
            Check(queue.Status().Pending == 1, "original no-follow audit queue remains readable");
    }
    finally { ancestry.Delete(recursive: true); }
}

sealed class CapturingHandler : HttpMessageHandler
{
    readonly HttpStatusCode status;
    readonly string reply;
    public Uri? LastUri;
    public string? LastMethod;
    public string? LastBody;
    public CapturingHandler(HttpStatusCode status, string reply) { this.status=status;this.reply=reply; }
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage req,CancellationToken cancellationToken)
    {
        LastUri=req.RequestUri; LastMethod=req.Method.Method;
        LastBody=await req.Content!.ReadAsStringAsync(cancellationToken);
        return new HttpResponseMessage(status)
        {
            Content=new StringContent(reply,Encoding.UTF8,"application/json")
        };
    }
}
