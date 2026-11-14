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
Console.WriteLine("PASS: ALL mail provider security checks");

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
