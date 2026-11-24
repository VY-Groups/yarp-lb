using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.DataProtection;

internal static class ManagementPrivacyPolicy
{
    internal const string CookieName = "GatewayCorePrivacy";
    internal const string AcceptancePath = "/admin/api/privacy/accept";
    internal const string Text = """
        GatewayCore Control Center — Privacy Policy
        Notice date: 24 November 2026

        Scope and responsibility
        GatewayCore is an on-premises administration and traffic delivery tool. Your deploying organization determines the purposes, lawful basis, access and retention of personal information and must provide any additional notices required for its deployment.

        Information handled
        Administrative accounts may include usernames, roles, email addresses, directory identifiers, authentication and session records. Configuration, machine inventory, routes, changes, audit events and backups may also contain personal or confidential information. Traffic is processed and forwarded according to configured routes and security policies. Local access logs may record client IP addresses, methods, route identifiers, response status, timestamps and durations. Security modules and external integrations may process additional request information according to configuration.

        Why information is used
        Information supports authentication, authorization, traffic delivery, monitoring, security investigations, change management and backup/recovery. Do not enter unnecessary personal information or credentials into notes, inventory or change explanations.

        Storage, access and integrations
        Management state, session protection material and operational records are stored in configured local or distributed stores. Enabled integrations may transmit information to configured upstream services, identity and directory providers, mail providers, fleet peers, audit collectors, monitoring exporters and other operator-selected destinations. The organization must assess these destinations and protect credentials, logs and backups. No claim is made that all deployments keep all information on one machine or in one country.

        Cookies
        The management console uses authentication, security and policy-acknowledgement cookies. Acceptance does not enable advertising or optional analytics.

        Retention, requests and security
        Your deploying organization manages retention, deletion, access requests and incident reporting under its policies and applicable law. Contact its designated privacy or security administrator with questions, corrections or requests. Security controls do not guarantee regulatory compliance or eliminate operational risk.

        Your choice
        Acknowledge this notice to use the management console. Declining leaves management functions unavailable; you may review the notice again or sign out. Acknowledgement does not waive privacy rights or constitute consent to unrelated optional processing. A new authenticated session or revised notice requires renewed acknowledgement.
        """;
    internal static readonly string Version = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(Text)));

    private static string? Binding(HttpContext ctx)
    {
        if (ctx.User.Identity?.IsAuthenticated != true) return null;
        var username = ctx.User.Identity.Name;
        var csrf = ctx.User.FindFirst("csrf")?.Value;
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(csrf)) return null;
        return Version + "\n" + csrf + "\n" + username;
    }

    private static IDataProtector Protector(HttpContext ctx) =>
        ctx.RequestServices.GetRequiredService<IDataProtectionProvider>()
            .CreateProtector("GatewayCore.ManagementPrivacyAcknowledgement.v1");

    private static CookieOptions Options(HttpContext ctx) => new()
    {
        Path = "/admin", HttpOnly = true, Secure = ctx.Request.IsHttps,
        SameSite = SameSiteMode.Strict, IsEssential = true
    };

    internal static bool Accepted(HttpContext ctx)
    {
        var binding = Binding(ctx);
        if (binding is null || !ctx.Request.Cookies.TryGetValue(CookieName, out var cookie) ||
            string.IsNullOrEmpty(cookie) || cookie.Length > 4096) return false;
        try { return string.Equals(Protector(ctx).Unprotect(cookie), binding, StringComparison.Ordinal); }
        catch (CryptographicException) { return false; }
        catch (FormatException) { return false; }
    }

    internal static void Issue(HttpContext ctx)
    {
        var binding = Binding(ctx) ?? throw new InvalidOperationException("Authenticated session required");
        ctx.Response.Cookies.Append(CookieName, Protector(ctx).Protect(binding), Options(ctx));
    }

    internal static void Clear(HttpContext ctx) => ctx.Response.Cookies.Delete(CookieName, Options(ctx));

    internal static bool Exempt(PathString path) =>
        path == "/admin/api/session" || path == "/admin/api/auth-methods" ||
        path == "/admin/api/bootstrap" || path == "/admin/api/login" ||
        path == "/admin/api/login/verify" || path == "/admin/api/logout" ||
        path == AcceptancePath;

    internal static string Page() =>
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
        "<title>Privacy Policy | GatewayCore</title><link rel=\"stylesheet\" href=\"/dashboard/style.css\">" +
        "</head><body><main class=\"privacy-card card\"><h1>Privacy Policy</h1><p class=\"subtle\">Revision: " +
        WebUtility.HtmlEncode(Version[..12]) + "</p><pre class=\"privacy-text\">" +
        WebUtility.HtmlEncode(Text) + "</pre><a class=\"privacy-link\" href=\"/dashboard\">Return to Control Center</a></main></body></html>";
}
internal sealed record PrivacyAcceptanceInput(string? Version);
