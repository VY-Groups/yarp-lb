using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

internal static class EnterpriseOidcAuthentication
{
    private const string ValidatedSubject = ".gc.subject";
    private const string ValidatedTime = ".gc.auth_time";

    internal static void Configure(AuthenticationBuilder builder, EnterpriseOidcPolicy policy,
        string usersPath, LocalAdminAudit audit)
    {
        var settings = policy.Settings;
        var secret = policy.ReadClientSecret();
        builder.AddOpenIdConnect(EnterpriseOidcPolicy.Scheme, options =>
        {
            options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.Authority = settings.Issuer;
            options.ClientId = settings.ClientId;
            options.ClientSecret = secret;
            options.CallbackPath = EnterpriseOidcPolicy.Callback;
            options.ResponseType = "code";
            options.ResponseMode = "query";
            options.UsePkce = true;
            options.RequireHttpsMetadata = true;
            options.MapInboundClaims = false;
            options.SaveTokens = false;
            options.GetClaimsFromUserInfoEndpoint = false;
            options.RefreshOnIssuerKeyNotFound = true;
            options.RemoteAuthenticationTimeout = TimeSpan.FromMinutes(3);
            options.ProtocolValidator.RequireNonce = true;
            options.ProtocolValidator.NonceLifetime = TimeSpan.FromMinutes(3);
            options.BackchannelTimeout = TimeSpan.FromSeconds(10);
            options.BackchannelHttpHandler = new SocketsHttpHandler
            {
                AllowAutoRedirect = false, UseCookies = false,
                ConnectTimeout = TimeSpan.FromSeconds(3)
            };
            options.Scope.Clear();
            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.CorrelationCookie.SameSite = SameSiteMode.Lax;
            options.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
            options.NonceCookie.SameSite = SameSiteMode.Lax;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidIssuer = settings.Issuer, ValidAudience = settings.ClientId,
                ValidateIssuer = true, ValidateAudience = true, ValidateLifetime = true,
                RequireExpirationTime = true, RequireSignedTokens = true,
                ValidateIssuerSigningKey = true, ClockSkew = TimeSpan.FromSeconds(30),
                ValidAlgorithms = ["RS256", "PS256", "ES256"]
            };
            options.Events.OnRedirectToIdentityProvider = ctx =>
            {
                ctx.ProtocolMessage.RedirectUri = settings.ManagementOrigin + EnterpriseOidcPolicy.Callback;
                ctx.ProtocolMessage.SetParameter("acr_values", settings.RequiredAcr);
                ctx.ProtocolMessage.SetParameter("max_age", "0");
                ctx.ProtocolMessage.SetParameter("prompt", "login");
                return Task.CompletedTask;
            };
            options.Events.OnTokenValidated = ctx =>
            {
                // Handler verifies signature, nonce, state/correlation and PKCE.
                // Do not perform account writes or establish a session here.
                if (ctx.Principal is null || !policy.ValidateToken(ctx.Principal,
                    ctx.SecurityToken.Issuer, DateTimeOffset.UtcNow, out var account, out var time))
                {
                    ctx.Fail("OIDC identity or phishing-resistant authentication policy rejected");
                    return Task.CompletedTask;
                }
                ctx.Properties!.Items[ValidatedSubject] = account!.Subject;
                ctx.Properties.Items[ValidatedTime] = time.ToString(CultureInfo.InvariantCulture);
                return Task.CompletedTask;
            };
            options.Events.OnTicketReceived = async ctx =>
            {
                // This event is after successful completion of the remote
                // handler's protocol checks. Resolve the local account afresh.
                try
                {
                    var properties = ctx.Properties!;
                    properties.Items.TryGetValue(ValidatedSubject, out var subject);
                    properties.Items.TryGetValue(ValidatedTime, out var authenticationTime);
                    var row = policy.Resolve(subject);
                    if (row is null || !long.TryParse(authenticationTime,
                        NumberStyles.None, CultureInfo.InvariantCulture, out var time) ||
                        !EnterpriseOidcPolicy.Fresh(time, DateTimeOffset.UtcNow, EnterpriseOidcPolicy.StepUpLifetime))
                    { ctx.HandleResponse(); ctx.Response.Redirect("/admin/oidc/error"); return; }
                    var users = JsonSerializer.Deserialize<List<AdminUser>>(await File.ReadAllTextAsync(usersPath)) ?? [];
                    var user = users.SingleOrDefault(u => u.Username.Equals(row.Username, StringComparison.OrdinalIgnoreCase));
                    if (user is null || !user.Enabled || user.Provider != "Local" || user.Role != row.Role ||
                        string.IsNullOrEmpty(user.SecurityStamp))
                    { ctx.HandleResponse(); ctx.Response.Redirect("/admin/oidc/error"); return; }
                    var claims = new[]
                    {
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim(ClaimTypes.Role, user.Role),
                        new Claim("csrf", Convert.ToHexString(RandomNumberGenerator.GetBytes(32))),
                        new Claim("stamp", user.SecurityStamp),
                        new Claim(EnterpriseOidcPolicy.SubjectClaim, row.Subject),
                        new Claim(EnterpriseOidcPolicy.AuthTimeClaim, time.ToString(CultureInfo.InvariantCulture)),
                        new Claim(EnterpriseOidcPolicy.PolicyClaim, policy.Fingerprint)
                    };
                    // Never put ID/access/refresh tokens or arbitrary IdP claims in the local cookie.
                    properties.Items.Remove(ValidatedSubject);
                    properties.Items.Remove(ValidatedTime);
                    properties.IsPersistent = false;
                    properties.AllowRefresh = false;
                    properties.IssuedUtc = DateTimeOffset.UtcNow;
                    properties.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(time).Add(EnterpriseOidcPolicy.SessionLifetime);
                    ctx.Principal = new ClaimsPrincipal(new ClaimsIdentity(claims,
                        CookieAuthenticationDefaults.AuthenticationScheme));
                    ctx.ReturnUri = "/dashboard";
                    await audit.AppendAsync(user.Username, "OIDC_LOGIN_AUTHORIZED", new { role = user.Role });
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidOperationException)
                { ctx.HandleResponse(); ctx.Response.Redirect("/admin/oidc/error"); }
            };
            options.Events.OnRemoteFailure = async ctx =>
            {
                // Never reflect raw provider errors, tokens or callback parameters.
                try { await audit.AppendAsync("oidc:unknown", "OIDC_LOGIN_DENIED"); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
                ctx.HandleResponse();
                ctx.Response.Redirect("/admin/oidc/error");
            };
        });
    }
}
