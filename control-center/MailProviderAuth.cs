using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class MailProviderAuth
{
    public const string PasswordMode = "password";
    public const string GoogleOAuth = "google-oauth";
    public const string MicrosoftOAuth = "microsoft-oauth";
    public const string MicrosoftApp = "microsoft-app";

    public static bool UsesOAuth(string mode) => mode is GoogleOAuth or MicrosoftOAuth or MicrosoftApp;

    public static string? Validate(string? mode, string? host, string? username,
        string? tenant, string? clientId, bool hasClientSecret, bool hasRefreshToken)
    {
        mode ??= PasswordMode;
        if (string.IsNullOrWhiteSpace(host) || host.Length > 255 ||
            host.Contains('/') || host.Contains('\\') || host.Contains('@') || host.Any(char.IsWhiteSpace))
            return "SMTP host must be a hostname; no URI, path or credentials allowed";
        if (mode == PasswordMode) return null; // approved private relay or provider app password
        if (mode is not (GoogleOAuth or MicrosoftOAuth or MicrosoftApp))
            return "Unsupported mail authentication mode";
        if (string.IsNullOrWhiteSpace(username) || username.Length > 254 || !username.Contains('@'))
            return "OAuth SMTP requires a complete mailbox username";
        if (string.IsNullOrWhiteSpace(clientId) || clientId.Length > 256 || clientId.Any(char.IsWhiteSpace))
            return "OAuth client ID is required";
        if (!hasClientSecret || (mode != MicrosoftApp && !hasRefreshToken))
            return "OAuth client secret and delegated refresh token (or app-only client secret) required";
        if (mode == GoogleOAuth)
            return host.Equals("smtp.gmail.com", StringComparison.OrdinalIgnoreCase)
                ? null : "Google OAuth tokens may only be sent to smtp.gmail.com";
        if (host.Equals("smtp.office365.com", StringComparison.OrdinalIgnoreCase) == false &&
            !(mode == MicrosoftOAuth && host.Equals("smtp-mail.outlook.com", StringComparison.OrdinalIgnoreCase)))
            return "Microsoft OAuth tokens may only be sent to approved Microsoft SMTP hosts";
        if (mode == MicrosoftApp)
            return Guid.TryParse(tenant, out _) ? null : "App-only Microsoft OAuth requires a concrete tenant GUID";
        return Guid.TryParse(tenant, out _) || tenant is "consumers" or "organizations"
            ? null : "Delegated Microsoft OAuth requires a tenant GUID, consumers or organizations";
    }

    public static Uri TokenEndpoint(string mode, string tenant)
    {
        if (mode == GoogleOAuth) return new Uri("https://oauth2.googleapis.com/token");
        if (mode is not (MicrosoftOAuth or MicrosoftApp))
            throw new InvalidOperationException("Unsupported OAuth provider");
        if (!Guid.TryParse(tenant, out _) && !(mode == MicrosoftOAuth && tenant is "consumers" or "organizations"))
            throw new InvalidOperationException("Invalid Microsoft OAuth tenant");
        return new Uri($"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
    }

    public static async Task<string> FetchAccessTokenAsync(
        string mode, string tenant, string clientId, string clientSecret, string refreshToken,
        HttpClient http, CancellationToken cancellationToken)
    {
        // Endpoint is pinned to Google or Microsoft, not configured by an
        // administrator or remote SMTP server. Reject redirects at the caller.
        var endpoint = TokenEndpoint(mode, tenant);
        var values = new Dictionary<string, string>
        {
            ["client_id"] = clientId,
            ["client_secret"] = clientSecret
        };
        if (mode == MicrosoftApp)
        {
            values["grant_type"] = "client_credentials";
            values["scope"] = "https://outlook.office365.com/.default";
        }
        else
        {
            values["grant_type"] = "refresh_token";
            values["refresh_token"] = refreshToken;
            if (mode == MicrosoftOAuth)
                values["scope"] = "https://outlook.office.com/SMTP.Send offline_access";
        }
        using var payload = new FormUrlEncodedContent(values);
        using var response = await http.PostAsync(endpoint, payload, cancellationToken);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException("OAuth token acquisition failed; review tenant, permissions and authentication");
        // Content is an untrusted provider response. Never log raw payloads,
        // access/refresh tokens, client secrets, or HTTP exception bodies.
        var raw = await response.Content.ReadAsStringAsync(cancellationToken);
        if (raw.Length > 32768)
            throw new InvalidOperationException("OAuth token response exceeds size limit");
        using var token = JsonDocument.Parse(raw);
        if (!token.RootElement.TryGetProperty("access_token", out var element))
            throw new InvalidOperationException("OAuth token response missing access token");
        var accessToken = element.GetString();
        if (string.IsNullOrWhiteSpace(accessToken) || accessToken.Length > 16384)
            throw new InvalidOperationException("OAuth access token invalid");
        return accessToken;
    }
}
