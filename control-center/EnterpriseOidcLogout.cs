using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

internal sealed record OidcLogoutNotice(string Subject, long IssuedAt);

/// <summary>Subject-wide signed OIDC back-channel logout. Do not accept an ID
/// token or unsigned browser request as evidence of provider revocation.</summary>
internal static class EnterpriseOidcLogout
{
    internal const string Path = "/admin/oidc/backchannel-logout";
    internal const string EventType = "http://schemas.openid.net/event/backchannel-logout";
    internal const int MaxToken = 12288;
    internal const int MaxForm = 16384;

    internal static async Task<OidcLogoutNotice?> ValidateAsync(string token, EnterpriseOidcPolicy policy,
        OpenIdConnectOptions options, CancellationToken ct)
    {
        if (token.Length is < 1 or > MaxToken || token.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_' or '.')) ||
            token.Count(c => c == '.') != 2 || options.ConfigurationManager is null) return null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct);
        deadline.CancelAfter(TimeSpan.FromSeconds(4));
        try
        {
            var handler = new JsonWebTokenHandler { MaximumTokenSizeInBytes = MaxToken, MapInboundClaims = false };
            for (int attempt = 0; attempt < 2; attempt++)
            {
                var metadata = await options.ConfigurationManager.GetConfigurationAsync(deadline.Token);
                if (metadata.Issuer != policy.Settings.Issuer || metadata.SigningKeys.Count == 0) return null;
                var result = await handler.ValidateTokenAsync(token, new TokenValidationParameters
                {
                    ValidIssuer = policy.Settings.Issuer, ValidAudience = policy.Settings.ClientId,
                    ValidateIssuer = true, ValidateAudience = true, ValidateIssuerSigningKey = true,
                    RequireSignedTokens = true, ValidateLifetime = true, RequireExpirationTime = false,
                    IssuerSigningKeys = metadata.SigningKeys,
                    ClockSkew = TimeSpan.FromSeconds(30), ValidAlgorithms = ["RS256", "PS256", "ES256"]
                });
                if (result.IsValid)
                {
                    var jwt = (JsonWebToken)result.SecurityToken;
                    // OIDC Back-Channel Logout permits an absent typ header;
                    // when present it must be exactly the registered value.
                    if (!HasAcceptedType(jwt)) return null;
                    return ParseValidated(Base64UrlEncoder.DecodeBytes(jwt.EncodedPayload), policy, DateTimeOffset.UtcNow);
                }
                if (attempt != 0 || result.Exception is not SecurityTokenSignatureKeyNotFoundException) return null;
                options.ConfigurationManager.RequestRefresh();
            }
        }
        catch (Exception ex) when (ex is OperationCanceledException or HttpRequestException or
                                   InvalidOperationException or IOException or ArgumentException or SecurityTokenException)
        { }
        return null;
    }

    private static bool HasAcceptedType(JsonWebToken jwt)
    {
        try
        {
            using var header = JsonDocument.Parse(Base64UrlEncoder.DecodeBytes(jwt.EncodedHeader),
                new JsonDocumentOptions { MaxDepth = 5 });
            if (header.RootElement.ValueKind != JsonValueKind.Object) return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in header.RootElement.EnumerateObject())
            {
                if (!names.Add(property.Name)) return false;
                if (property.Name == "typ" &&
                    (property.Value.ValueKind != JsonValueKind.String || property.Value.GetString() != "logout+jwt"))
                    return false;
            }
            return true;
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException)
        { return false; }
    }

    internal static OidcLogoutNotice? ParseValidated(byte[] payload, EnterpriseOidcPolicy policy, DateTimeOffset now)
    {
        try
        {
            using var doc = JsonDocument.Parse(payload, new JsonDocumentOptions { MaxDepth = 5 });
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in root.EnumerateObject())
                if (!names.Add(item.Name)) return null;
            if (names.Contains("nonce") || root.GetProperty("iss").GetString() != policy.Settings.Issuer)
                return null;
            var aud = root.GetProperty("aud");
            if (aud.ValueKind == JsonValueKind.Array)
            {
                if (aud.GetArrayLength() != 1 || aud[0].GetString() != policy.Settings.ClientId) return null;
            }
            else if (aud.GetString() != policy.Settings.ClientId) return null;
            if (root.TryGetProperty("azp", out var azp) && azp.GetString() != policy.Settings.ClientId) return null;
            var subject = root.GetProperty("sub").GetString();
            var id = root.GetProperty("jti").GetString();
            if (policy.Resolve(subject) is null || id is not { Length: >= 1 and <= 256 } || id.Any(char.IsControl)) return null;
            if (!root.GetProperty("iat").TryGetInt64(out var iat) ||
                !EnterpriseOidcPolicy.Fresh(iat, now, TimeSpan.FromMinutes(2))) return null;
            var events = root.GetProperty("events");
            if (events.ValueKind != JsonValueKind.Object ||
                events.EnumerateObject().Count() != 1 ||
                !events.TryGetProperty(EventType, out var marker) ||
                marker.ValueKind != JsonValueKind.Object || marker.EnumerateObject().Any()) return null;
            return new OidcLogoutNotice(subject!, iat);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
        { return null; }
    }
}
