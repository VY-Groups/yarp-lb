using System.Net;

/// <summary>Accept only an authenticated transport or a loopback development collector.</summary>
public static class OtlpEndpointPolicy
{
    public static Uri? Parse(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var endpoint) ||
            endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 ||
            endpoint.Fragment.Length != 0 || endpoint.AbsolutePath is not ("" or "/") ||
            endpoint.Port is < 1 or > 65535)
            throw new InvalidOperationException("OTLP endpoint must be an absolute base URL without credentials, path, query or fragment");

        var loopback = endpoint.IsLoopback ||
            (IPAddress.TryParse(endpoint.Host, out var ip) && IPAddress.IsLoopback(ip));
        if (!endpoint.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) &&
            !(loopback && endpoint.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("OTLP requires HTTPS; plain HTTP is allowed only for a loopback collector");
        return endpoint;
    }
}
