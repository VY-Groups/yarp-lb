using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Model;

/// <summary>Deliberately narrow, opt-in public HTTP asset compression.
/// Never compress management, TLS, authenticated, affinity, conditional or range traffic.</summary>
internal sealed class PublicAssetCompression(IResponseCompressionProvider inner) : IResponseCompressionProvider
{
    internal static bool RequestEligible(HttpContext context)
    {
        var request = context.Request;
        var feature = context.GetReverseProxyFeature();
        var route = feature.Route.Config;
        if (!ApplicationAccessPolicy.TryParse(route.Metadata, out var policy) || !policy.PublicHttpCompression ||
            request.IsHttps || !HttpMethods.IsGet(request.Method) || request.QueryString.HasValue ||
            context.User.Identity?.IsAuthenticated == true ||
            !string.IsNullOrEmpty(route.AuthorizationPolicy) ||
            feature.Cluster.Config.SessionAffinity?.Enabled == true ||
            context.WebSockets.IsWebSocketRequest) return false;
        foreach (var key in new[] { "Authorization", "Cookie", "Range", "If-Range", "If-Match",
            "If-None-Match", "If-Modified-Since", "If-Unmodified-Since", "Upgrade",
            "Cache-Control", "Pragma", "Proxy-Authorization" })
            if (request.Headers.ContainsKey(key)) return false;
        return true;
    }

    internal static bool ResponseEligible(HttpContext context)
    {
        var response = context.Response;
        var h = response.Headers;
        if (response.StatusCode != 200 || response.ContentLength is not (>= 1024 and <= 16 * 1024 * 1024) ||
            h.ContainsKey("Set-Cookie") || h.ContainsKey("Content-Encoding") ||
            h.ContainsKey("Content-Range") || h.ContainsKey("ETag") ||
            h.ContainsKey("Content-MD5") || h.ContainsKey("Digest") ||
            h.ContainsKey("Content-Digest") || h.ContainsKey("Repr-Digest") ||
            h.ContainsKey("Trailer") || h.ContainsKey("WWW-Authenticate")) return false;
        if (!CacheControlHeaderValue.TryParse(h.CacheControl.ToString(), out var cache) ||
            cache is null || !cache.Public || cache.Private || cache.NoStore || cache.NoCache ||
            cache.NoTransform || cache.MaxAge is not { } age || age <= TimeSpan.Zero ||
            cache.Extensions.Count != 0) return false;
        if (h.Vary.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Any(value => !value.Equals("Accept-Encoding", StringComparison.OrdinalIgnoreCase))) return false;
        var type = response.ContentType?.Split(';', 2)[0].Trim().ToLowerInvariant();
        return type is "text/css" or "text/javascript" or "application/javascript" or "image/svg+xml";
    }

    public bool CheckRequestAcceptsCompression(HttpContext context) =>
        RequestEligible(context) && inner.CheckRequestAcceptsCompression(context);
    public bool ShouldCompressResponse(HttpContext context) =>
        ResponseEligible(context) && inner.ShouldCompressResponse(context);
    public ICompressionProvider? GetCompressionProvider(HttpContext context) => inner.GetCompressionProvider(context);
}
