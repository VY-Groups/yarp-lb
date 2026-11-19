using Microsoft.AspNetCore.Server.Kestrel.Core;

/// <summary>Explicit traffic-listener protocol modes. HTTP/3 mode retains HTTP/1.1
/// and HTTP/2 over TCP while enabling HTTP/3 over QUIC/UDP on the same TLS port.</summary>
public static class TrafficHttpProtocols
{
    public static HttpProtocols Parse(string? value) => value switch
    {
        "1.1" => HttpProtocols.Http1,
        "2" => HttpProtocols.Http2,
        "3" => HttpProtocols.Http1AndHttp2AndHttp3,
        _ => throw new InvalidOperationException("HttpVersion must be 1.1, 2, or 3 (3 enables HTTP/1.1, HTTP/2, and HTTP/3)")
    };

}
