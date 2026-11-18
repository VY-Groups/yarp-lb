using Microsoft.Extensions.Logging;

/// <summary>Structured access-log event emitted for each proxied HTTP request.</summary>
public static partial class GatewayAccessLog
{
    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} clientIpSource={ClientIpSource} method={Method} routeId={RouteId} statusCode={StatusCode} durationMs={DurationMs}")]
    public static partial void Write(
        ILogger logger,
        DateTimeOffset timestampUtc,
        string clientIp,
        string clientIpSource,
        string method,
        string routeId,
        int statusCode,
        double durationMs);
}
