using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;

/// <summary>
/// Single logging bootstrap shared by the shipping Control Center YARP proxy
/// and the disposable L7 GatewayLab. No change to audit/event-source providers.
/// </summary>
public static class GatewayLoggingConfiguration
{
    public static NonBlockingConsoleLoggerProvider Install(ILoggingBuilder logging,
        TextWriter output, int capacity = 1024, int maxLineChars = 4096)
    {
        ArgumentNullException.ThrowIfNull(logging);
        // The default ConsoleLoggerProvider can synchronously wait on its
        // internal queue, leading to ThreadPool starvation when stdout stalls.
        logging.AddFilter<ConsoleLoggerProvider>((_, _) => false);
        // Per-request access records are emitted by GatewayCore.AccessLog and
        // remain at Information. YARP's own request/response diagnostics are
        // redundant at that level and allocate formatted strings for every
        // forwarded request; keep actionable YARP warnings and errors.
        // A separate, IP-free record exists only for the outbound OTLP
        // provider. Writing that record to the local console *as well as*
        // the original GatewayCore.AccessLog duplicates every INFO request
        // and formats an extra line in the forwarding hot path.
        // Filter only this console provider: the OpenTelemetryLoggerProvider
        // continues to receive the sanitized event independently.
        logging.AddFilter<NonBlockingConsoleLoggerProvider>(
            "GatewayCore.TelemetryAccess", LogLevel.None);
        logging.AddFilter<NonBlockingConsoleLoggerProvider>(
            "Yarp.ReverseProxy", LogLevel.Warning);
        // The gateway emits its own timestamped GatewayCore.AccessLog entry for
        // every request. ASP.NET's hosting start/finish and endpoint-selection
        // Information records duplicate that per-request stream and format
        // strings on the request path; retain their warnings and errors.
        logging.AddFilter<NonBlockingConsoleLoggerProvider>(
            "Microsoft.AspNetCore.Hosting.Diagnostics", LogLevel.Warning);
        logging.AddFilter<NonBlockingConsoleLoggerProvider>(
            "Microsoft.AspNetCore.Routing.EndpointMiddleware", LogLevel.Warning);
        var provider = new NonBlockingConsoleLoggerProvider(output, capacity, maxLineChars);
        logging.AddProvider(provider);
        return provider;
    }
}
