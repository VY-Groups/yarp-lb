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
        var provider = new NonBlockingConsoleLoggerProvider(output, capacity, maxLineChars);
        logging.AddProvider(provider);
        return provider;
    }
}
