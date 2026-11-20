using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;

internal static class GatewayLogFilteringAcceptance
{
    public static async Task RunAsync()
    {
        // Compare both implementations with the same warmed no-op logger:
        // this isolates call-site allocation, not console/OTLP formatter costs.
        var capture = new CallSiteLogger();
        var timestamp = DateTimeOffset.Parse("2026-01-02T03:04:05+00:00",
            System.Globalization.CultureInfo.InvariantCulture);
        void Legacy() => capture.LogInformation(
            "GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} clientIpSource={ClientIpSource} method={Method} routeId={RouteId} statusCode={StatusCode} durationMs={DurationMs}",
            timestamp, "127.0.0.1", "socket", "POST", "fixture", 200, 12.5);
        void Typed() => GatewayOpenTelemetry.LogAccess(capture, timestamp, "127.0.0.1",
            "socket", "POST", "fixture", 200, 12.5);
        capture.Capture = true;
        Legacy();
        var previousMessage = capture.Message;
        var previousFields = capture.Fields;
        Typed();
        Must(capture.Message == previousMessage && capture.Fields is not null &&
             previousFields is not null && previousFields.SequenceEqual(capture.Fields),
            "typed access log preserves formatted message and structured field names and values");
        capture.Capture = false;
        long Measure(Action emit)
        {
            for (var i = 0; i < 2000; i++) emit();
            var before = GC.GetAllocatedBytesForCurrentThread();
            for (var i = 0; i < 100000; i++) emit();
            return GC.GetAllocatedBytesForCurrentThread() - before;
        }
        var legacyBytes = Measure(Legacy);
        var typedBytes = Measure(Typed);
        Console.WriteLine($"ACCESS_LOG_CALLSITE_ALLOCATIONS legacy={legacyBytes} typed={typedBytes} calls=100000");
        Must(typedBytes < legacyBytes, "typed access log reduces warmed synchronous call-site allocation");

        var (backend, backendPort) = BuildApp("log-filter-backend");
        backend.MapGet("/{**path}", () => Results.Text("forwarded"));
        await backend.StartAsync();
        var backendAddress = GetAddress(backendPort);

        // The provider drains log lines on a background thread while this test
        // polls the capture. StringWriter/StringBuilder are not thread-safe;
        // concurrent ToString and WriteLine can corrupt the builder on Linux.
        var output = new SynchronizedCaptureWriter();
        var (gateway, gatewayPort) = BuildGateway(output, backendAddress);
        var accessLogger = gateway.Services.GetRequiredService<ILoggerFactory>()
            .CreateLogger("GatewayCore.AccessLog");
        gateway.Use(async (context, next) =>
        {
            try { await next(); }
            finally
            {
                var clientAddress = GatewayClientAddress.ForAccessLog(
                    context.Connection.RemoteIpAddress,
                    context.Request.Headers["X-Forwarded-For"].ToString(), new HashSet<string>());
                GatewayOpenTelemetry.LogAccess(accessLogger, DateTimeOffset.UtcNow,
                    clientAddress.Address?.ToString() ?? "unknown", clientAddress.Source,
                    context.Request.Method, "acceptance-route", context.Response.StatusCode, 12.5);
            }
        });
        gateway.MapReverseProxy();
        await gateway.StartAsync();
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            using var response = await client.GetAsync(GetAddress(gatewayPort) + "/acceptance");
            var body = await response.Content.ReadAsStringAsync();
            Must(response.StatusCode == HttpStatusCode.OK && body == "forwarded",
                "real YARP forwarding succeeds while log filters are active");
            var yarpLogger = gateway.Services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Yarp.ReverseProxy.Forwarder.HttpForwarder");
            var hostingLogger = gateway.Services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Microsoft.AspNetCore.Hosting.Diagnostics");
            var endpointLogger = gateway.Services.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Microsoft.AspNetCore.Routing.EndpointMiddleware");
            yarpLogger.LogInformation("acceptance-info-filtered");
            yarpLogger.LogWarning("acceptance-warning-preserved");
            hostingLogger.LogInformation("hosting-info-filtered");
            hostingLogger.LogWarning("hosting-warning-preserved");
            endpointLogger.LogInformation("endpoint-info-filtered");
            endpointLogger.LogWarning("endpoint-warning-preserved");

            var accessLogDeadline = DateTimeOffset.UtcNow.AddSeconds(3);
            while ((!output.ToString().Contains("GATEWAY_ACCESS", StringComparison.Ordinal) ||
                    !output.ToString().Contains("acceptance-warning-preserved", StringComparison.Ordinal) ||
                    !output.ToString().Contains("hosting-warning-preserved", StringComparison.Ordinal) ||
                    !output.ToString().Contains("endpoint-warning-preserved", StringComparison.Ordinal)) &&
                   DateTimeOffset.UtcNow < accessLogDeadline)
                await Task.Delay(10);

            var lines = output.ToString();
            Must(lines.Contains("Information GatewayCore.AccessLog", StringComparison.Ordinal) &&
                 lines.Contains("GATEWAY_ACCESS timestampUtc=", StringComparison.Ordinal) &&
                 lines.Contains("clientIp=127.0.0.1", StringComparison.Ordinal) &&
                 lines.Contains("clientIpSource=socket method=GET routeId=acceptance-route statusCode=200 durationMs=12.5", StringComparison.Ordinal),
                "timestamped client-IP access log remains enabled at Information");
            Must(!lines.Contains("acceptance-info-filtered", StringComparison.Ordinal) &&
                 !lines.Contains("Information Yarp.ReverseProxy.Forwarder.HttpForwarder", StringComparison.Ordinal),
                "YARP Information sentinel and per-request messages are filtered from the console sink");
            Must(!lines.Contains("hosting-info-filtered", StringComparison.Ordinal) &&
                 !lines.Contains("endpoint-info-filtered", StringComparison.Ordinal),
                "ASP.NET hosting and endpoint Information sentinels are filtered from the console sink");
            Must(lines.Contains("Warning Yarp.ReverseProxy.Forwarder.HttpForwarder", StringComparison.Ordinal),
                "YARP warnings remain visible in the console sink");
            Must(lines.Contains("Warning Microsoft.AspNetCore.Hosting.Diagnostics", StringComparison.Ordinal) &&
                 lines.Contains("Warning Microsoft.AspNetCore.Routing.EndpointMiddleware", StringComparison.Ordinal),
                "ASP.NET hosting and endpoint warnings remain visible in the console sink");
            Console.WriteLine("PASS: real forwarding preserves access log while suppressing duplicate per-request INFO");
        }
        finally
        {
            await gateway.StopAsync();
            await backend.StopAsync();
            await gateway.DisposeAsync();
            await backend.DisposeAsync();
        }
    }

    private static (WebApplication App, int Port) BuildApp(string name)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.ApplicationName = name;
        var port = FindFreePort();
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        builder.Logging.ClearProviders();
        GatewayLoggingConfiguration.Install(builder.Logging, TextWriter.Null);
        return (builder.Build(), port);
    }

    private static (WebApplication App, int Port) BuildGateway(TextWriter output, string backendAddress)
    {
        var builder = WebApplication.CreateBuilder();
        builder.Environment.ApplicationName = "log-filter-gateway";
        var port = FindFreePort();
        builder.WebHost.UseUrls($"http://127.0.0.1:{port}");
        builder.Logging.ClearProviders();
        GatewayLoggingConfiguration.Install(builder.Logging, output);
        builder.Services.AddReverseProxy().LoadFromMemory(
            new[]
            {
                new RouteConfig
                {
                    RouteId = "acceptance-route",
                    ClusterId = "acceptance-cluster",
                    Match = new RouteMatch { Path = "/{**catch-all}" }
                }
            },
            new[]
            {
                new ClusterConfig
                {
                    ClusterId = "acceptance-cluster",
                    Destinations = new Dictionary<string, DestinationConfig>
                    {
                        ["backend"] = new() { Address = backendAddress + "/" }
                    }
                }
            });
        return (builder.Build(), port);
    }

    private static string GetAddress(int port) => $"http://127.0.0.1:{port}";

    private static int FindFreePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static void Must(bool condition, string description)
    {
        if (!condition) throw new InvalidOperationException("FAIL: " + description);
        Console.WriteLine("PASS: " + description);
    }

    private sealed class CallSiteLogger : ILogger
    {
        public bool Capture { get; set; }
        public string? Message { get; private set; }
        public KeyValuePair<string, object?>[]? Fields { get; private set; }
        public bool IsEnabled(LogLevel level) => level == LogLevel.Information;
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public void Log<TState>(LogLevel level, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (!Capture) return;
            Message = formatter(state, exception);
            Fields = ((IEnumerable<KeyValuePair<string, object?>>)(object)state!).ToArray();
        }
    }

    private sealed class SynchronizedCaptureWriter : TextWriter
    {
        private readonly object sync = new();
        private readonly StringBuilder content = new();

        public override Encoding Encoding => Encoding.UTF8;

        public override void WriteLine(string? value)
        {
            lock (sync) content.AppendLine(value);
        }

        public override string ToString()
        {
            lock (sync) return content.ToString();
        }
    }
}
