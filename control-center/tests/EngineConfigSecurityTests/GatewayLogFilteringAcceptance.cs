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
                accessLogger.LogInformation(
                    "GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} clientIpSource={ClientIpSource} statusCode={StatusCode}",
                    DateTimeOffset.UtcNow,
                    clientAddress.Address?.ToString() ?? "unknown", clientAddress.Source,
                    context.Response.StatusCode);
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
            yarpLogger.LogInformation("acceptance-info-filtered");
            yarpLogger.LogWarning("acceptance-warning-preserved");

            var accessLogDeadline = DateTimeOffset.UtcNow.AddSeconds(3);
            while ((!output.ToString().Contains("GATEWAY_ACCESS", StringComparison.Ordinal) ||
                    !output.ToString().Contains("acceptance-warning-preserved", StringComparison.Ordinal)) &&
                   DateTimeOffset.UtcNow < accessLogDeadline)
                await Task.Delay(10);

            var lines = output.ToString();
            Must(lines.Contains("Information GatewayCore.AccessLog", StringComparison.Ordinal) &&
                 lines.Contains("GATEWAY_ACCESS timestampUtc=", StringComparison.Ordinal) &&
                 lines.Contains("clientIp=127.0.0.1", StringComparison.Ordinal) &&
                 lines.Contains("clientIpSource=socket", StringComparison.Ordinal),
                "timestamped client-IP access log remains enabled at Information");
            Must(!lines.Contains("acceptance-info-filtered", StringComparison.Ordinal) &&
                 !lines.Contains("Information Yarp.ReverseProxy.Forwarder.HttpForwarder", StringComparison.Ordinal),
                "YARP Information sentinel and per-request messages are filtered from the console sink");
            Must(lines.Contains("Warning Yarp.ReverseProxy.Forwarder.HttpForwarder", StringComparison.Ordinal),
                "YARP warnings remain visible in the console sink");
            Console.WriteLine("PASS: real forwarding preserves access log while suppressing YARP per-request INFO");
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
