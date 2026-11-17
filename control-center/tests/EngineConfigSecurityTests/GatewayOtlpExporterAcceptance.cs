using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

/// <summary>Exercises the real OTLP HTTP exporters against a loopback collector fixture.</summary>
public static class GatewayOtlpExporterAcceptance
{
    public static async Task RunAsync()
    {
        var oldEndpoint = Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT");
        var oldRatio = Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO");
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        var records = new ConcurrentQueue<(string Path, byte[] Body)>();
        using var receiverTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var receiver = ReceiveAsync(listener, records, receiverTimeout.Token);
        try
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", $"http://127.0.0.1:{port}");
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", "1");
            var services = new ServiceCollection();
            services.AddLogging();
            if (!GatewayOpenTelemetry.Configure(services, "otlp-acceptance"))
                throw new Exception("OTLP configuration was unexpectedly disabled");
            using var provider = services.BuildServiceProvider();
            var tracerProvider = provider.GetRequiredService<TracerProvider>();
            var meterProvider = provider.GetRequiredService<MeterProvider>();
            var parent = new ActivityContext(ActivityTraceId.CreateRandom(), ActivitySpanId.CreateRandom(),
                ActivityTraceFlags.Recorded);
            using (var activity = GatewayOpenTelemetry.ActivitySource.StartActivity(
                       "gateway.proxy.request", ActivityKind.Internal, parent))
            {
                if (activity is null) throw new Exception("Configured sampler dropped the 100% acceptance span");
                activity.SetTag("client.address", "203.0.113.99");
                activity.SetTag("network.peer.address", "203.0.113.99");
                activity.SetTag("url.full", "https://gateway.example/private?token=otlp-secret-canary");
                activity.SetTag("url.path", "/private");
                activity.SetTag("url.query", "token=otlp-secret-canary");
                activity.SetTag("gateway.route.id", "acceptance_route");
                activity.SetTag("gateway.cluster.id", "acceptance_cluster");
                activity.SetTag("gateway.destination.id", "target_a");
            }

            var response = new Microsoft.AspNetCore.Http.DefaultHttpContext();
            response.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.RecordProxyResult(response, 12.5);
            if (!tracerProvider.ForceFlush(10000) || !meterProvider.ForceFlush(10000))
                throw new Exception("OTLP provider failed to flush before acceptance deadline");

            var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while (records.Count < 2 && DateTimeOffset.UtcNow < deadline)
                await Task.Delay(50, receiverTimeout.Token);
            var captured = records.ToArray();
            var traces = captured.Where(x => x.Path == "/v1/traces").ToArray();
            var metrics = captured.Where(x => x.Path == "/v1/metrics").ToArray();
            if (traces.Length == 0 || metrics.Length == 0)
                throw new Exception($"Expected both OTLP signals; received: {string.Join(", ", captured.Select(x => x.Path))}");

            var tracePayload = Encoding.Latin1.GetString(traces.SelectMany(x => x.Body).ToArray());
            foreach (var sensitive in new[] { "203.0.113.99", "otlp-secret-canary", "/private" })
                if (tracePayload.Contains(sensitive, StringComparison.Ordinal))
                    throw new Exception($"Sensitive value was present in OTLP trace export: {sensitive}");
            foreach (var expected in new[] { "acceptance_route", "acceptance_cluster", "target_a", "gatewaycore-control-center" })
                if (!tracePayload.Contains(expected, StringComparison.Ordinal))
                    throw new Exception($"Expected bounded trace/resource attribute was absent: {expected}");

            var metricPayload = Encoding.Latin1.GetString(metrics.SelectMany(x => x.Body).ToArray());
            foreach (var expected in new[] { "gateway.proxy.requests", "gateway.proxy.request.duration", "5xx" })
                if (!metricPayload.Contains(expected, StringComparison.Ordinal))
                    throw new Exception($"Expected bounded proxy metric was absent: {expected}");
            Console.WriteLine("PASS: real OTLP/HTTP collector received traces and metrics; sensitive URL/client values were redacted");
        }
        finally
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", oldEndpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", oldRatio);
            receiverTimeout.Cancel();
            listener.Stop();
            try { await receiver; }
            catch (OperationCanceledException) { }
            catch (SocketException) when (receiverTimeout.IsCancellationRequested) { }
        }
    }

    private static async Task ReceiveAsync(TcpListener listener,
        ConcurrentQueue<(string Path, byte[] Body)> records, CancellationToken cancellationToken)
    {
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                using var client = await listener.AcceptTcpClientAsync(cancellationToken);
                using var stream = client.GetStream();
                var headerBytes = new List<byte>();
                var marker = 0;
                while (marker < 4)
                {
                    var one = new byte[1];
                    var read = await stream.ReadAsync(one, cancellationToken);
                    if (read == 0) throw new EndOfStreamException("Collector received a truncated HTTP header");
                    headerBytes.Add(one[0]);
                    marker = (marker, one[0]) switch
                    {
                        (0, 13) or (2, 13) => marker + 1,
                        (1, 10) or (3, 10) => marker + 1,
                        _ => one[0] == 13 ? 1 : 0
                    };
                    if (headerBytes.Count > 16384) throw new InvalidDataException("Collector HTTP header exceeds its test bound");
                }
                var headers = Encoding.ASCII.GetString(headerBytes.ToArray());
                var firstLine = headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)[0].Split(' ');
                if (firstLine.Length < 2) throw new InvalidDataException("Collector received an invalid HTTP request line");
                var lengthLine = headers.Split("\r\n", StringSplitOptions.RemoveEmptyEntries)
                    .FirstOrDefault(line => line.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
                if (lengthLine is null || !int.TryParse(lengthLine[(lengthLine.IndexOf(':') + 1)..].Trim(), out var length) ||
                    length is < 0 or > 1_048_576)
                    throw new InvalidDataException("Collector requires a bounded Content-Length request");
                var body = new byte[length];
                var offset = 0;
                while (offset < body.Length)
                {
                    var count = await stream.ReadAsync(body.AsMemory(offset), cancellationToken);
                    if (count == 0) throw new EndOfStreamException("Collector received a truncated OTLP payload");
                    offset += count;
                }
                records.Enqueue((firstLine[1], body));
                var reply = Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                await stream.WriteAsync(reply, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (SocketException) when (cancellationToken.IsCancellationRequested) { }
    }
}
