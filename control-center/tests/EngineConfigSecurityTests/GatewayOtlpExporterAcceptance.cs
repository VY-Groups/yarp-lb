using System.Collections.Concurrent;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

/// <summary>Exercises the real OTLP HTTP exporters against a loopback collector fixture.</summary>
public static class GatewayOtlpExporterAcceptance
{
    public static Task RunWithoutCollectorAsync()
    {
        var oldEndpoint = Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT");
        var oldRatio = Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO");
        using var closedPort = new TcpListener(IPAddress.Loopback, 0);
        closedPort.Start();
        var endpoint = $"http://127.0.0.1:{((IPEndPoint)closedPort.LocalEndpoint).Port}";
        closedPort.Stop();
        try
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", endpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", "1");
            var services = new ServiceCollection();
            services.AddLogging();
            if (!GatewayOpenTelemetry.Configure(services, "otlp-outage-acceptance"))
                throw new Exception("Unavailable-collector configuration was unexpectedly disabled");
            var provider = services.BuildServiceProvider();
            var started = Stopwatch.GetTimestamp();
            using (var activity = GatewayOpenTelemetry.ActivitySource.StartActivity(
                       "gateway.proxy.request", ActivityKind.Internal))
                activity?.SetTag("gateway.route.id", "collector_outage_route");
            GatewayOpenTelemetry.RecordProxyResult(new DefaultHttpContext(), 1.0);
            EmitAccessLog(provider);
            var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            if (elapsedMs > 250)
                throw new Exception($"Proxy telemetry recording blocked for {elapsedMs:F1}ms while the collector was absent");
            var tracerProvider = provider.GetRequiredService<TracerProvider>();
            var meterProvider = provider.GetRequiredService<MeterProvider>();
            var loggerProvider = provider.GetRequiredService<LoggerProvider>();
            _ = tracerProvider.ForceFlush(6000);
            _ = meterProvider.ForceFlush(6000);
            _ = loggerProvider.ForceFlush(6000);
            var shutdown = Stopwatch.StartNew();
            provider.Dispose();
            shutdown.Stop();
            if (shutdown.Elapsed > TimeSpan.FromSeconds(15))
                throw new Exception($"OTLP provider shutdown exceeded its 15-second bound with an absent collector ({shutdown.Elapsed.TotalSeconds:F1}s)");
            Console.WriteLine($"PASS: OTLP providers shut down in {shutdown.Elapsed.TotalMilliseconds:F0}ms with an unreachable collector");
            Console.WriteLine("PASS: request telemetry recording stayed below 250ms with an unreachable collector");
            return Task.CompletedTask;
        }
        finally
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", oldEndpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", oldRatio);
        }
    }

    public static async Task RunAgainstCollectorAsync(string endpoint)
    {
        var oldEndpoint = Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT");
        var oldRatio = Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO");
        try
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", endpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", "1");
            var services = new ServiceCollection();
            services.AddLogging();
            if (!GatewayOpenTelemetry.Configure(services, "otlp-container-acceptance"))
                throw new Exception("Container OTLP configuration was unexpectedly disabled");
            using var provider = services.BuildServiceProvider();
            var tracerProvider = provider.GetRequiredService<TracerProvider>();
            var meterProvider = provider.GetRequiredService<MeterProvider>();
            var loggerProvider = provider.GetRequiredService<LoggerProvider>();
            using var loggingDropScenario = EmitLoggingDropCounters();
            var parent = new ActivityContext(ActivityTraceId.CreateRandom(), ActivitySpanId.CreateRandom(),
                ActivityTraceFlags.Recorded);
            using (var activity = GatewayOpenTelemetry.ActivitySource.StartActivity(
                       "gateway.proxy.request", ActivityKind.Internal, parent))
            {
                if (activity is null) throw new Exception("Container acceptance span was not sampled");
                activity.SetTag("client.address", "203.0.113.99");
                activity.SetTag("url.full", "https://gateway.example/private?token=otlp-container-secret-canary");
                activity.SetTag("url.query", "token=otlp-container-secret-canary");
                activity.SetTag("gateway.route.id", "container_acceptance_route");
                activity.SetTag("gateway.cluster.id", "container_acceptance_cluster");
                activity.SetTag("gateway.destination.id", "container_target_a");
            }
            var response = new DefaultHttpContext();
            response.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.RecordProxyResult(response, 17.5,
                "container_acceptance_route", "container_acceptance_cluster", "container_target_a");
            EmitAccessLog(provider);
            EmitRestrictedLogs(provider);
            if (!tracerProvider.ForceFlush(10000) || !meterProvider.ForceFlush(10000) || !loggerProvider.ForceFlush(10000))
                throw new Exception("Container OTLP exporters failed to flush before acceptance deadline");
            await VerifyPrometheusLoggingCountersAsync(endpoint, loggingDropScenario);
            Console.WriteLine("PASS: real OpenTelemetry Collector accepted traces and metrics via OTLP/HTTP");
        }
        finally
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", oldEndpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", oldRatio);
        }
    }

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
            var loggerProvider = provider.GetRequiredService<LoggerProvider>();
            using var loggingDropScenario = EmitLoggingDropCounters();
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
                activity.SetTag("http.request.header.x-api-key", "otlp-custom-header-canary");
                activity.SetTag("http.request.header.x-customer-id", new[] { "otlp-header-array-canary" });
                activity.SetTag("vendor.custom.payload", "otlp-enrichment-canary");
                activity.SetTag("gateway.route.id", "acceptance_route");
                activity.SetTag("gateway.cluster.id", "acceptance_cluster");
                activity.SetTag("gateway.destination.id", "target_a");
            }
            using var aspNetSource = new ActivitySource("Microsoft.AspNetCore");
            using (var aspNetActivity = aspNetSource.StartActivity(
                       "GET /orders/customer-id-otlp-secret?token=otlp-secret-canary", ActivityKind.Server))
            {
                if (aspNetActivity is null) throw new Exception("ASP.NET HTTP span was not subscribed by the OTel pipeline");
                aspNetActivity.SetTag("http.request.method", "GET");
                // Poison the Activity tag with a syntactically balanced
                // but client-derived path. The actual selected ASP.NET
                // endpoint metadata, never this tag, is the trusted source.
                aspNetActivity.SetTag("http.route", "/users/{untrusted-brace-canary}");
                var selectedContext = new DefaultHttpContext();
                selectedContext.SetEndpoint(new Microsoft.AspNetCore.Routing.RouteEndpoint(
                    _ => Task.CompletedTask,
                    Microsoft.AspNetCore.Routing.Patterns.RoutePatternFactory.Parse("/orders/{orderId}"),
                    0, new EndpointMetadataCollection(), "trusted route fixture"));
                GatewayOpenTelemetry.StampSelectedRouteTemplate(aspNetActivity, selectedContext);
                aspNetActivity.SetTag("http.target", "/orders/customer-id-otlp-secret?token=otlp-secret-canary");
                aspNetActivity.SetTag("url.path", "/orders/customer-id-otlp-secret");
                aspNetActivity.SetTag("url.query", "token=otlp-secret-canary");
                aspNetActivity.SetTag("client.address", "203.0.113.77");
            }
            using (var unmatchedActivity = aspNetSource.StartActivity(
                       "GET /users/unmatched-id-otlp-secret?key=second-secret-canary", ActivityKind.Server))
            {
                if (unmatchedActivity is null) throw new Exception("Unmatched ASP.NET HTTP span was not subscribed by the OTel pipeline");
                unmatchedActivity.SetTag("http.request.method", "GET");
                unmatchedActivity.SetTag("http.target", "/users/unmatched-id-otlp-secret?key=second-secret-canary");
                unmatchedActivity.SetTag("url.path", "/users/unmatched-id-otlp-secret");
                unmatchedActivity.SetTag("url.query", "key=second-secret-canary");
                unmatchedActivity.SetTag("client.address", "203.0.113.78");
            }

            // A literal-looking http.route is not necessarily a safe
            // framework route pattern. A middleware/instrumentation upgrade
            // could fill it with the actual URL path and a customer ID.
            // Verify BOTH the OTLP tag and ASP.NET span name are redacted.
            using (var literalRoute = aspNetSource.StartActivity(
                       "GET /users/route-literal-customer-canary", ActivityKind.Server))
            {
                if (literalRoute is null)
                    throw new Exception("Literal ASP.NET route privacy fixture was not sampled");
                literalRoute.SetTag("http.request.method", "GET");
                literalRoute.SetTag("http.route", "/users/route-literal-customer-canary");
                literalRoute.SetTag("url.path", "/users/route-literal-customer-canary");
            }
            // The route-tag shape alone is not authentication. Even a
            // well-formed brace-wrapped customer path must fail without a
            // marker from the actual selected RouteEndpoint metadata.
            using (var forgedRoute = aspNetSource.StartActivity(
                       "GET /users/brace-wrapped-user-canary", ActivityKind.Server))
            {
                if (forgedRoute is null)
                    throw new Exception("Forged route privacy fixture was not sampled");
                forgedRoute.SetTag("http.request.method", "GET");
                forgedRoute.SetTag("http.route", "/users/{brace-wrapped-user-canary}");
            }
            // An empty brace parameter is also invalid even when a component
            // attempts to pass it as a route-template-looking attribute.
            using (var emptyParameter = aspNetSource.StartActivity(
                       "GET /orders/invalid-empty-parameter-canary", ActivityKind.Server))
            {
                if (emptyParameter is null)
                    throw new Exception("Malformed ASP.NET route privacy fixture was not sampled");
                emptyParameter.SetTag("http.request.method", "GET");
                emptyParameter.SetTag("http.route", "/orders/{}/invalid-empty-parameter-canary");
            }

            // Separate from the synthetic unit path above, this runs
            // a real Kestrel + ASP.NET RouteEndpoint. Only the shipping
            // OpenTelemetry EnrichWithHttpResponse callback can stamp the
            // trusted route, and a live URL customer token must never reach
            // the collector. A synthetic marker alone cannot prove that.
            var inboundW3cTraceId = await RunSelectedAspNetRouteOverRealHttpAsync();

            var response = new Microsoft.AspNetCore.Http.DefaultHttpContext();
            response.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            GatewayOpenTelemetry.RecordProxyResult(response, 12.5,
                "acceptance_route", "acceptance_cluster", "target_a");
            var rejectionReasons = new[]
            {
                "admission_destination_unresolved", "admission_policy_conflict",
                "invalid_admission_config", "admission_configuration_unavailable", "destination_queue_timeout",
                "destination_queue_full", "destination_unavailable_after_queue"
            };
            foreach (var reason in rejectionReasons)
            {
                var rejected = new DefaultHttpContext();
                GatewayOpenTelemetry.MarkLocalRejection(rejected, reason);
                GatewayOpenTelemetry.RecordProxyResult(rejected, 1.0);
            }
            using var stopping = new CancellationTokenSource();
            stopping.Cancel();
            var proxy = new ApplicationBuilder(provider);
            GatewayOpenTelemetry.UseProxyTelemetry(proxy);
            GatewayOpenTelemetry.UseShutdownFence(proxy, stopping.Token);
            proxy.Run(_ => throw new Exception("A request crossed the already-cancelled shutdown fence"));
            var earlyShutdownResponse = new DefaultHttpContext { RequestServices = provider };
            await proxy.Build()(earlyShutdownResponse);
            if (earlyShutdownResponse.Response.StatusCode != StatusCodes.Status503ServiceUnavailable ||
                !earlyShutdownResponse.Response.Headers.TryGetValue("X-GatewayCore-Rejection", out var shutdownReason) ||
                shutdownReason != "gateway_shutdown")
                throw new Exception("Real proxy middleware pipeline did not reject early shutdown with HTTP 503");
            var upstreamHeader = new DefaultHttpContext();
            upstreamHeader.Response.Headers["X-GatewayCore-Rejection"] = "destination_queue_full";
            GatewayOpenTelemetry.RecordProxyResult(upstreamHeader, 1.0);
            var unknownInternalReason = new DefaultHttpContext();
            GatewayOpenTelemetry.MarkLocalRejection(unknownInternalReason,
                "path=/private?token=otlp-rejection-secret-canary");
            GatewayOpenTelemetry.RecordProxyResult(unknownInternalReason, 1.0);
            foreach (var untrustedReason in new[]
                     { "path=/private?token=otlp-rejection-secret-canary", "backend=customer-123" })
            {
                var rejected = new DefaultHttpContext();
                rejected.Response.Headers["X-GatewayCore-Rejection"] = untrustedReason;
                GatewayOpenTelemetry.RecordProxyResult(rejected, 1.0);
            }
            EmitAccessLog(provider);
            EmitRestrictedLogs(provider);
            if (!tracerProvider.ForceFlush(10000) || !meterProvider.ForceFlush(10000) || !loggerProvider.ForceFlush(10000))
                throw new Exception("OTLP provider failed to flush before acceptance deadline");

            var deadline = DateTimeOffset.UtcNow.AddSeconds(10);
            while (records.Count < 3 && DateTimeOffset.UtcNow < deadline)
                await Task.Delay(50, receiverTimeout.Token);
            var captured = records.ToArray();
            var traces = captured.Where(x => x.Path == "/v1/traces").ToArray();
            var metrics = captured.Where(x => x.Path == "/v1/metrics").ToArray();
            var logs = captured.Where(x => x.Path == "/v1/logs").ToArray();
            if (traces.Length == 0 || metrics.Length == 0 || logs.Length == 0)
                throw new Exception($"Expected OTLP traces, metrics and logs; received: {string.Join(", ", captured.Select(x => x.Path))}");

            var traceBytes = traces.SelectMany(x => x.Body).ToArray();
            var tracePayload = Encoding.Latin1.GetString(traceBytes);
            if (traceBytes.AsSpan().IndexOf(Convert.FromHexString(
                    inboundW3cTraceId.ToHexString())) < 0)
                throw new Exception(
                    "W3C remote trace ID from actual Kestrel HTTP request was absent in OTLP export");
            foreach (var sensitive in new[]
                     {
                         "203.0.113.99", "203.0.113.77", "otlp-secret-canary",
                         "203.0.113.78", "customer-id-otlp-secret", "unmatched-id-otlp-secret",
                         "second-secret-canary", "/private", "otlp-custom-header-canary",
                         "otlp-header-array-canary", "otlp-enrichment-canary",
                         "route-literal-customer-canary", "invalid-empty-parameter-canary",
                         "untrusted-brace-canary", "brace-wrapped-user-canary",
                         "live-route-customer-canary"
                     })
                if (tracePayload.Contains(sensitive, StringComparison.Ordinal))
                    throw new Exception($"Sensitive value was present in OTLP trace export: {sensitive}");
            foreach (var expected in new[] { "acceptance_route", "acceptance_cluster", "target_a", "gatewaycore-control-center" })
                if (!tracePayload.Contains(expected, StringComparison.Ordinal))
                    throw new Exception($"Expected bounded trace/resource attribute was absent: {expected}");
            if (!tracePayload.Contains("GET /orders/{orderId}", StringComparison.Ordinal))
                throw new Exception("Selected-route metadata helper did not preserve a safe template");
            if (!tracePayload.Contains("GET /verified-route/{opaqueId}", StringComparison.Ordinal))
                throw new Exception("Real Kestrel ASP.NET RouteEndpoint was not exported with trusted router provenance");
            if (!tracePayload.Contains("HTTP GET", StringComparison.Ordinal))
                throw new Exception("Unmatched ASP.NET span did not fall back to a method-only name");

            var metricPayload = Encoding.Latin1.GetString(metrics.SelectMany(x => x.Body).ToArray());
            foreach (var expected in new[]
                     {
                         "gateway.proxy.requests", "gateway.proxy.request.duration", "5xx",
                         "gateway.route.id", "acceptance_route", "gateway.cluster.id", "acceptance_cluster",
                         "gateway.destination.id", "target_a", "gateway.proxy.local_rejections",
                         "gateway.proxy.rejection.reason"
                     })
                if (!metricPayload.Contains(expected, StringComparison.Ordinal))
                    throw new Exception($"Expected bounded proxy metric was absent: {expected}");
            if (metricPayload.Contains("otlp-rejection-secret-canary", StringComparison.Ordinal) ||
                metricPayload.Contains("customer-123", StringComparison.Ordinal) ||
                metricPayload.Contains("/private", StringComparison.Ordinal))
                throw new Exception("Untrusted rejection header content was present in OTLP metrics");
            var rejectionCounts = ReadOtlpStringAttributeSums(
                metrics.SelectMany(x => x.Body).ToArray(), "gateway.proxy.local_rejections",
                "gateway.proxy.rejection.reason");
            var expectedRejectionLabels = rejectionReasons.Append("gateway_shutdown").Append("other")
                .ToHashSet(StringComparer.Ordinal);
            if (!rejectionCounts.Keys.ToHashSet(StringComparer.Ordinal).SetEquals(expectedRejectionLabels) ||
                rejectionCounts.Count > 9)
                throw new Exception($"Local rejection metric labels were not the fixed allowlist plus other: [{string.Join(",", rejectionCounts.Keys)}]");
            if (!rejectionCounts.TryGetValue("gateway_shutdown", out var shutdownCount) || shutdownCount != 1)
                throw new Exception($"Early pipeline shutdown was not recorded exactly once (observed {shutdownCount})");
            foreach (var reason in expectedRejectionLabels)
                if (!rejectionCounts.TryGetValue(reason, out var reasonCount) || reasonCount != 1)
                    throw new Exception($"Local rejection reason '{reason}' was not counted exactly once (observed {reasonCount})");
            var metricValues = ReadOtlpMetricValues(metrics.SelectMany(x => x.Body).ToArray());
            foreach (var expected in new[]
                     {
                         ("yarp_logging_dropped", loggingDropScenario.TotalDropped),
                         ("yarp_logging_dropped_low_priority", loggingDropScenario.LowPriorityDropped),
                         ("yarp_logging_dropped_high_priority", loggingDropScenario.HighPriorityDropped),
                         ("yarp_logging_write_errors", loggingDropScenario.WriteErrors)
                     })
            {
                metricValues.TryGetValue(expected.Item1, out var values);
                if (expected.Item2 <= 0 || values is null || !values.Contains(expected.Item2))
                    throw new Exception($"OTLP collector did not receive {expected.Item1}={expected.Item2}; " +
                                        $"observed [{string.Join(",", values ?? Array.Empty<long>())}]");
            }
            var logPayload = Encoding.Latin1.GetString(logs.SelectMany(x => x.Body).ToArray());
            foreach (var expected in new[] { "GATEWAY_TELEMETRY_ACCESS", "timestampUtc", "route_acceptance", "statusCode", "_OTHER" })
                if (!logPayload.Contains(expected, StringComparison.Ordinal))
                    throw new Exception($"Expected bounded telemetry access log field was absent from OTLP: {expected}");
            foreach (var sensitive in new[] { "GATEWAY_ACCESS", "clientIp", "clientIpSource",
                         "203.0.113.17", "otlp-secret-canary", "Authorization",
                         "Cookie", "/private", "UNTRUSTED-METHOD-SECRET" })
                if (logPayload.Contains(sensitive, StringComparison.OrdinalIgnoreCase))
                    throw new Exception($"Sensitive local-access or request data was present in OTLP log export: {sensitive}");
            foreach (var excluded in new[] { "otlp-audit-secret-canary", "otlp-application-secret-canary", "GatewayCore.SecurityAudit" })
                if (logPayload.Contains(excluded, StringComparison.Ordinal))
                    throw new Exception($"Non-access log data was present in OTLP export: {excluded}");
            Console.WriteLine("PASS: real OTLP/HTTP collector received bounded console total/low/high drops and write-error counter values");
            Console.WriteLine("PASS: real OTLP/HTTP collector received traces, metrics and IP-free bounded access telemetry logs; local access/IP fields were excluded");
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

    private static void EmitAccessLog(IServiceProvider provider)
    {
        var factory = provider.GetRequiredService<ILoggerFactory>();
        var local = factory.CreateLogger("GatewayCore.AccessLog");
        var exported = factory.CreateLogger("GatewayCore.TelemetryAccess");
        var now = DateTimeOffset.UtcNow;
        GatewayOpenTelemetry.LogAccess(local,
            now, "203.0.113.17", "remote", "GET", "route_acceptance", 200, 12.5);
        GatewayOpenTelemetry.LogTelemetryAccess(exported,
            now, GatewayOpenTelemetry.BoundedTelemetryMethod("GET"), "route_acceptance", 200, 12.5);
        // Unknown untrusted HTTP methods must never enter the OTLP log stream.
        GatewayOpenTelemetry.LogTelemetryAccess(exported,
            now, GatewayOpenTelemetry.BoundedTelemetryMethod("UNTRUSTED-METHOD-SECRET"),
            "_other", 400, 1.0);
        if (GatewayOpenTelemetry.BoundedTelemetryMethod("UNTRUSTED-METHOD-SECRET") != "_OTHER")
            throw new Exception("Unknown HTTP method was not normalized before OTLP logging");
    }

    private static void EmitRestrictedLogs(IServiceProvider provider)
    {
        var factory = provider.GetRequiredService<ILoggerFactory>();
        factory.CreateLogger("GatewayCore.SecurityAudit")
            .LogWarning("Administrative audit marker {Secret}", "otlp-audit-secret-canary");
        factory.CreateLogger("Microsoft.Hosting.Lifetime")
            .LogWarning("Application diagnostic marker {Secret}", "otlp-application-secret-canary");
    }

    private static async Task<ActivityTraceId> RunSelectedAspNetRouteOverRealHttpAsync()
    {
        // A real W3C remote parent must survive Kestrel's ASP.NET tracing
        // instrumentation and reach the exact OTLP collector wire payload.
        // A random local Activity alone cannot prove inbound propagation.
        var remoteTrace = ActivityTraceId.CreateRandom();
        var remoteParent = ActivitySpanId.CreateRandom();
        var builder = WebApplication.CreateBuilder(Array.Empty<string>());
        builder.WebHost.UseUrls("http://127.0.0.1:0");
        await using var app = builder.Build();
        app.MapGet("/verified-route/{opaqueId}", () =>
        {
            var current = Activity.Current;
            if (current is null || current.IdFormat != ActivityIdFormat.W3C ||
                current.TraceId != remoteTrace || current.ParentSpanId != remoteParent)
                throw new InvalidOperationException(
                    "Actual selected ASP.NET route did not preserve its W3C remote traceparent");
            return Results.Text("ok");
        });
        await app.StartAsync();
        try
        {
            var localAddress = app.Urls.Single(url =>
                url.StartsWith("http://127.0.0.1:", StringComparison.Ordinal));
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            { Timeout = TimeSpan.FromSeconds(5) };
            using var request = new HttpRequestMessage(HttpMethod.Get,
                localAddress.TrimEnd('/') + "/verified-route/live-route-customer-canary");
            request.Headers.TryAddWithoutValidation("traceparent",
                $"00-{remoteTrace.ToHexString()}-{remoteParent.ToHexString()}-01");
            using var response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();
            return remoteTrace;
        }
        finally
        {
            await app.StopAsync();
        }
    }

    private static async Task VerifyPrometheusLoggingCountersAsync(string collectorEndpoint,
        LoggingDropScenario scenario)
    {
        var collector = new Uri(collectorEndpoint, UriKind.Absolute);
        if (collector.Scheme != Uri.UriSchemeHttp || collector.Port < 1 ||
            !IPAddress.TryParse(collector.Host, out var address) || !IPAddress.IsLoopback(address))
            throw new InvalidOperationException("Container acceptance requires a loopback OTLP Collector endpoint");
        var prometheusBase = new UriBuilder(collector) { Port = 9090, Path = "/api/v1/query", Query = "" };
        using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
        { Timeout = TimeSpan.FromSeconds(3) };
        foreach (var (name, expected) in new[]
                 {
                     ("yarp_logging_dropped_total", scenario.TotalDropped),
                     ("yarp_logging_dropped_low_priority_total", scenario.LowPriorityDropped),
                     ("yarp_logging_dropped_high_priority_total", scenario.HighPriorityDropped),
                     ("yarp_logging_write_errors_total", scenario.WriteErrors)
                 })
        {
            if (expected <= 0) throw new Exception($"Container counter fixture did not produce {name}");
            var deadline = DateTimeOffset.UtcNow.AddSeconds(30);
            var observed = false;
            string lastQueryResult = "<Prometheus query not completed>";
            while (!observed && DateTimeOffset.UtcNow < deadline)
            {
                var requestBuilder = new UriBuilder(prometheusBase.Uri)
                { Query = "query=" + Uri.EscapeDataString(name) };
                var requestUri = requestBuilder.Uri;
                try
                {
                    using var response = await client.GetAsync(requestUri);
                    response.EnsureSuccessStatusCode();
                    using var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
                    var root = payload.RootElement;
                    lastQueryResult = payload.RootElement.GetRawText();
                    observed = root.TryGetProperty("status", out var status) && status.GetString() == "success" &&
                        root.GetProperty("data").GetProperty("result").EnumerateArray().Any(series =>
                        {
                            var raw = series.GetProperty("value")[1].GetString();
                            return double.TryParse(raw, System.Globalization.NumberStyles.Float,
                                       System.Globalization.CultureInfo.InvariantCulture, out var value) && value == expected;
                        });
                }
                catch (HttpRequestException) { }
                catch (TaskCanceledException) { }
                if (!observed) await Task.Delay(1000);
            }
            if (!observed)
            {
                var observedSeries = await ReadPrometheusLoggingSeriesAsync(client, prometheusBase.Uri);
                throw new Exception($"Collector-to-Prometheus pipeline did not expose {name}={expected}. " +
                    $"Last exact query response: {lastQueryResult}. " +
                    $"Observed yarp_logging series: {observedSeries}");
            }
            Console.WriteLine($"PASS: Prometheus received Collector-exported {name}={expected}");
        }
    }

    private static async Task<string> ReadPrometheusLoggingSeriesAsync(HttpClient client, Uri prometheusBase)
    {
        var request = new UriBuilder(prometheusBase)
        { Query = "query=" + Uri.EscapeDataString("{__name__=~\"yarp_logging_.*\"}") };
        try
        {
            using var response = await client.GetAsync(request.Uri);
            response.EnsureSuccessStatusCode();
            using var payload = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync());
            return payload.RootElement.GetProperty("data").GetProperty("result").GetRawText();
        }
        catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException or JsonException)
        {
            return $"<diagnostic query failed: {exception.GetType().Name}: {exception.Message}>";
        }
    }

    private static LoggingDropScenario EmitLoggingDropCounters()
    {
        return new LoggingDropScenario();
    }

    private sealed class LoggingDropScenario : IDisposable
    {
        private readonly ManualResetEventSlim release = new(false);
        private readonly ManualResetEventSlim entered = new(false);
        private readonly ManualResetEventSlim drained = new(false);
        private readonly BlockingTextWriter writer;
        private readonly NonBlockingConsoleLoggerProvider sink;

        public long TotalDropped => sink.DroppedMessages;
        public long LowPriorityDropped => sink.DroppedLowPriorityMessages;
        public long HighPriorityDropped => sink.DroppedHighPriorityMessages;
        public long WriteErrors => sink.WriteErrors;

        public LoggingDropScenario()
        {
            writer = new BlockingTextWriter(release, entered, drained);
            sink = new NonBlockingConsoleLoggerProvider(writer, capacity: 16, maxLineChars: 256);
            try
            {
                var logger = sink.CreateLogger("otlp-counter-acceptance");
                logger.LogInformation("fill background-writer handoff slot");
                if (!entered.Wait(TimeSpan.FromSeconds(3)))
                    throw new Exception("OTLP counter acceptance writer did not enter its blocked state");
                for (var i = 0; i < 64; i++) logger.LogInformation("low priority saturation {Index}", i);
                if (sink.DroppedLowPriorityMessages == 0 || sink.QueuedMessages != 14)
                    throw new Exception("OTLP counter acceptance did not prove bounded low-priority queue saturation");
                for (var i = 0; i < 64; i++) logger.LogWarning("high priority saturation {Index}", i);
                if (sink.DroppedHighPriorityMessages == 0 || sink.QueuedMessages != sink.Capacity)
                    throw new Exception("OTLP counter acceptance did not prove bounded high-priority queue saturation");
                if (sink.DroppedMessages != sink.DroppedLowPriorityMessages + sink.DroppedHighPriorityMessages)
                    throw new Exception("OTLP console drop totals did not reconcile by priority");
                release.Set();
                if (!drained.Wait(TimeSpan.FromSeconds(3)))
                    throw new Exception("OTLP counter acceptance writer did not drain after release");
                if (sink.WriteErrors != 1)
                    throw new Exception($"OTLP counter acceptance expected one simulated writer failure, got {sink.WriteErrors}");
            }
            catch
            {
                Dispose();
                throw;
            }
        }

        public void Dispose()
        {
            release.Set();
            sink.Dispose();
            drained.Dispose();
            entered.Dispose();
            release.Dispose();
            writer.Dispose();
        }
    }

    private sealed class BlockingTextWriter(ManualResetEventSlim release,
        ManualResetEventSlim entered, ManualResetEventSlim drained) : StringWriter
    {
        private int written;

        public override void WriteLine(string? value)
        {
            entered.Set();
            release.Wait();
            if (Interlocked.Increment(ref written) == 1) throw new IOException("simulated writer failure");
            base.WriteLine(value);
            if (Volatile.Read(ref written) >= 17)
                drained.Set();
        }
    }

    private static Dictionary<string, long[]> ReadOtlpMetricValues(byte[] payload)
    {
        var result = new Dictionary<string, List<long>>(StringComparer.Ordinal);
        foreach (var resource in ReadFields(payload).Where(field => field.Number == 1 && field.Wire == 2))
        foreach (var scope in ReadFields(resource.Bytes!).Where(field => field.Number == 2 && field.Wire == 2))
        foreach (var metric in ReadFields(scope.Bytes!).Where(field => field.Number == 2 && field.Wire == 2))
        {
            var metricFields = ReadFields(metric.Bytes!);
            var name = metricFields.FirstOrDefault(field => field.Number == 1 && field.Wire == 2).Text;
            if (string.IsNullOrEmpty(name)) continue;
            var sum = metricFields.FirstOrDefault(field => field.Number == 7 && field.Wire == 2);
            if (sum.Bytes is null) continue;
            foreach (var point in ReadFields(sum.Bytes!).Where(field => field.Number == 1 && field.Wire == 2))
            {
                var value = ReadFields(point.Bytes!).FirstOrDefault(field => field.Number == 6 && field.Wire == 1);
                if (value.Bytes is null) continue;
                if (!result.TryGetValue(name, out var values)) result[name] = values = new List<long>();
                values.Add(BinaryPrimitives.ReadInt64LittleEndian(value.Bytes));
            }
        }
        return result.ToDictionary(pair => pair.Key, pair => pair.Value.ToArray(), StringComparer.Ordinal);
    }

    private static Dictionary<string, long> ReadOtlpStringAttributeSums(byte[] payload, string metricName, string attributeName)
    {
        var values = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var resource in ReadFields(payload).Where(field => field.Number == 1 && field.Wire == 2))
        foreach (var scope in ReadFields(resource.Bytes!).Where(field => field.Number == 2 && field.Wire == 2))
        foreach (var metric in ReadFields(scope.Bytes!).Where(field => field.Number == 2 && field.Wire == 2))
        {
            var metricFields = ReadFields(metric.Bytes!);
            if (metricFields.FirstOrDefault(field => field.Number == 1 && field.Wire == 2).Text != metricName)
                continue;
            var sum = metricFields.FirstOrDefault(field => field.Number == 7 && field.Wire == 2);
            if (sum.Bytes is null) continue;
            foreach (var point in ReadFields(sum.Bytes).Where(field => field.Number == 1 && field.Wire == 2))
            foreach (var attribute in ReadFields(point.Bytes!).Where(field => field.Number == 7 && field.Wire == 2))
            {
                var keyValue = ReadFields(attribute.Bytes!);
                if (keyValue.FirstOrDefault(field => field.Number == 1 && field.Wire == 2).Text != attributeName)
                    continue;
                var anyValue = keyValue.FirstOrDefault(field => field.Number == 2 && field.Wire == 2);
                if (anyValue.Bytes is null) continue;
                var textValue = ReadFields(anyValue.Bytes).FirstOrDefault(field => field.Number == 1 && field.Wire == 2).Text;
                var countField = ReadFields(point.Bytes!).FirstOrDefault(field => field.Number == 6 && field.Wire == 1);
                if (textValue is not null && countField.Bytes is not null)
                {
                    var count = BinaryPrimitives.ReadInt64LittleEndian(countField.Bytes);
                    values[textValue] = values.GetValueOrDefault(textValue) + count;
                }
            }
        }
        return values;
    }

    private readonly record struct ProtoField(int Number, int Wire, ulong Varint, byte[]? Bytes, string? Text);

    private static List<ProtoField> ReadFields(byte[] payload)
    {
        var fields = new List<ProtoField>();
        var offset = 0;
        while (offset < payload.Length)
        {
            var tag = ReadVarint(payload, ref offset);
            var number = (int)(tag >> 3);
            var wire = (int)(tag & 7);
            if (number == 0) throw new InvalidDataException("Invalid protobuf field number");
            switch (wire)
            {
                case 0:
                    fields.Add(new ProtoField(number, wire, ReadVarint(payload, ref offset), null, null));
                    break;
                case 1:
                    if (payload.Length - offset < 8) throw new InvalidDataException("Truncated protobuf fixed64 field");
                    fields.Add(new ProtoField(number, wire, 0, payload.AsSpan(offset, 8).ToArray(), null));
                    offset += 8;
                    break;
                case 2:
                    var length = checked((int)ReadVarint(payload, ref offset));
                    if (length < 0 || payload.Length - offset < length)
                        throw new InvalidDataException("Truncated protobuf length-delimited field");
                    var bytes = payload.AsSpan(offset, length).ToArray();
                    fields.Add(new ProtoField(number, wire, 0, bytes,
                        Encoding.UTF8.GetString(bytes)));
                    offset += length;
                    break;
                case 5:
                    if (payload.Length - offset < 4) throw new InvalidDataException("Truncated protobuf fixed32 field");
                    fields.Add(new ProtoField(number, wire, 0, payload.AsSpan(offset, 4).ToArray(), null));
                    offset += 4;
                    break;
                default:
                    throw new InvalidDataException($"Unsupported protobuf wire type {wire}");
            }
        }
        return fields;
    }

    private static ulong ReadVarint(byte[] payload, ref int offset)
    {
        ulong value = 0;
        for (var shift = 0; shift < 64; shift += 7)
        {
            if (offset >= payload.Length) throw new InvalidDataException("Truncated protobuf varint");
            var current = payload[offset++];
            value |= (ulong)(current & 0x7f) << shift;
            if ((current & 0x80) == 0) return value;
        }
        throw new InvalidDataException("Protobuf varint exceeds 64 bits");
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
