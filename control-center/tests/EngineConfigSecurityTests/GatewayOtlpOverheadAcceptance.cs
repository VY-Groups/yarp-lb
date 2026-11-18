using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

/// <summary>
/// Paired loopback measurement of the shipping proxy telemetry middleware.
/// This is a repeatable CI comparison, not customer-capacity or production evidence.
/// </summary>
public static class GatewayOtlpOverheadAcceptance
{
    private const int RequestsPerSample = 10000;
    private const int WarmupRequests = 500;
    private const int Concurrency = 16;
    private const int Samples = 3;

    public static async Task RunAsync()
    {
        var oldEndpoint = Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT");
        var oldRatio = Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO");
        await using var collector = await StartCollectorAsync();
        var collectorAddress = collector.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        var pairs = new List<PairedSample>();
        try
        {
            // Alternate order to reduce systematic warm-cache and runner-load bias.
            for (var index = 0; index < Samples; index++)
            {
                var telemetryFirst = index % 2 == 1;
                var first = await MeasureAsync(telemetryFirst, collectorAddress);
                var second = await MeasureAsync(!telemetryFirst, collectorAddress);
                pairs.Add(telemetryFirst
                    ? new PairedSample(second, first)
                    : new PairedSample(first, second));
            }

            var disabled = pairs.Select(pair => pair.TelemetryDisabled).ToArray();
            var enabled = pairs.Select(pair => pair.TelemetryEnabled).ToArray();
            var disabledP95 = Median(disabled.Select(result => result.P95Milliseconds));
            var enabledP95 = Median(enabled.Select(result => result.P95Milliseconds));
            var disabledRps = Median(disabled.Select(result => result.RequestsPerSecond));
            var enabledRps = Median(enabled.Select(result => result.RequestsPerSecond));
            var report = new
            {
                benchmark = "GatewayCore proxy telemetry middleware, loopback HTTP",
                operatingSystem = Environment.OSVersion.ToString(),
                requestsPerSample = RequestsPerSample,
                warmupRequests = WarmupRequests,
                concurrency = Concurrency,
                samplesPerMode = Samples,
                samplingRatio = 0.05,
                connectionPolicy = "HTTP/1.1 keep-alive; one shared client per mode sample; drain response body",
                collector = "local disposable HTTP receiver",
                median = new
                {
                    telemetryDisabled = new { p95Milliseconds = Round(disabledP95), requestsPerSecond = Round(disabledRps) },
                    telemetryEnabled = new { p95Milliseconds = Round(enabledP95), requestsPerSecond = Round(enabledRps) },
                    p95LatencyChangePercent = PercentChange(disabledP95, enabledP95),
                    throughputChangePercent = PercentChange(disabledRps, enabledRps)
                },
                sampleRanges = new
                {
                    telemetryDisabled = new
                    {
                        minRequestsPerSecond = Round(disabled.Min(result => result.RequestsPerSecond)),
                        maxRequestsPerSecond = Round(disabled.Max(result => result.RequestsPerSecond)),
                        minP95Milliseconds = Round(disabled.Min(result => result.P95Milliseconds)),
                        maxP95Milliseconds = Round(disabled.Max(result => result.P95Milliseconds))
                    },
                    telemetryEnabled = new
                    {
                        minRequestsPerSecond = Round(enabled.Min(result => result.RequestsPerSecond)),
                        maxRequestsPerSecond = Round(enabled.Max(result => result.RequestsPerSecond)),
                        minP95Milliseconds = Round(enabled.Min(result => result.P95Milliseconds)),
                        maxP95Milliseconds = Round(enabled.Max(result => result.P95Milliseconds))
                    }
                },
                pairedDeltas = pairs.Select((pair, index) => new
                {
                    pair = index + 1,
                    telemetryWasFirst = index % 2 == 1,
                    p95LatencyChangePercent = PercentChange(pair.TelemetryDisabled.P95Milliseconds,
                        pair.TelemetryEnabled.P95Milliseconds),
                    throughputChangePercent = PercentChange(pair.TelemetryDisabled.RequestsPerSecond,
                        pair.TelemetryEnabled.RequestsPerSecond),
                    telemetryDisabled = Sample(pair.TelemetryDisabled),
                    telemetryEnabled = Sample(pair.TelemetryEnabled)
                }),
                samples = pairs.SelectMany((pair, index) => new[]
                {
                    new { pair = index + 1, telemetryEnabled = false, sample = Sample(pair.TelemetryDisabled) },
                    new { pair = index + 1, telemetryEnabled = true, sample = Sample(pair.TelemetryEnabled) }
                })
            };
            var reportJson = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
            var reportDirectory = Environment.GetEnvironmentVariable("RUNNER_TEMP");
            if (string.IsNullOrWhiteSpace(reportDirectory)) reportDirectory = Path.GetTempPath();
            var reportPath = Path.Combine(reportDirectory, "gatewaycore-otel-overhead-report.json");
            await File.WriteAllTextAsync(reportPath, reportJson);
            var githubSummaryPath = Environment.GetEnvironmentVariable("GITHUB_STEP_SUMMARY");
            if (!string.IsNullOrWhiteSpace(githubSummaryPath))
            {
                await File.AppendAllTextAsync(githubSummaryPath,
                    $"## Paired GatewayCore telemetry middleware measurement\n\n```json\n{reportJson}\n```\n");
            }
            Console.WriteLine("OTEL_OVERHEAD_REPORT " + reportJson);
            Console.WriteLine($"OTEL_OVERHEAD_REPORT_PATH {reportPath}");
            Console.WriteLine("PASS: paired proxy telemetry overhead comparison completed; values are CI loopback measurements only");
        }
        finally
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", oldEndpoint);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", oldRatio);
        }
    }

    private static async Task<MeasurementApp> StartCollectorAsync()
    {
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(),
            EnvironmentName = "Production"
        });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        var app = builder.Build();
        app.MapPost("/v1/{signal}", async context =>
        {
            await context.Request.Body.CopyToAsync(Stream.Null, context.RequestAborted);
            context.Response.StatusCode = StatusCodes.Status200OK;
        });
        await app.StartAsync();
        return new MeasurementApp(app);
    }

    private static async Task<SampleResult> MeasureAsync(bool telemetryEnabled, string collectorAddress)
    {
        if (telemetryEnabled)
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", collectorAddress);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", "0.05");
        }
        else
        {
            Environment.SetEnvironmentVariable("YARP_OTEL_ENDPOINT", null);
            Environment.SetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO", null);
        }

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(),
            EnvironmentName = "Production"
        });
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 0));
        if (telemetryEnabled && !GatewayOpenTelemetry.Configure(builder.Services, "otlp-overhead-acceptance"))
            throw new InvalidOperationException("Telemetry-on benchmark failed to configure the exporter");

        await using var app = builder.Build();
        app.Use(async (context, next) =>
        {
            var started = Stopwatch.GetTimestamp();
            var activity = GatewayOpenTelemetry.StartProxyActivity(context);
            try
            {
                await next();
            }
            catch (Exception exception)
            {
                GatewayOpenTelemetry.RecordProxyException(activity, exception);
                throw;
            }
            finally
            {
                var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                GatewayOpenTelemetry.CompleteProxyActivity(activity, context, "benchmark_backend");
                GatewayOpenTelemetry.RecordProxyResult(context, elapsedMs);
            }
        });
        app.MapGet("/benchmark", () => Results.Text("ok"));
        await app.StartAsync();
        var address = app.Services.GetRequiredService<IServer>()
            .Features.Get<IServerAddressesFeature>()!.Addresses.Single();
        using var handler = new SocketsHttpHandler { MaxConnectionsPerServer = Concurrency };
        using var client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = TimeSpan.FromSeconds(15),
            DefaultRequestVersion = HttpVersion.Version11,
            DefaultVersionPolicy = HttpVersionPolicy.RequestVersionExact
        };
        var requestUri = new Uri(new Uri(address), "benchmark");

        await SendRequestsAsync(client, requestUri, WarmupRequests);
        var latencies = await SendRequestsAsync(client, requestUri, RequestsPerSample);
        var elapsed = latencies.Elapsed.TotalSeconds;
        var sorted = latencies.Milliseconds.Order().ToArray();

        if (telemetryEnabled)
        {
            var services = app.Services;
            var tracer = services.GetRequiredService<TracerProvider>();
            var meter = services.GetRequiredService<MeterProvider>();
            var logger = services.GetRequiredService<LoggerProvider>();
            if (!tracer.ForceFlush(10000) || !meter.ForceFlush(10000) || !logger.ForceFlush(10000))
                throw new InvalidOperationException("Local OTLP receiver did not drain overhead benchmark exports");
        }

        await app.StopAsync();
        return new SampleResult(telemetryEnabled, RequestsPerSample / elapsed,
            Percentile(sorted, 0.50), Percentile(sorted, 0.95), Percentile(sorted, 0.99));
    }

    private static async Task<LatencySample> SendRequestsAsync(HttpClient client, Uri uri, int count)
    {
        var latencies = new ConcurrentBag<double>();
        var requestCountPerWorker = count / Concurrency;
        var remainder = count % Concurrency;
        var wallStart = Stopwatch.GetTimestamp();
        var workers = Enumerable.Range(0, Concurrency).Select(async worker =>
        {
            var requests = requestCountPerWorker + (worker < remainder ? 1 : 0);
            for (var request = 0; request < requests; request++)
            {
                var started = Stopwatch.GetTimestamp();
                using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
                if (response.StatusCode != HttpStatusCode.OK)
                    throw new InvalidOperationException($"Loopback benchmark returned HTTP {(int)response.StatusCode}");
                await response.Content.CopyToAsync(Stream.Null);
                latencies.Add(Stopwatch.GetElapsedTime(started).TotalMilliseconds);
            }
        });
        await Task.WhenAll(workers);
        return new LatencySample(Stopwatch.GetElapsedTime(wallStart), latencies.ToArray());
    }

    private static double Percentile(double[] sorted, double percentile)
    {
        if (sorted.Length == 0) return 0;
        var index = Math.Clamp((int)Math.Ceiling(sorted.Length * percentile) - 1, 0, sorted.Length - 1);
        return sorted[index];
    }

    private static double Median(IEnumerable<double> values)
    {
        var sorted = values.Order().ToArray();
        return sorted.Length % 2 == 1
            ? sorted[sorted.Length / 2]
            : (sorted[sorted.Length / 2 - 1] + sorted[sorted.Length / 2]) / 2;
    }

    private static double Round(double value) => Math.Round(value, 3, MidpointRounding.AwayFromZero);

    private static object Sample(SampleResult result) => new
    {
        requestsPerSecond = Round(result.RequestsPerSecond),
        p50Milliseconds = Round(result.P50Milliseconds),
        p95Milliseconds = Round(result.P95Milliseconds),
        p99Milliseconds = Round(result.P99Milliseconds)
    };

    private static double? PercentChange(double baseline, double measured) =>
        baseline <= 0 ? null : Round((measured - baseline) / baseline * 100);

    private sealed record SampleResult(bool TelemetryEnabled, double RequestsPerSecond,
        double P50Milliseconds, double P95Milliseconds, double P99Milliseconds);

    private sealed record PairedSample(SampleResult TelemetryDisabled, SampleResult TelemetryEnabled);

    private sealed record LatencySample(TimeSpan Elapsed, double[] Milliseconds);

    private sealed class MeasurementApp(WebApplication app) : IAsyncDisposable
    {
        public IServiceProvider Services => app.Services;
        public ValueTask DisposeAsync() => app.DisposeAsync();
    }
}
