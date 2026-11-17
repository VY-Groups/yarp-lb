using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry;
using OpenTelemetry.Exporter;
using OpenTelemetry.Metrics;
using OpenTelemetry.Logs;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Opt-in OTLP traces and metrics. Export uses bounded SDK queues and background
/// workers; collector availability never gates the proxy request path.
/// </summary>
public static class GatewayOpenTelemetry
{
    public const string ActivitySourceName = "GatewayCore.ControlCenter";
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, "0.1");
    private static readonly Meter Meter = new(ActivitySourceName, "0.1");
    private static readonly Counter<long> ProxyRequests = Meter.CreateCounter<long>("gateway.proxy.requests");
    private static readonly Histogram<double> ProxyDuration = Meter.CreateHistogram<double>("gateway.proxy.request.duration", "ms");

    public static bool Configure(IServiceCollection services, string? machineName = null)
    {
        var endpoint = OtlpEndpointPolicy.Parse(Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT"));
        if (endpoint is null) return false;
        var traceEndpoint = new Uri(endpoint, "/v1/traces");
        var metricEndpoint = new Uri(endpoint, "/v1/metrics");
        var sampleRatio = ParseSampleRatio(Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO"));
        var instance = string.IsNullOrWhiteSpace(machineName) ? Environment.MachineName : machineName;
        if (instance.Length > 128) throw new InvalidOperationException("OTel service instance ID exceeds 128 characters");

        services.AddLogging(logging => logging.AddFilter("GatewayCore.AccessLog", LogLevel.Information));
        services.AddOpenTelemetry()
            .ConfigureResource(resource => resource.AddService(
                serviceName: "gatewaycore-control-center",
                serviceVersion: "0.1",
                serviceInstanceId: instance))
            .WithTracing(tracing => tracing
                .SetSampler(new ParentBasedSampler(new TraceIdRatioBasedSampler(sampleRatio)))
                .AddSource(ActivitySourceName)
                .AddProcessor(new GatewayTelemetryPrivacyProcessor())
                .AddAspNetCoreInstrumentation(options =>
                {
                    options.Filter = context =>
                        !context.Request.Path.StartsWithSegments("/gateway/metrics") &&
                        !context.Request.Path.StartsWithSegments("/admin/api/metrics");
                    options.EnrichWithHttpRequest = (activity, request) =>
                    {
                        var proxy = request.HttpContext.Features.Get<IReverseProxyFeature>();
                        SetBoundedId(activity, "gateway.route.id", proxy?.Route?.Config.RouteId);
                        SetBoundedId(activity, "gateway.cluster.id", proxy?.Cluster?.Config.ClusterId);
                    };
                    options.RecordException = false;
                })
                .AddOtlpExporter(exporter =>
                {
                    exporter.Endpoint = traceEndpoint;
                    exporter.Protocol = OtlpExportProtocol.HttpProtobuf;
                    exporter.TimeoutMilliseconds = 5000;
                }))
            // Access logs use a dedicated logger category below. This prevents application,
            // authentication and audit messages from being copied into the OTLP log stream.
            .WithLogging(logging => logging
                .AddOtlpExporter((exporter, processor) =>
                {
                    exporter.Endpoint = new Uri(endpoint, "/v1/logs");
                    exporter.Protocol = OtlpExportProtocol.HttpProtobuf;
                    exporter.TimeoutMilliseconds = 5000;
                    processor.BatchExportProcessorOptions.MaxQueueSize = 2048;
                    processor.BatchExportProcessorOptions.MaxExportBatchSize = 512;
                    processor.BatchExportProcessorOptions.ScheduledDelayMilliseconds = 5000;
                    processor.BatchExportProcessorOptions.ExporterTimeoutMilliseconds = 5000;
                }), options =>
                {
                    options.IncludeFormattedMessage = false;
                    options.ParseStateValues = true;
                    options.IncludeScopes = false;
                })
            .WithMetrics(metrics => metrics
                .AddMeter(ActivitySourceName)
                .AddAspNetCoreInstrumentation()
                .AddRuntimeInstrumentation()
                .AddOtlpExporter((exporter, reader) =>
                {
                    exporter.Endpoint = metricEndpoint;
                    exporter.Protocol = OtlpExportProtocol.HttpProtobuf;
                    exporter.TimeoutMilliseconds = 5000;
                    reader.PeriodicExportingMetricReaderOptions.ExportIntervalMilliseconds = 15000;
                    reader.PeriodicExportingMetricReaderOptions.ExportTimeoutMilliseconds = 5000;
                }));
        return true;
    }

    public static Activity? StartProxyActivity(HttpContext context)
    {
        var activity = ActivitySource.StartActivity("gateway.proxy.request", ActivityKind.Internal);
        var proxy = context.Features.Get<IReverseProxyFeature>();
        SetBoundedId(activity, "gateway.route.id", proxy?.Route?.Config.RouteId);
        SetBoundedId(activity, "gateway.cluster.id", proxy?.Cluster?.Config.ClusterId);
        return activity;
    }

    public static void CompleteProxyActivity(Activity? activity, HttpContext context, string? destinationId)
    {
        if (activity is null) return;
        SetBoundedId(activity, "gateway.destination.id", destinationId);
        activity.SetTag("http.response.status_code", context.Response.StatusCode);
        if (context.Response.StatusCode >= 500)
            activity.SetStatus(ActivityStatusCode.Error);
    }

    public static void RecordProxyResult(HttpContext context, double elapsedMs)
    {
        var statusClass = context.Response.StatusCode switch
        {
            >= 200 and < 300 => "2xx",
            >= 300 and < 400 => "3xx",
            >= 400 and < 500 => "4xx",
            >= 500 and < 600 => "5xx",
            _ => "other"
        };
        var tags = new TagList { { "http.response.status_class", statusClass } };
        ProxyRequests.Add(1, tags);
        ProxyDuration.Record(elapsedMs, tags);
    }

    public static void RecordProxyException(Activity? activity, Exception exception)
    {
        if (activity is null) return;
        activity.SetStatus(ActivityStatusCode.Error);
        activity.SetTag("error.type", exception.GetType().Name);
    }

    private static double ParseSampleRatio(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return 0.05;
        if (!double.TryParse(text, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var ratio) ||
            !double.IsFinite(ratio) || ratio is < 0 or > 1)
            throw new InvalidOperationException("YARP_OTEL_TRACE_SAMPLE_RATIO must be a finite number from 0 to 1");
        return ratio;
    }

    private static void SetBoundedId(Activity? activity, string key, string? value)
    {
        if (activity is not null && value is { Length: > 0 and <= 80 } &&
            Regex.IsMatch(value, "^[A-Za-z0-9_-]+$", RegexOptions.CultureInvariant))
            activity.SetTag(key, value);
    }
}

/// <summary>Keep client identifiers, request paths and secrets out of OTLP spans.</summary>
internal sealed class GatewayTelemetryPrivacyProcessor : BaseProcessor<Activity>
{
    private static readonly string[] SensitiveTags =
    [
        "client.address", "client.port", "network.peer.address", "network.peer.port",
        "url.full", "url.path", "url.query", "user_agent.original",
        "http.request.header.authorization", "http.request.header.cookie"
    ];

    public override void OnEnd(Activity data)
    {
        foreach (var tag in SensitiveTags) data.SetTag(tag, null);
        base.OnEnd(data);
    }
}
