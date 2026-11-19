using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Collections.Concurrent;
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
    private static readonly GatewayTelemetryDimensionBudget DimensionBudget = new();

    public static bool Configure(IServiceCollection services, string? machineName = null)
    {
        var endpoint = OtlpEndpointPolicy.Parse(Environment.GetEnvironmentVariable("YARP_OTEL_ENDPOINT"));
        if (endpoint is null) return false;
        var traceEndpoint = new Uri(endpoint, "/v1/traces");
        var metricEndpoint = new Uri(endpoint, "/v1/metrics");
        var sampleRatio = ParseSampleRatio(Environment.GetEnvironmentVariable("YARP_OTEL_TRACE_SAMPLE_RATIO"));
        var instance = string.IsNullOrWhiteSpace(machineName) ? Environment.MachineName : machineName;
        if (instance.Length > 128) throw new InvalidOperationException("OTel service instance ID exceeds 128 characters");

        services.AddLogging(logging => logging.AddFilter<OpenTelemetryLoggerProvider>(
            (category, level) => string.Equals(category, "GatewayCore.AccessLog", StringComparison.Ordinal) &&
                level >= LogLevel.Information));
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
                .AddMeter("GatewayCoreYarp.Logging")
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

    public static void RecordProxyResult(HttpContext context, double elapsedMs,
        string? routeId = null, string? clusterId = null, string? destinationId = null)
    {
        var statusClass = context.Response.StatusCode switch
        {
            >= 200 and < 300 => "2xx",
            >= 300 and < 400 => "3xx",
            >= 400 and < 500 => "4xx",
            >= 500 and < 600 => "5xx",
            _ => "other"
        };
        var tags = DimensionBudget.CreateTags(routeId, clusterId, destinationId, statusClass);
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

/// <summary>
/// Caps distinct route/cluster/destination tuples emitted to OTLP. Configured IDs
/// are validated before becoming metric attributes; overflow is one fixed tuple.
/// </summary>
internal sealed class GatewayTelemetryDimensionBudget
{
    public const int MaximumTrackedTuples = 4096;
    private readonly int _maximumTrackedTuples;
    private readonly ConcurrentDictionary<string, byte> _tracked = new(StringComparer.Ordinal);
    private readonly object _registrationLock = new();
    private volatile bool _saturated;

    public GatewayTelemetryDimensionBudget(int maximumTrackedTuples = MaximumTrackedTuples)
    {
        if (maximumTrackedTuples < 1 || maximumTrackedTuples > MaximumTrackedTuples)
            throw new ArgumentOutOfRangeException(nameof(maximumTrackedTuples));
        _maximumTrackedTuples = maximumTrackedTuples;
    }

    public int TrackedTuples => _tracked.Count;

    public TagList CreateTags(string? routeId, string? clusterId, string? destinationId, string statusClass)
    {
        var route = SafeId(routeId) ? routeId! : "_other";
        var cluster = SafeId(clusterId) ? clusterId! : "_other";
        var destination = SafeId(destinationId) ? destinationId! : "_other";
        var key = string.Concat(route, "\0", cluster, "\0", destination);
        if (!_tracked.ContainsKey(key) && !_saturated)
        {
            lock (_registrationLock)
            {
                if (!_tracked.ContainsKey(key))
                {
                    if (_tracked.Count < _maximumTrackedTuples)
                        _tracked.TryAdd(key, 0);
                    else
                    {
                        _saturated = true;
                        route = cluster = destination = "_other";
                    }
                }
            }
        }
        else if (!_tracked.ContainsKey(key))
        {
            route = cluster = destination = "_other";
        }

        return new TagList
        {
            { "http.response.status_class", statusClass },
            { "gateway.route.id", route },
            { "gateway.cluster.id", cluster },
            { "gateway.destination.id", destination }
        };
    }

    private static bool SafeId(string? value) => value is { Length: > 0 and <= 80 } &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-');
}

/// <summary>Keep client identifiers, request paths and secrets out of OTLP spans.</summary>
internal sealed class GatewayTelemetryPrivacyProcessor : BaseProcessor<Activity>
{
    // Deny by default: instrumentation upgrades and custom enrichment may
    // introduce additional request headers, tenant identifiers or raw URLs.
    // Preserve only explicit, bounded operational attributes.
    public override void OnEnd(Activity data)
    {
        foreach (var tag in data.TagObjects.ToArray())
            if (!IsAllowed(tag.Key, tag.Value))
                data.SetTag(tag.Key, null);
        NormalizeAspNetCoreDisplayName(data);
        base.OnEnd(data);
    }

    private static bool IsAllowed(string key, object? value) => key switch
    {
        "gateway.route.id" or "gateway.cluster.id" or "gateway.destination.id" =>
            value is string id && id.Length is > 0 and <= 80 &&
            id.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-'),
        "http.request.method" => value is string method && IsKnownMethod(method),
        "http.response.status_code" => value is int status && status is >= 100 and <= 599
            || value is long longStatus && longStatus is >= 100 and <= 599,
        "http.route" => value is string route && IsSafeRouteTemplate(route),
        "url.scheme" => value is "http" or "https",
        "network.protocol.version" => value is "1.0" or "1.1" or "2" or "2.0" or "3" or "3.0",
        "error.type" => value is string error && error.Length is > 0 and <= 80 &&
            error.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.'),
        _ => false
    };

    private static bool IsKnownMethod(string method) => method is
        "GET" or "HEAD" or "POST" or "PUT" or "DELETE" or "CONNECT" or
        "OPTIONS" or "TRACE" or "PATCH" or "_OTHER";

    private static void NormalizeAspNetCoreDisplayName(Activity activity)
    {
        if (!string.Equals(activity.Source.Name, "Microsoft.AspNetCore", StringComparison.Ordinal))
            return;

        var method = activity.GetTagItem("http.request.method") as string;
        if (method is null || !IsKnownMethod(method) || method == "_OTHER")
            method = null;

        var route = activity.GetTagItem("http.route") as string;
        if (IsSafeRouteTemplate(route))
        {
            activity.DisplayName = $"{method ?? "HTTP"} {route}";
            return;
        }

        activity.SetTag("http.route", null);
        activity.DisplayName = method is null ? "HTTP request" : $"HTTP {method}";
    }

    private static bool IsSafeRouteTemplate(string? route)
    {
        if (route is not { Length: > 0 and <= 256 } || route[0] != '/') return false;
        var insideParameter = false;
        foreach (var character in route)
        {
            if (character == '{')
            {
                if (insideParameter) return false;
                insideParameter = true;
                continue;
            }
            if (character == '}')
            {
                if (!insideParameter) return false;
                insideParameter = false;
                continue;
            }
            if (character == '?' && !insideParameter) return false;
            if (!char.IsAsciiLetterOrDigit(character) &&
                character is not ('/' or '_' or '-' or '.' or ':' or '*' or '?'))
                return false;
        }
        return !insideParameter;
    }
}
