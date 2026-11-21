using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Builder;
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
public static partial class GatewayOpenTelemetry
{
    // Typed logging removes the params object[] and eager boxing from the
    // common call site while preserving the existing structured access log.
    [LoggerMessage(EventId = 0, Level = LogLevel.Information,
        Message = "GATEWAY_ACCESS timestampUtc={TimestampUtc:o} clientIp={ClientIp} clientIpSource={ClientIpSource} method={Method} routeId={RouteId} statusCode={StatusCode} durationMs={DurationMs}")]
    public static partial void LogAccess(ILogger logger, DateTimeOffset timestampUtc,
        string clientIp, string clientIpSource, string method, string routeId,
        int statusCode, double durationMs);

    public const string ActivitySourceName = "GatewayCore.ControlCenter";
    public static readonly ActivitySource ActivitySource = new(ActivitySourceName, "0.1");
    private static readonly Meter Meter = new(ActivitySourceName, "0.1");
    private static readonly Counter<long> ProxyRequests = Meter.CreateCounter<long>("gateway.proxy.requests");
    private static readonly Histogram<double> ProxyDuration = Meter.CreateHistogram<double>("gateway.proxy.request.duration", "ms");
    private static readonly Counter<long> LocalProxyRejections = Meter.CreateCounter<long>("gateway.proxy.local_rejections");
    private static readonly GatewayTelemetryDimensionBudget DimensionBudget = new();
    private static readonly object LocalRejectionItemKey = new();

    internal static void UseProxyTelemetry(IApplicationBuilder pipeline, Action<HttpContext, double>? afterRequest = null)
    {
        pipeline.Use(async (context, next) =>
        {
            var started = Stopwatch.GetTimestamp();
            var activity = StartProxyActivity(context);
            try
            {
                await next();
            }
            catch (Exception exception)
            {
                RecordProxyException(activity, exception);
                throw;
            }
            finally
            {
                var elapsedMs = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
                var feature = context.Features.Get<IReverseProxyFeature>();
                var destination = feature?.ProxiedDestination;
                CompleteProxyActivity(activity, context, destination?.DestinationId);
                RecordProxyResult(context, elapsedMs,
                    feature?.Route.Config.RouteId,
                    feature?.Cluster.Config.ClusterId,
                    destination?.DestinationId);
                afterRequest?.Invoke(context, elapsedMs);
            }
        });
    }

    internal static void UseShutdownFence(IApplicationBuilder pipeline, CancellationToken stopping)
    {
        pipeline.Use(async (context, next) =>
        {
            if (stopping.IsCancellationRequested)
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                MarkLocalRejection(context, "gateway_shutdown");
                return;
            }
            await next();
        });
    }

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
        activity.Stop();
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

        // The private context marker is written by GatewayCore's local rejection
        // middleware. Do not derive metric labels from response headers: an upstream
        // application can return arbitrary headers.
        if (context.Items.TryGetValue(LocalRejectionItemKey, out var markedReason))
        {
            context.Items.Remove(LocalRejectionItemKey);
            if (markedReason is string rejectionValue &&
                TryGetLocalRejectionReason(rejectionValue, out var rejectionReason))
                LocalProxyRejections.Add(1, new TagList
                {
                    { "gateway.proxy.rejection.reason", rejectionReason }
                });
        }
    }

    internal static void MarkLocalRejection(HttpContext context, string reason)
    {
        _ = TryGetLocalRejectionReason(reason, out var boundedReason);
        context.Items[LocalRejectionItemKey] = boundedReason;
        context.Response.Headers["X-GatewayCore-Rejection"] = boundedReason;
    }

    internal static bool TryGetLocalRejectionReason(string? value, out string reason)
    {
        if (value is null)
        {
            reason = string.Empty;
            return false;
        }

        reason = value switch
        {
            "gateway_shutdown" => "gateway_shutdown",
            "admission_destination_unresolved" => "admission_destination_unresolved",
            "admission_policy_conflict" => "admission_policy_conflict",
            "invalid_admission_config" => "invalid_admission_config",
            "admission_configuration_unavailable" => "admission_configuration_unavailable",
            "destination_queue_timeout" => "destination_queue_timeout",
            "destination_queue_full" => "destination_queue_full",
            "destination_unavailable_after_queue" => "destination_unavailable_after_queue",
            _ => "other"
        };
        return true;
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

    internal static bool IsSafeTelemetryId(string? value)
    {
        if (value is not { Length: > 0 and <= 80 }) return false;
        // Use a full ASCII scan instead of Regex and LINQ on sampled spans.
        // The old '
}

/// <summary>
/// Caps distinct route/cluster/destination tuples emitted to OTLP. Configured IDs
/// are validated before becoming metric attributes; overflow is one fixed tuple.
/// </summary>
internal sealed class GatewayTelemetryDimensionBudget
{
    public const int MaximumTotalTuples = 4096;
    private readonly int _maximumNamedTuples;
    // These keys live on the per-request metrics path. Keep them as value tuples
    // so an already-registered route/cluster/destination doesn't allocate a
    // composite string for every measurement.
    private readonly ConcurrentDictionary<(string Route, string Cluster, string Destination), byte> _tracked = new();
    private readonly object _registrationLock = new();
    private volatile bool _saturated;

    public GatewayTelemetryDimensionBudget(int maximumTotalTuples = MaximumTotalTuples)
    {
        if (maximumTotalTuples < 2 || maximumTotalTuples > MaximumTotalTuples)
            throw new ArgumentOutOfRangeException(nameof(maximumTotalTuples));
        // Reserve one series tuple for the fixed overflow dimensions.
        _maximumNamedTuples = maximumTotalTuples - 1;
    }

    public int TrackedTuples => _tracked.Count;

    public TagList CreateTags(string? routeId, string? clusterId, string? destinationId, string statusClass)
    {
        var route = SafeId(routeId) ? routeId! : "_other";
        var cluster = SafeId(clusterId) ? clusterId! : "_other";
        var destination = SafeId(destinationId) ? destinationId! : "_other";
        var key = (Route: route, Cluster: cluster, Destination: destination);
        if (!_tracked.ContainsKey(key) && !_saturated)
        {
            lock (_registrationLock)
            {
                if (!_tracked.ContainsKey(key))
                {
                    if (_tracked.Count < _maximumNamedTuples)
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

    private static bool SafeId(string? value)
    {
        if (value is not { Length: > 0 and <= 80 }) return false;
        // Avoid LINQ over string here: its interface enumerator can allocate on
        // every proxied request when metric attributes are recorded.
        foreach (var character in value)
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('_' or '-'))
                return false;
        return true;
    }
}

/// <summary>Keep client identifiers, request paths and secrets out of OTLP spans.</summary>
internal sealed class GatewayTelemetryPrivacyProcessor : BaseProcessor<Activity>
{
    // Deny by default: instrumentation upgrades and custom enrichment may
    // introduce additional request headers, tenant identifiers or raw URLs.
    // Preserve only explicit, bounded operational attributes.
    public override void OnEnd(Activity data)
    {
        // Activity tags cannot be removed while enumerating its live tag
        // collection. Collect ONLY rejected tag keys into a reusable pooled
        // buffer, then remove them after enumeration. This replaces the old
        // per-exported-span KeyValuePair[] materialization while preserving
        // deny-by-default semantics and all attribute allowlist checks.
        string[]? rejectedKeys = null;
        var rejectedCount = 0;
        try
        {
            foreach (var tag in data.TagObjects)
            {
                if (IsAllowed(tag.Key, tag.Value)) continue;
                rejectedKeys ??= ArrayPool<string>.Shared.Rent(16);
                if (rejectedCount == rejectedKeys.Length)
                {
                    var expanded = ArrayPool<string>.Shared.Rent(checked(rejectedKeys.Length * 2));
                    Array.Copy(rejectedKeys, expanded, rejectedCount);
                    ArrayPool<string>.Shared.Return(rejectedKeys, clearArray: true);
                    rejectedKeys = expanded;
                }
                rejectedKeys[rejectedCount++] = tag.Key;
            }
            for (var index = 0; index < rejectedCount; index++)
                data.SetTag(rejectedKeys![index], null);
        }
        finally
        {
            // Never allow a process-wide pooled buffer to retain keys from
            // sensitive, untrusted trace enrichment after a span is exported.
            if (rejectedKeys is not null)
                ArrayPool<string>.Shared.Return(rejectedKeys, clearArray: true);
        }
        NormalizeAspNetCoreDisplayName(data);
        base.OnEnd(data);
    }

    private static bool IsAllowed(string key, object? value) => key switch
    {
        "gateway.route.id" or "gateway.cluster.id" or "gateway.destination.id" =>
            value is string id && GatewayOpenTelemetry.IsSafeTelemetryId(id),
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
 regex anchor accepted a trailing newline.
        foreach (var character in value)
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('_' or '-'))
                return false;
        return true;
    }

    private static void SetBoundedId(Activity? activity, string key, string? value)
    {
        if (activity is not null && IsSafeTelemetryId(value))
            activity.SetTag(key, value);
    }
}

/// <summary>
/// Caps distinct route/cluster/destination tuples emitted to OTLP. Configured IDs
/// are validated before becoming metric attributes; overflow is one fixed tuple.
/// </summary>
internal sealed class GatewayTelemetryDimensionBudget
{
    public const int MaximumTotalTuples = 4096;
    private readonly int _maximumNamedTuples;
    // These keys live on the per-request metrics path. Keep them as value tuples
    // so an already-registered route/cluster/destination doesn't allocate a
    // composite string for every measurement.
    private readonly ConcurrentDictionary<(string Route, string Cluster, string Destination), byte> _tracked = new();
    private readonly object _registrationLock = new();
    private volatile bool _saturated;

    public GatewayTelemetryDimensionBudget(int maximumTotalTuples = MaximumTotalTuples)
    {
        if (maximumTotalTuples < 2 || maximumTotalTuples > MaximumTotalTuples)
            throw new ArgumentOutOfRangeException(nameof(maximumTotalTuples));
        // Reserve one series tuple for the fixed overflow dimensions.
        _maximumNamedTuples = maximumTotalTuples - 1;
    }

    public int TrackedTuples => _tracked.Count;

    public TagList CreateTags(string? routeId, string? clusterId, string? destinationId, string statusClass)
    {
        var route = SafeId(routeId) ? routeId! : "_other";
        var cluster = SafeId(clusterId) ? clusterId! : "_other";
        var destination = SafeId(destinationId) ? destinationId! : "_other";
        var key = (Route: route, Cluster: cluster, Destination: destination);
        if (!_tracked.ContainsKey(key) && !_saturated)
        {
            lock (_registrationLock)
            {
                if (!_tracked.ContainsKey(key))
                {
                    if (_tracked.Count < _maximumNamedTuples)
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

    private static bool SafeId(string? value)
    {
        if (value is not { Length: > 0 and <= 80 }) return false;
        // Avoid LINQ over string here: its interface enumerator can allocate on
        // every proxied request when metric attributes are recorded.
        foreach (var character in value)
            if (!char.IsAsciiLetterOrDigit(character) && character is not ('_' or '-'))
                return false;
        return true;
    }
}

/// <summary>Keep client identifiers, request paths and secrets out of OTLP spans.</summary>
internal sealed class GatewayTelemetryPrivacyProcessor : BaseProcessor<Activity>
{
    // Deny by default: instrumentation upgrades and custom enrichment may
    // introduce additional request headers, tenant identifiers or raw URLs.
    // Preserve only explicit, bounded operational attributes.
    public override void OnEnd(Activity data)
    {
        // Activity tags cannot be removed while enumerating its live tag
        // collection. Collect ONLY rejected tag keys into a reusable pooled
        // buffer, then remove them after enumeration. This replaces the old
        // per-exported-span KeyValuePair[] materialization while preserving
        // deny-by-default semantics and all attribute allowlist checks.
        string[]? rejectedKeys = null;
        var rejectedCount = 0;
        try
        {
            foreach (var tag in data.TagObjects)
            {
                if (IsAllowed(tag.Key, tag.Value)) continue;
                rejectedKeys ??= ArrayPool<string>.Shared.Rent(16);
                if (rejectedCount == rejectedKeys.Length)
                {
                    var expanded = ArrayPool<string>.Shared.Rent(checked(rejectedKeys.Length * 2));
                    Array.Copy(rejectedKeys, expanded, rejectedCount);
                    ArrayPool<string>.Shared.Return(rejectedKeys, clearArray: true);
                    rejectedKeys = expanded;
                }
                rejectedKeys[rejectedCount++] = tag.Key;
            }
            for (var index = 0; index < rejectedCount; index++)
                data.SetTag(rejectedKeys![index], null);
        }
        finally
        {
            // Never allow a process-wide pooled buffer to retain keys from
            // sensitive, untrusted trace enrichment after a span is exported.
            if (rejectedKeys is not null)
                ArrayPool<string>.Shared.Return(rejectedKeys, clearArray: true);
        }
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
