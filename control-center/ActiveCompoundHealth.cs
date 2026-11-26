using System.Net;
using System.Net.Sockets;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

/// <summary>Separate opt-in active health configuration. TCP is always required;
/// AND/OR combines the two HTTP readiness outcomes, never bypasses HTTP or TLS.</summary>
public sealed record ActiveCompoundSettings(string Mode, string SecondaryPath)
{
    public const string ModeKey = "ADC.Health.CompoundMode";
    public const string PathKey = "ADC.Health.SecondaryPath";
    internal static readonly HttpRequestOptionsKey<ActiveCompoundSettings> ProbeKey = new("GatewayCore.ActiveCompoundProbe");

    public static bool TryRead(IReadOnlyDictionary<string,string>? metadata, out ActiveCompoundSettings? settings)
    {
        settings = null;
        if (metadata is null) return true;
        if (!metadata.TryGetValue(ModeKey, out var mode)) return !metadata.ContainsKey(PathKey);
        if (mode is not ("AND" or "OR") || !metadata.TryGetValue(PathKey, out var path) ||
            !CompoundProbeSettings.ValidPath(path)) return false;
        settings = new(mode, path);
        return true;
    }

    public static bool ValidateDraft(JsonObject cluster)
    {
        if (cluster["Metadata"] is not JsonObject metadata) return true;
        if (!metadata.ContainsKey(ModeKey)) return !metadata.ContainsKey(PathKey);
        if (metadata[ModeKey] is not JsonValue mode || !mode.TryGetValue<string>(out var modeText) ||
            metadata[PathKey] is not JsonValue path || !path.TryGetValue<string>(out var pathText) ||
            modeText is null || pathText is null ||
            !TryRead(new Dictionary<string,string> { [ModeKey] = modeText, [PathKey] = pathText }, out var settings) ||
            settings is null) return false;
        var active = (cluster["HealthCheck"] as JsonObject)?["Active"] as JsonObject;
        if (active?["Enabled"] is not JsonValue enabled || !enabled.TryGetValue<bool>(out var on) || !on ||
            active["Path"] is not JsonValue primary || !primary.TryGetValue<string>(out var primaryPath) ||
            !CompoundProbeSettings.ValidPath(primaryPath) || primaryPath == settings.SecondaryPath ||
            cluster["HttpClient"]?["WebProxy"] is not null ||
            cluster["HealthCheck"]?["AvailableDestinationsPolicy"]?.ToString() != "HealthyAndUnknown")
            return false;
        return cluster["Destinations"] is JsonObject destinations &&
            destinations.All(x => x.Value is JsonObject d && d["Health"] is null);
    }
}

public sealed class ActiveCompoundConfigFilter : IProxyConfigFilter
{
    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel)
    {
        if (!ActiveCompoundSettings.TryRead(cluster.Metadata, out var settings) ||
            (settings is not null &&
             (cluster.HealthCheck?.Active?.Enabled != true ||
              !CompoundProbeSettings.ValidPath(cluster.HealthCheck.Active.Path) ||
              cluster.HealthCheck.Active.Path == settings.SecondaryPath ||
              cluster.HealthCheck.AvailableDestinationsPolicy != "HealthyAndUnknown" ||
              cluster.HttpClient?.WebProxy is not null ||
              (cluster.Destinations?.Values.Any(d => !string.IsNullOrEmpty(d.Health)) ?? false))))
            throw new InvalidOperationException("Invalid active compound health configuration.");
        return ValueTask.FromResult(cluster);
    }

    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel) =>
        ValueTask.FromResult(route);
}

/// <summary>Preserve YARP's existing probe creation; only internal request
/// options distinguish health probes from arbitrary client traffic.</summary>
public sealed class CompoundProbingRequestFactory(IProbingRequestFactory inner) : IProbingRequestFactory
{
    public HttpRequestMessage CreateRequest(ClusterModel cluster, DestinationModel destination)
    {
        var request = inner.CreateRequest(cluster, destination);
        if (!ActiveCompoundSettings.TryRead(cluster.Config.Metadata, out var settings))
        {
            request.Dispose();
            throw new InvalidOperationException("Invalid active compound health settings.");
        }
        if (settings is not null) request.Options.Set(ActiveCompoundSettings.ProbeKey, settings);
        return request;
    }

    public static void Register(IServiceCollection services)
    {
        var original = services.Last(x => x.ServiceType == typeof(IProbingRequestFactory));
        services.Remove(original);
        services.AddSingleton<IProbingRequestFactory>(sp =>
        {
            var implementation = original.ImplementationInstance ?? original.ImplementationFactory?.Invoke(sp) ??
                ActivatorUtilities.CreateInstance(sp, original.ImplementationType!);
            return new CompoundProbingRequestFactory((IProbingRequestFactory)implementation);
        });
    }
}

public sealed class CompoundForwarderFactory(ILogger<ForwarderHttpClientFactory> logger) : ForwarderHttpClientFactory(logger)
{
    protected override bool CanReuseOldClient(ForwarderHttpClientContext context) =>
        base.CanReuseOldClient(context) && MetadataEqual(context.OldMetadata, context.NewMetadata);

    private static bool MetadataEqual(IReadOnlyDictionary<string,string>? a, IReadOnlyDictionary<string,string>? b) =>
        ReferenceEquals(a,b) || (a is not null && b is not null && a.Count == b.Count &&
            a.All(x => b.TryGetValue(x.Key, out var value) && value == x.Value));

    protected override void ConfigureHandler(ForwarderHttpClientContext context, SocketsHttpHandler handler)
    {
        base.ConfigureHandler(context, handler);
        BackendMutualTls.Configure(context, handler);
    }

    protected override HttpMessageHandler WrapHandler(ForwarderHttpClientContext context, HttpMessageHandler handler) =>
        ActiveCompoundSettings.TryRead(context.NewMetadata, out var settings) && settings is not null
            ? new CompoundProbeHandler(handler) : handler;
}

public sealed class CompoundProbeHandler(HttpMessageHandler inner) : DelegatingHandler(inner)
{
    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token)
    {
        // All ordinary requests retain exactly the original forwarding behavior.
        if (!request.Options.TryGetValue(ActiveCompoundSettings.ProbeKey, out var settings))
            return await base.SendAsync(request, token);

        var primary = request.RequestUri;
        if (primary is null || request.Method != HttpMethod.Get ||
            !CompoundProbeSettings.TryTarget(primary, settings.SecondaryPath, out var secondary))
            return new HttpResponseMessage(HttpStatusCode.ServiceUnavailable);

        using var additional = new HttpRequestMessage(HttpMethod.Get, secondary)
        {
            Version = request.Version,
            VersionPolicy = request.VersionPolicy
        };
        additional.Headers.Host = request.Headers.Host;
        var tcpTask = TcpAsync(primary, token);
        var primaryTask = HttpAsync(request, token);
        var secondaryTask = HttpAsync(additional, token);
        var outcomes = await Task.WhenAll(tcpTask, primaryTask, secondaryTask);
        token.ThrowIfCancellationRequested();
        var ready = outcomes[0] && (settings.Mode == "AND"
            ? outcomes[1] && outcomes[2] : settings.Mode == "OR" && (outcomes[1] || outcomes[2]));
        // This status is consumed exclusively by the native active-health policy.
        return new HttpResponseMessage(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable);
    }

    private async Task<bool> HttpAsync(HttpRequestMessage request, CancellationToken token)
    {
        try
        {
            using var response = await base.SendAsync(request, token);
            return response.IsSuccessStatusCode;
        }
        catch (HttpRequestException) { return false; }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return false; }
    }

    private static async Task<bool> TcpAsync(Uri primary, CancellationToken token)
    {
        try
        {
            using var socket = new TcpClient();
            await socket.ConnectAsync(primary.IdnHost, primary.Port, token);
            return true;
        }
        catch (SocketException) { return false; }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return false; }
    }
}
