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

    public static bool ValidateDraft(JsonObject cluster) => CompoundActiveDraft.Validate(cluster);
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


/// <summary>Readiness evidence scoped to immutable YARP configuration models.
/// Old probes cannot publish into a new generation, and a newer completed
/// failure cannot be overwritten by an older in-flight success.</summary>
public static class CompoundReadinessEvidence
{
    private sealed class Entry
    {
        internal long Issued, Completed, SuccessfulAt;
        internal bool Ready;
    }

    public sealed class Ticket
    {
        private readonly Action<bool> complete;
        internal Ticket(Action<bool> complete) => this.complete = complete;
        internal void Complete(bool ready) => complete(ready);
    }

    internal static readonly HttpRequestOptionsKey<Ticket> EvidenceKey = new("GatewayCore.CompoundEvidence");
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<ClusterModel,
        System.Runtime.CompilerServices.ConditionalWeakTable<DestinationModel, Entry>> Generations = new();

    public static Ticket Begin(ClusterModel cluster, DestinationModel destination)
    {
        var destinations = Generations.GetValue(cluster, static _ => new());
        var entry = destinations.GetValue(destination, static _ => new Entry());
        long sequence;
        lock (entry) sequence = ++entry.Issued;
        return new Ticket(ready =>
        {
            lock (entry)
            {
                if (sequence <= entry.Completed) return;
                entry.Completed = sequence;
                entry.Ready = ready;
                entry.SuccessfulAt = ready ? System.Diagnostics.Stopwatch.GetTimestamp() : 0;
            }
        });
    }

    public static bool IsReady(ClusterModel cluster, DestinationModel destination)
    {
        if (!Generations.TryGetValue(cluster, out var destinations) ||
            !destinations.TryGetValue(destination, out var entry)) return false;
        var active = cluster.Config.HealthCheck?.Active;
        var interval = active?.Interval ?? TimeSpan.FromSeconds(15);
        var timeout = active?.Timeout ?? TimeSpan.FromSeconds(5);
        // Bounded freshness; normal scheduling jitter is tolerated for two cycles.
        var seconds = Math.Clamp(interval.TotalSeconds * 2 + timeout.TotalSeconds, 1, 180);
        lock (entry)
            return entry.Ready && entry.SuccessfulAt != 0 &&
                System.Diagnostics.Stopwatch.GetElapsedTime(entry.SuccessfulAt).TotalSeconds <= seconds;
    }

    public static bool Eligible(ClusterModel cluster, DestinationState destination) =>
        destination.Health.Active == DestinationHealth.Healthy &&
        destination.Health.Passive != DestinationHealth.Unhealthy &&
        IsReady(cluster, destination.Model);
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
        if (settings is not null)
        {
            request.Options.Set(ActiveCompoundSettings.ProbeKey, settings);
            request.Options.Set(CompoundReadinessEvidence.EvidenceKey, CompoundReadinessEvidence.Begin(cluster, destination));
        }
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

        request.Options.TryGetValue(CompoundReadinessEvidence.EvidenceKey, out var evidence);
        var ready = false;
        try
        {
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
        ready = outcomes[0] && (settings.Mode == "AND"
            ? outcomes[1] && outcomes[2] : settings.Mode == "OR" && (outcomes[1] || outcomes[2]));
        // This status is consumed exclusively by the native active-health policy.
        return new HttpResponseMessage(ready ? HttpStatusCode.OK : HttpStatusCode.ServiceUnavailable);
        }
        finally { evidence?.Complete(ready && !token.IsCancellationRequested); }
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
