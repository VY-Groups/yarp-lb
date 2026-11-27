using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Model;

/// <summary>Virtual service binding is the receiving local socket, never Host
/// or forwarded headers. Unbound legacy routes cannot leak onto virtual sockets.</summary>
public static class VirtualServiceBinding
{
    public const string Key = "ADC.VirtualServer.Id";
    public static bool ValidId(string? id) =>
        id is not null && Regex.IsMatch(id, @"\A[A-Za-z0-9_-]{1,64}\z");
    public static bool Permitted(IReadOnlyDictionary<string,string>? metadata, string? socketId) =>
        metadata?.TryGetValue(Key, out var required) == true
            ? ValidId(required) && string.Equals(required, socketId, StringComparison.Ordinal)
            : socketId is null;
}

public sealed class VirtualServiceMatcherPolicy(GatewayListenerIsolation? listeners)
    : MatcherPolicy, IEndpointSelectorPolicy
{
    // After host/method/header policies, before final endpoint selection.
    public override int Order => -5;
    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints) =>
        endpoints.Any(e => e.Metadata.GetMetadata<RouteModel>() is not null);
    public Task ApplyAsync(HttpContext context, CandidateSet candidates)
    {
        var id = listeners?.VirtualServiceId(context);
        for (int i = 0; i < candidates.Count; i++)
        {
            if (!candidates.IsValidCandidate(i)) continue;
            var route = candidates[i].Endpoint.Metadata.GetMetadata<RouteModel>();
            if (route is not null && !VirtualServiceBinding.Permitted(route.Config.Metadata, id))
                candidates.SetValidity(i, false);
        }
        return Task.CompletedTask;
    }
}

public sealed class VirtualServiceRouteFilter(GatewayListenerIsolation? listeners) : IProxyConfigFilter
{
    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel) =>
        ValueTask.FromResult(cluster);
    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel)
    {
        if (route.Metadata?.TryGetValue(VirtualServiceBinding.Key, out var id) == true &&
            (!VirtualServiceBinding.ValidId(id) || listeners?.HasVirtualService(id) != true))
            throw new InvalidOperationException("Route references a virtual service not provisioned on this gateway.");
        return ValueTask.FromResult(route);
    }
}
