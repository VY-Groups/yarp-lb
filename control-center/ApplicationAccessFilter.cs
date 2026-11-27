using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Configuration;

public sealed class ApplicationAccessFilter : IProxyConfigFilter
{
    private sealed record Entry(bool Valid, ApplicationAccessPolicy Policy);
    private static readonly ConditionalWeakTable<RouteConfig, Entry> Policies = new();
    private static Entry Get(RouteConfig route) => Policies.GetValue(route, static config =>
    {
        var valid = ApplicationAccessPolicy.TryParse(config.Metadata, out var policy);
        return new(valid, policy);
    });
    public static bool Permits(RouteConfig route, HttpContext context)
    {
        var entry = Get(route);
        return entry.Valid && entry.Policy.Permits(context.Request.IsHttps, context.Connection.RemoteIpAddress);
    }
    public ValueTask<ClusterConfig> ConfigureClusterAsync(ClusterConfig cluster, CancellationToken cancel) =>
        ValueTask.FromResult(cluster);
    public ValueTask<RouteConfig> ConfigureRouteAsync(RouteConfig route, ClusterConfig? cluster, CancellationToken cancel)
    {
        if (!Get(route).Valid) throw new InvalidOperationException("Invalid application access policy.");
        return ValueTask.FromResult(route);
    }
}
