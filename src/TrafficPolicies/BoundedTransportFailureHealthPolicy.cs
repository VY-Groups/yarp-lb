using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using Yarp.ReverseProxy.Forwarder;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

/// <summary>
/// Opt-in passive transport ejection policy with an absolute per-cluster
/// reservation budget. Never ejects due to ordinary upstream HTTP 5xx or a
/// client cancel. Does NOT retry, duplicate or replay any request.
/// </summary>
public sealed class BoundedTransportFailureHealthPolicy : IPassiveHealthCheckPolicy
{
    public const string PolicyName = "BoundedTransportFailure";
    private sealed class ClusterBudget { public readonly object Gate = new(); public readonly Dictionary<string,long> Until = new(); }
    private readonly ConditionalWeakTable<ClusterState,ClusterBudget> budgets = new();
    private readonly IDestinationHealthUpdater updater;

    public BoundedTransportFailureHealthPolicy(IDestinationHealthUpdater updater) => this.updater=updater;
    public string Name => PolicyName;

    public void RequestProxied(HttpContext context, ClusterState cluster, DestinationState destination)
    {
        if (context.RequestAborted.IsCancellationRequested) return;
        var error=context.Features.Get<IForwarderErrorFeature>()?.Error;
        if (error is not (ForwarderError.Request or ForwarderError.RequestTimedOut or
            ForwarderError.RequestBodyDestination or ForwarderError.ResponseBodyDestination))
            return;
        var metadata=cluster.Model.Config.Metadata;
        var configuredPercent=50;
        var minimumRemaining=1;
        if(metadata is not null)
        {
            if(metadata.TryGetValue("BoundedTransportFailure.MaxEjectedPercent",out var rawPercent) &&
               (!int.TryParse(rawPercent,out configuredPercent) || configuredPercent is < 1 or > 100))
                return; // invalid config must not cause unlimited ejection
            if(metadata.TryGetValue("BoundedTransportFailure.MinHealthyRemaining",out var rawMin) &&
               (!int.TryParse(rawMin,out minimumRemaining) || minimumRemaining is < 0 or > 1024))
                return;
        }
        var total = cluster.Model.Config.Destinations.Count;
        var cap=EjectionBudget.Allowed(total,configuredPercent,minimumRemaining);
        if (cap<=0) return;
        var cooldown = cluster.Model.Config.HealthCheck?.Passive?.ReactivationPeriod ??
            TimeSpan.FromSeconds(2);
        if (cooldown <= TimeSpan.Zero || cooldown > TimeSpan.FromMinutes(10)) return;
        var now=Stopwatch.GetTimestamp();
        var next=now+Math.Max(1,(long)(cooldown.TotalSeconds*Stopwatch.Frequency));
        var scope=budgets.GetValue(cluster,_=>new ClusterBudget());
        lock(scope.Gate)
        {
            foreach(var expired in scope.Until.Where(x=>x.Value<=now).Select(x=>x.Key).ToArray())
                scope.Until.Remove(expired);
            if(scope.Until.ContainsKey(destination.DestinationId) || scope.Until.Count>=cap)
                return;
            // Claim the only available ejection slot atomically across requests.
            scope.Until.Add(destination.DestinationId,next);
        }
        updater.SetPassive(cluster,destination,DestinationHealth.Unhealthy,cooldown);
    }
}

/// <summary>Pure ejection ceiling; safety-critical defaults preserve at least
/// one candidate until active health can independently fail the whole pool.</summary>
public static class EjectionBudget
{
    public static int Allowed(int total,int percent,int minHealthyRemaining)
    {
        if(total<0 || percent is < 1 or > 100 || minHealthyRemaining<0)
            throw new ArgumentOutOfRangeException(nameof(total));
        var limit=Math.Min(total-minHealthyRemaining,(int)((long)total*percent/100));
        return Math.Max(0,limit);
    }
}
