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
    private sealed class ClusterBudget { public readonly object Gate = new(); public readonly Dictionary<string,long> Until = new(); public readonly Dictionary<string,int> FailureStreak = new(); }
    private readonly ConditionalWeakTable<ClusterState,ClusterBudget> budgets = new();
    private readonly IDestinationHealthUpdater updater;

    public BoundedTransportFailureHealthPolicy(IDestinationHealthUpdater updater) => this.updater=updater;
    public string Name => PolicyName;

    public void RequestProxied(HttpContext context, ClusterState cluster, DestinationState destination)
    {
        if (context.RequestAborted.IsCancellationRequested) return;
        var error=context.Features.Get<IForwarderErrorFeature>()?.Error;
        var transportFailure = error is (ForwarderError.Request or ForwarderError.RequestTimedOut or
            ForwarderError.RequestBodyDestination or ForwarderError.ResponseBodyDestination);
        var metadata=cluster.Model.Config.Metadata;
        var configuredPercent=50;
        var minimumRemaining=1;
        var requiredFailures=2;
        if(metadata is not null)
        {
            if(metadata.TryGetValue("BoundedTransportFailure.MaxEjectedPercent",out var rawPercent) &&
               (!int.TryParse(rawPercent,out configuredPercent) || configuredPercent is < 1 or > 100))
                return; // invalid config must not cause unlimited ejection
            if(metadata.TryGetValue("BoundedTransportFailure.MinHealthyRemaining",out var rawMin) &&
               (!int.TryParse(rawMin,out minimumRemaining) || minimumRemaining is < 0 or > 1024))
                return;
            if(metadata.TryGetValue("BoundedTransportFailure.ConsecutiveFailures",out var rawFailures) &&
               (!int.TryParse(rawFailures,out requiredFailures) || requiredFailures is < 1 or > 10))
                return;
        }
        var destinations = cluster.Model.Config.Destinations;
        if (destinations is null) return;
        var total = destinations.Count;
        var cap=EjectionBudget.Allowed(total,configuredPercent,minimumRemaining);
        if (cap<=0) return;
        var cooldown = cluster.Model.Config.HealthCheck?.Passive?.ReactivationPeriod ??
            TimeSpan.FromSeconds(15);
        if (cooldown <= TimeSpan.Zero || cooldown > TimeSpan.FromMinutes(10)) return;
        var now=Stopwatch.GetTimestamp();
        var next=now+Math.Max(1,(long)(cooldown.TotalSeconds*Stopwatch.Frequency));
        var scope=budgets.GetValue(cluster,_=>new ClusterBudget());
        lock(scope.Gate)
        {
            foreach(var expired in scope.Until.Where(x=>x.Value<=now).Select(x=>x.Key).ToArray())
                scope.Until.Remove(expired);
            // A successful/non-transport response ends the consecutive failure streak.
            // Never eject for upstream HTTP 5xx, client abort, or ordinary HTTP response.
            if (!transportFailure)
            {
                scope.FailureStreak.Remove(destination.DestinationId);
                return;
            }
            var id = destination.DestinationId;
            var count = scope.FailureStreak.TryGetValue(id, out var prior) ? prior : 0;
            count = Math.Min(count + 1, requiredFailures);
            scope.FailureStreak[id] = count;
            if (count < requiredFailures || scope.Until.ContainsKey(id) || scope.Until.Count >= cap)
                return;
            // Configured capacity alone is not an availability reserve. A
            // probe timeout at startup can leave both peers actively down;
            // reserving one of them for 15s then strands the other during
            // maintenance even after healthy probes resume.
            var activeEnabled=cluster.Model.Config.HealthCheck?.Active?.Enabled==true;
            bool Eligible(DestinationState peer)=>EjectionBudget.EligibleForReserve(
                activeEnabled,peer.Health.Active==DestinationHealth.Healthy,
                peer.Health.Passive==DestinationHealth.Unhealthy,
                TrafficLifecycle.IsDraining(peer),scope.Until.ContainsKey(peer.DestinationId));
            var alternatives=0;
            var reserved=scope.Until.Count;
            var candidateEligible=false;
            foreach(var peer in cluster.Destinations.Values)
            {
                // Count a still-ejected destination even if its local
                // reservation timer expired before YARP's updater ran.
                if(peer.Health.Passive==DestinationHealth.Unhealthy &&
                    !scope.Until.ContainsKey(peer.DestinationId))reserved++;
                if(ReferenceEquals(peer,destination))candidateEligible=Eligible(peer);
                else if(peer.DestinationId!=id && Eligible(peer))alternatives++;
            }
            if(!EjectionBudget.CanReserve(cap,reserved,alternatives,minimumRemaining,candidateEligible))
            {
                // Suppressed failure streaks must not be replayed later
                // as if they were fresh failures after active recovery.
                scope.FailureStreak.Remove(id);
                return;
            }
            scope.FailureStreak.Remove(id);
            // Claim the slot atomically across concurrent passive requests.
            scope.Until.Add(destination.DestinationId,next);
        }
        updater.SetPassive(cluster,destination,DestinationHealth.Unhealthy,cooldown);
    }
}
