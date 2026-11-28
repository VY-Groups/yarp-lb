using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>Named service-group templates use explicit real-server and monitor
/// references. Runtime clusters are independently reviewed materialized copies.</summary>
public static class ServiceGroupCatalog
{
    public const string PayloadKey = "serviceGroups";
    public const string StorageKey = "AdminServiceGroups";
    private static readonly HashSet<string> Policies = new(StringComparer.Ordinal)
        { "RoundRobin", "WeightedRoundRobin", "WeightedRandom", "LeastRequests",
          "WeightedLeastRequests", "FastestResponse", "SourceIpHash", "PrimaryBackup" };

    public static string? Validate(JsonObject payload, JsonObject current)
    {
        var groups = payload.ContainsKey(PayloadKey) ? payload[PayloadKey] :
            current[StorageKey] ?? new JsonObject();
        if (groups is not JsonObject templates || templates.Count > 100)
            return "Service-group catalog must contain at most 100 templates.";
        var servers = (payload.ContainsKey(RealServerCatalog.PayloadKey) ?
            payload[RealServerCatalog.PayloadKey] : current[RealServerCatalog.StorageKey]) as JsonObject;
        var profiles = (payload.ContainsKey(MonitorProfileRegistry.PayloadKey) ?
            payload[MonitorProfileRegistry.PayloadKey] : current[MonitorProfileRegistry.StorageKey]) as JsonObject;
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, node) in templates)
        {
            if (!Regex.IsMatch(id, @"\A[A-Za-z0-9_-]{1,80}\z") || !ids.Add(id) ||
                node is not JsonObject template || template.Count != 3 ||
                template["Policy"] is not JsonValue policyValue ||
                !policyValue.TryGetValue<string>(out var policy) || policy is null || !Policies.Contains(policy) ||
                template["MonitorProfile"] is not JsonValue profileValue ||
                !profileValue.TryGetValue<string>(out var profile) || profile is null ||
                (profile.Length != 0 && (profiles is null || !profiles.ContainsKey(profile))) ||
                template["Members"] is not JsonObject members || members.Count is < 1 or > 40)
                return "Invalid service-group template, policy, monitor reference or member count.";
            if (policy == "PrimaryBackup" && profile.Length == 0)
                return "PrimaryBackup template requires a monitor profile.";
            var primary = 0;
            foreach (var (serverId, memberNode) in members)
            {
                if (servers is null || !servers.ContainsKey(serverId) ||
                    memberNode is not JsonObject member || member.Count != 2 ||
                    member["Weight"] is not JsonValue weightValue ||
                    !weightValue.TryGetValue<string>(out var weight) ||
                    !int.TryParse(weight, System.Globalization.NumberStyles.None,
                        System.Globalization.CultureInfo.InvariantCulture, out var number) ||
                    number is < 1 or > 100 ||
                    member["TrafficRole"] is not JsonValue roleValue ||
                    !roleValue.TryGetValue<string>(out var role) || role is not ("primary" or "backup"))
                    return "Service-group member requires an existing server, weight 1..100 and valid role.";
                if (role == "primary") primary++;
            }
            if (policy == "PrimaryBackup" && primary == 0)
                return "PrimaryBackup template needs a primary member.";
        }
        return null;
    }

    // A linked group is still a materialized runtime cluster. The catalog never
    // rewrites live traffic: every dependent snapshot must be in the same draft.
    public const string LinkKey = "ADC.ServiceGroupTemplate";
    private static readonly string[] MonitorKeys =
        ["RiseFall.Rise", "RiseFall.Fall", "ConsecutiveFailuresHealthPolicy.Threshold",
         "ADC.Health.CompoundMode", "ADC.Health.SecondaryPath"];

    public static string? ValidateLinked(JsonObject clusters, JsonObject disabled,
        JsonObject payload, JsonObject current)
    {
        var groups = (payload.ContainsKey(PayloadKey) ? payload[PayloadKey] : current[StorageKey]) as JsonObject;
        var servers = (payload.ContainsKey(RealServerCatalog.PayloadKey) ? payload[RealServerCatalog.PayloadKey] :
            current[RealServerCatalog.StorageKey]) as JsonObject;
        var profiles = (payload.ContainsKey(MonitorProfileRegistry.PayloadKey) ? payload[MonitorProfileRegistry.PayloadKey] :
            current[MonitorProfileRegistry.StorageKey]) as JsonObject;
        foreach (var (clusterId, node) in clusters)
        {
            if (node is not JsonObject cluster || cluster["Metadata"] is not JsonObject metadata ||
                !metadata.ContainsKey(LinkKey)) continue;
            var error = "Linked service group " + clusterId + " must match its catalog template; synchronize or explicitly unlink in the reviewed draft.";
            if (metadata[LinkKey] is not JsonValue link || !link.TryGetValue<string>(out var id) ||
                id is null || groups?[id] is not JsonObject template ||
                template["Members"] is not JsonObject members ||
                cluster["Destinations"] is not JsonObject destinations ||
                !JsonNode.DeepEquals(template["Policy"], cluster["LoadBalancingPolicy"]) ||
                metadata.ContainsKey(SharedMonitorContract.SourceKey)) return error;
            var observed = new Dictionary<string, JsonNode?>(StringComparer.Ordinal);
            foreach (var (key, value) in destinations)
                if (!observed.TryAdd(key, value)) return error;
            var prefix = clusterId + "::";
            foreach (var (key, value) in disabled)
                if (key.StartsWith(prefix, StringComparison.Ordinal) &&
                    !observed.TryAdd(key[prefix.Length..], value)) return error;
            if (observed.Count != members.Count) return error;
            foreach (var (serverId, member) in members)
            {
                if (!observed.TryGetValue(serverId, out var destination) ||
                    destination is not JsonObject dest || servers?[serverId] is not JsonObject server ||
                    member is not JsonObject spec || dest["Metadata"] is not JsonObject dm ||
                    !JsonNode.DeepEquals(dest["Address"], server["Address"]) ||
                    !JsonNode.DeepEquals(dm["Weight"], spec["Weight"]) ||
                    !JsonNode.DeepEquals(dm["TrafficRole"], spec["TrafficRole"])) return error;
            }
            var profileId = template["MonitorProfile"]?.GetValue<string>();
            var active = (cluster["HealthCheck"] as JsonObject)?["Active"];
            if (string.IsNullOrEmpty(profileId))
            {
                if (active is not null || MonitorKeys.Any(metadata.ContainsKey)) return error;
            }
            else
            {
                if (profiles?[profileId] is not JsonObject profile ||
                    !JsonNode.DeepEquals(active, profile["Active"]) ||
                    MonitorKeys.Any(key => !JsonNode.DeepEquals(metadata[key], profile["Metadata"]?[key])))
                    return error;
            }
        }
        return null;
    }
}
