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
}
