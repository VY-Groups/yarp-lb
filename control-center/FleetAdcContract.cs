using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>Shared, deterministic controller/agent contract for the complete
/// reviewed ADC object snapshot. Omitted legacy catalogs cannot erase objects.
/// No unsigned node-local expansion or merge of reviewed values.</summary>
public static class FleetAdcContract
{
    private static readonly (string Payload, string Storage)[] Sections =
    [
        ("disabled", "AdminDisabledDestinations"),
        (MonitorProfileRegistry.PayloadKey, MonitorProfileRegistry.StorageKey),
        (RealServerCatalog.PayloadKey, RealServerCatalog.StorageKey),
        (ServiceGroupCatalog.PayloadKey, ServiceGroupCatalog.StorageKey)
    ];

    public static bool TryBuildApproved(JsonObject payload, JsonObject current, out JsonObject proxy, out string? error)
    {
        proxy = new JsonObject();
        error = "Approved change is missing routes or clusters.";
        if (payload["routes"] is not JsonObject routes || payload["clusters"] is not JsonObject clusters)
            return false;
        proxy["Routes"] = routes.DeepClone();
        proxy["Clusters"] = clusters.DeepClone();
        foreach (var (key, storage) in Sections)
        {
            if (!payload.ContainsKey(key)) continue;
            if (payload[key] is not JsonObject section)
            {
                error = "Invalid approved ADC section: " + key;
                return false;
            }
            proxy[storage] = section.DeepClone();
        }
        error = Validate(proxy, current);
        return error is null;
    }

    public static string? Validate(JsonObject candidate, JsonObject current)
    {
        try
        {
            if (candidate["Routes"] is not JsonObject routes || candidate["Clusters"] is not JsonObject clusters ||
                routes.Count > 100 || clusters.Count > 100)
                return "Invalid signed routes or clusters.";
            var payload = new JsonObject();
            foreach (var (key, storage) in Sections)
            {
                if (!candidate.ContainsKey(storage))
                {
                    if (current.ContainsKey(storage) && current[storage] is not JsonObject { Count: 0 })
                        return "Explicit reviewed ADC section required to replace existing " + storage + ".";
                    continue;
                }
                if (candidate[storage] is not JsonObject section)
                    return "Invalid signed ADC section: " + storage;
                payload[key] = section.DeepClone();
            }
            if (RealServerCatalog.Validate(payload) is { } serverError) return serverError;
            if (MonitorProfileRegistry.Validate(payload) is { } profileError) return profileError;
            // All nonempty objects must be in the signed snapshot; never resolve
            // template references against unsigned previous node state.
            if (ServiceGroupCatalog.Validate(payload, new JsonObject()) is { } groupError) return groupError;
            if (SharedMonitorContract.Validate(clusters) is { } monitorError) return monitorError;
            if (SecureAffinityDraft.Validate(clusters) is { } affinityError) return affinityError;
            foreach (var (_, cluster) in clusters)
                if (cluster is not JsonObject row || !CompoundProbeSettings.TryRead(row, out _) ||
                    !CompoundActiveDraft.Validate(row))
                    return "Invalid signed compound health or diagnostic settings.";
            if (payload["disabled"] is JsonObject disabled)
            {
                if (disabled.Count > 4000) return "Too many disabled destinations.";
                foreach (var (id, node) in disabled)
                {
                    var parts = id.Split("::", StringSplitOptions.None);
                    if (parts.Length != 2 || parts.Any(p => !Regex.IsMatch(p, @"\A[A-Za-z0-9_-]{1,80}\z")) ||
                        !clusters.ContainsKey(parts[0]) || node is not JsonObject destination ||
                        destination["Address"] is not JsonValue value || !value.TryGetValue<string>(out var address) ||
                        !Uri.TryCreate(address, UriKind.Absolute, out var uri) ||
                        uri.Scheme is not ("http" or "https") || string.IsNullOrWhiteSpace(uri.Host) || uri.UserInfo.Length != 0)
                        return "Invalid disabled destination in signed configuration.";
                }
            }
            return null;
        }
        catch (Exception e) when (e is InvalidOperationException or ArgumentException or FormatException)
        { return "Invalid signed ADC configuration structure."; }
    }
}
