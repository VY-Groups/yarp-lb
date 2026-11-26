using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

/// <summary>Control-plane-only reusable monitor snapshots. No runtime objects or
/// implicit deployment: every assigned snapshot is part of a reviewed draft.</summary>
public static class MonitorProfileRegistry
{
    public const string PayloadKey = "monitorProfiles";
    public const string StorageKey = "AdminMonitorProfiles";
    private static readonly HashSet<string> ActiveKeys = new(StringComparer.Ordinal)
        { "Enabled", "Path", "Interval", "Timeout", "Policy" };
    private static readonly HashSet<string> MetadataKeys = new(StringComparer.Ordinal)
        { "RiseFall.Rise", "RiseFall.Fall", "ConsecutiveFailuresHealthPolicy.Threshold",
          "ADC.Health.CompoundMode", "ADC.Health.SecondaryPath" };

    public static string? Validate(JsonObject payload)
    {
        if (!payload.ContainsKey(PayloadKey)) return null; // legacy clients preserve registry
        if (payload[PayloadKey] is not JsonObject profiles || profiles.Count > 100)
            return "Monitor profiles must be an object containing at most 100 profiles.";
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (id, node) in profiles)
        {
            if (!Regex.IsMatch(id, @"\A[A-Za-z0-9_-]{1,80}\z") || !ids.Add(id) ||
                node is not JsonObject profile || profile.Count != 2 ||
                profile["Active"] is not JsonObject active || active.Count != ActiveKeys.Count ||
                active.Any(x => !ActiveKeys.Contains(x.Key)) ||
                profile["Metadata"] is not JsonObject metadata ||
                metadata.Any(x => !MetadataKeys.Contains(x.Key) || x.Value is not JsonValue v ||
                    !v.TryGetValue<string>(out var value) || value is null))
                return "Invalid monitor profile ID or unsupported profile fields.";
            foreach (var key in ActiveKeys.Where(k => k != "Enabled"))
                if (active[key] is not JsonValue value || !value.TryGetValue<string>(out _))
                    return "Monitor profile active settings must be strings except Enabled.";
            if (active["Path"] is not JsonValue path || !path.TryGetValue<string>(out var pathText) ||
                !CompoundProbeSettings.ValidPath(pathText))
                return "Monitor profile requires a bounded same-origin readiness path.";

            // Reuse the reviewed monitor snapshot contract, including timing,
            // enabled state, policy and threshold bounds, without writing a fake cluster.
            var source = new JsonObject { ["HealthCheck"] = new JsonObject {
                ["Active"] = active.DeepClone(), ["AvailableDestinationsPolicy"] = "HealthyAndUnknown" },
                ["Metadata"] = metadata.DeepClone(), ["Destinations"] = new JsonObject() };
            var target = source.DeepClone().AsObject();
            target["Metadata"]![SharedMonitorContract.SourceKey] = "source";
            var test = new JsonObject { ["source"] = source, ["target"] = target };
            if (SharedMonitorContract.Validate(test) is { } error) return error;
            if (!ActiveCompoundSettings.ValidateDraft(source))
                return "Invalid active compound monitor profile.";
        }
        return null;
    }
}
