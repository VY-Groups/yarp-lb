using System.Text.Json.Nodes;
using System.Globalization;
using System.Text.RegularExpressions;

/// <summary>Persisted, one-hop HTTP monitor references. Every linked cluster
/// carries an independently reviewed runtime snapshot, identical to its owner.
/// No silent expansion or mutation after approval.</summary>
public static class SharedMonitorContract
{
    public const string SourceKey = "ADC.HealthMonitorSource";
    private static readonly string[] ThresholdKeys =
        ["RiseFall.Rise", "RiseFall.Fall", "ConsecutiveFailuresHealthPolicy.Threshold"];

    public static string? Validate(JsonObject clusters)
    {
        foreach (var (id, node) in clusters)
        {
            if (node is not JsonObject target) continue;
            if (target["Metadata"] is not JsonObject metadata || !metadata.ContainsKey(SourceKey)) continue;
            if (metadata[SourceKey] is not JsonValue reference ||
                !reference.TryGetValue<string>(out var sourceId) || sourceId is null ||
                !Regex.IsMatch(sourceId, @"\A[A-Za-z0-9_-]{1,80}\z") ||
                string.Equals(id, sourceId, StringComparison.OrdinalIgnoreCase) ||
                clusters[sourceId] is not JsonObject source)
                return "Shared monitor source must be a different existing service group.";
            if (source["Metadata"] is JsonObject sourceMetadata && sourceMetadata.ContainsKey(SourceKey))
                return "Shared monitor sources cannot themselves reference another source.";
            var active = (source["HealthCheck"] as JsonObject)?["Active"] as JsonObject;
            if (active is null || active["Enabled"] is not JsonValue enabled ||
                !enabled.TryGetValue<bool>(out var on) || !on)
                return "Shared monitor source must have an enabled HTTP monitor.";
            if (!ReadDuration(active["Interval"], out var interval) ||
                !ReadDuration(active["Timeout"], out var timeout) || timeout > interval)
                return "Shared monitor interval and timeout must be 1–60 seconds; timeout cannot exceed interval.";
            if (active["Path"] is not JsonValue pathValue || !pathValue.TryGetValue<string>(out var path) ||
                string.IsNullOrEmpty(path) || path.Length > 300 || !path.StartsWith('/') ||
                path.StartsWith("//", StringComparison.Ordinal) || path.Contains('\\') ||
                path.Any(char.IsControl))
                return "Shared monitor must use a bounded relative readiness path.";
            if (active["Policy"]?.ToString() is not ("RiseFall" or "ConsecutiveFailures"))
                return "Unsupported shared monitor policy.";
            if (!JsonNode.DeepEquals(active, (target["HealthCheck"] as JsonObject)?["Active"]))
                return "Linked monitor settings differ from the source. Update all linked groups in one reviewed change.";
            foreach (var key in ThresholdKeys)
            {
                var value = (source["Metadata"] as JsonObject)?[key];
                if (value is not null && (!int.TryParse(value.ToString(), NumberStyles.None,
                    CultureInfo.InvariantCulture, out var n) || n is < 1 or > 10))
                    return "Shared monitor thresholds must be 1–10.";
                if (!JsonNode.DeepEquals(value, metadata[key]))
                    return "Linked monitor thresholds differ from the source.";
            }
        }
        return null;
    }

    private static bool ReadDuration(JsonNode? value, out TimeSpan duration) =>
        TimeSpan.TryParseExact(value?.ToString(), "c", CultureInfo.InvariantCulture, out duration) &&
        duration >= TimeSpan.FromSeconds(1) && duration <= TimeSpan.FromSeconds(60) &&
        duration.Ticks % TimeSpan.TicksPerSecond == 0;
}
