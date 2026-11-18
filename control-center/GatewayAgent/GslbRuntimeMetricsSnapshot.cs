using System.Globalization;
using System.Text;
using System.Text.Json;

internal sealed record GslbRuntimeMetricsSnapshot(
    int ConfiguredTargets,
    int QuorumTargets,
    int BelowQuorumTargets,
    int HealthyReports,
    int UnhealthyReports,
    int UnknownReports,
    int StaleOrMissingReports);

internal sealed record GslbAgentReportStatus(string AgentId, DateTimeOffset? LastAcceptedUtc,
    long? LastAcceptedAgeSeconds, int RejectedTotal, int FreshReports, int StaleOrMissingReports);

internal sealed record GslbAgentReportStatusSnapshot(DateTimeOffset CheckedUtc,
    IReadOnlyList<GslbAgentReportStatus> Agents);

internal static class GslbAgentReportStatusParser
{
    private const int MaximumJsonBytes = 16_384;
    private const int MaximumAgents = 64;
    private const int MaximumTargetsPerAgent = 1024;

    public static bool TryParse(string json, out GslbAgentReportStatusSnapshot? snapshot)
    {
        snapshot = null;
        if (Encoding.UTF8.GetByteCount(json) > MaximumJsonBytes) return false;
        try
        {
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 4 });
            var root = document.RootElement;
            if (root.ValueKind != JsonValueKind.Object || root.EnumerateObject().Count() != 3 ||
                !root.TryGetProperty("type", out var type) ||
                type.GetString() != "loopback-gslb-agent-report-status" ||
                !root.TryGetProperty("checkedUtc", out var checkedUtcElement) ||
                !TryUtc(checkedUtcElement, out var checkedUtc) ||
                !root.TryGetProperty("agents", out var agentsElement) ||
                agentsElement.ValueKind != JsonValueKind.Array || agentsElement.GetArrayLength() is < 1 or > MaximumAgents)
                return false;

            var result = new List<GslbAgentReportStatus>(agentsElement.GetArrayLength());
            var ids = new HashSet<string>(StringComparer.Ordinal);
            foreach (var agent in agentsElement.EnumerateArray())
            {
                if (agent.ValueKind != JsonValueKind.Object || agent.EnumerateObject().Count() != 6 ||
                    !agent.TryGetProperty("agentId", out var idElement) || idElement.ValueKind != JsonValueKind.String)
                    return false;
                var id = idElement.GetString();
                if (!ValidAgentId(id) || !ids.Add(id!)) return false;

                if (!agent.TryGetProperty("lastAcceptedUtc", out var acceptedUtcElement) ||
                    !TryNullableUtc(acceptedUtcElement, out var acceptedUtc) ||
                    !agent.TryGetProperty("lastAcceptedAgeSeconds", out var ageElement) ||
                    !TryNullableNonNegativeLong(ageElement, out var ageSeconds) ||
                    !agent.TryGetProperty("rejectedTotal", out var rejectedElement) ||
                    !TryBoundedCounter(rejectedElement, out var rejectedTotal) ||
                    !agent.TryGetProperty("freshReports", out var freshElement) ||
                    !TryBoundedCounter(freshElement, out var freshReports) || freshReports > MaximumTargetsPerAgent ||
                    !agent.TryGetProperty("staleOrMissingReports", out var staleElement) ||
                    !TryBoundedCounter(staleElement, out var staleReports) || staleReports > MaximumTargetsPerAgent ||
                    freshReports + staleReports > MaximumTargetsPerAgent ||
                    ((acceptedUtc is null) != (ageSeconds is null)))
                    return false;

                result.Add(new GslbAgentReportStatus(id!, acceptedUtc, ageSeconds,
                    rejectedTotal, freshReports, staleReports));
            }
            snapshot = new GslbAgentReportStatusSnapshot(checkedUtc, result);
            return true;
        }
        catch (JsonException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (FormatException) { return false; }
    }

    private static bool TryUtc(JsonElement value, out DateTimeOffset result)
    {
        result = default;
        return value.ValueKind == JsonValueKind.String && value.TryGetDateTimeOffset(out result) && result.Offset == TimeSpan.Zero;
    }

    private static bool TryNullableUtc(JsonElement value, out DateTimeOffset? result)
    {
        result = null;
        if (value.ValueKind == JsonValueKind.Null) return true;
        if (!TryUtc(value, out var parsed)) return false;
        result = parsed;
        return true;
    }

    private static bool TryNullableNonNegativeLong(JsonElement value, out long? result)
    {
        result = null;
        if (value.ValueKind == JsonValueKind.Null) return true;
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out var parsed) || parsed < 0)
            return false;
        result = parsed;
        return true;
    }

    private static bool TryBoundedCounter(JsonElement value, out int result)
    {
        result = 0;
        return value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out result) && result >= 0;
    }

    private static bool ValidAgentId(string? id) => id is { Length: >= 1 and <= 64 } &&
        id[0] is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '_' &&
        id.Skip(1).All(character => character is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or
            >= '0' and <= '9' or '_' or '-');
}

internal static class GslbRuntimeMetricsParser
{
    private static readonly string[] Samples =
    [
        "gatewaycore_gslb_report_gated_sites",
        "gatewaycore_gslb_agent_quorum_targets{state=\"quorum\"}",
        "gatewaycore_gslb_agent_quorum_targets{state=\"below_quorum\"}",
        "gatewaycore_gslb_agent_evidence_reports{state=\"healthy\"}",
        "gatewaycore_gslb_agent_evidence_reports{state=\"unhealthy\"}",
        "gatewaycore_gslb_agent_evidence_reports{state=\"unknown\"}",
        "gatewaycore_gslb_agent_evidence_reports{state=\"stale_or_missing\"}"
    ];

    public static bool TryParse(string text, out GslbRuntimeMetricsSnapshot? snapshot)
    {
        snapshot = null;
        if (Encoding.UTF8.GetByteCount(text) > 16_384) return false;
        var values = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var rawLine in text.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (rawLine.Length > 512) return false;
            var line = rawLine.TrimEnd('\r');
            foreach (var sample in Samples)
            {
                var prefix = sample + " ";
                if (!line.StartsWith(prefix, StringComparison.Ordinal)) continue;
                if (!int.TryParse(line.AsSpan(prefix.Length), NumberStyles.None,
                        CultureInfo.InvariantCulture, out var value) || value > 65_535 ||
                    !values.TryAdd(sample, value)) return false;
                break;
            }
        }
        if (values.Count != Samples.Length) return false;
        snapshot = new GslbRuntimeMetricsSnapshot(
            values[Samples[0]], values[Samples[1]], values[Samples[2]], values[Samples[3]],
            values[Samples[4]], values[Samples[5]], values[Samples[6]]);
        return snapshot.QuorumTargets + snapshot.BelowQuorumTargets == snapshot.ConfiguredTargets;
    }
}
