using System.Globalization;
using System.Text;

internal sealed record GslbRuntimeMetricsSnapshot(
    int ConfiguredTargets,
    int QuorumTargets,
    int BelowQuorumTargets,
    int HealthyReports,
    int UnhealthyReports,
    int UnknownReports,
    int StaleOrMissingReports);

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
