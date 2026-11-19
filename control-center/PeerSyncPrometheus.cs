using System.Globalization;
using System.Text;

/// <summary>Low-cardinality Prometheus exposition for best-effort peer telemetry.</summary>
public static class PeerSyncPrometheus
{
    public static void Append(StringBuilder output, bool configured, PeerSyncStatus? status)
    {
        ArgumentNullException.ThrowIfNull(output);
        output.AppendLine("# HELP yarp_peer_sync_enabled Whether signed peer telemetry is configured on this node");
        output.AppendLine("# TYPE yarp_peer_sync_enabled gauge");
        output.Append("yarp_peer_sync_enabled ").Append(configured ? 1 : 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_remote_fresh Whether a current-minute authenticated remote snapshot is available");
        output.AppendLine("# TYPE yarp_peer_sync_remote_fresh gauge");
        output.Append("yarp_peer_sync_remote_fresh ")
            .Append(status?.RemoteReportedInCurrentMinute == true ? 1 : 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_last_accepted_age_seconds Monotonic age of the most recently accepted peer frame; omitted before first acceptance");
        output.AppendLine("# TYPE yarp_peer_sync_last_accepted_age_seconds gauge");
        if (status?.LastAcceptedAgeSeconds is { } ageSeconds)
            output.Append("yarp_peer_sync_last_accepted_age_seconds ")
                .Append(ageSeconds.ToString(CultureInfo.InvariantCulture)).Append('\n');
    }
}
