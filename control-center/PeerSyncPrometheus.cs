using System.Globalization;
using System.Text;

/// <summary>Low-cardinality Prometheus exposition for best-effort peer telemetry.</summary>
public static class PeerSyncPrometheus
{
    public static void Append(StringBuilder output, bool configured, PeerSyncStatus? status,
        PeerSyncPublisherStatus? publisher = null)
    {
        ArgumentNullException.ThrowIfNull(output);
        output.AppendLine("# HELP yarp_peer_sync_enabled Whether signed peer telemetry is configured on this node");
        output.AppendLine("# TYPE yarp_peer_sync_enabled gauge");
        output.Append("yarp_peer_sync_enabled ").Append(configured ? 1 : 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_remote_fresh Whether a current-minute authenticated remote snapshot is available");
        output.AppendLine("# TYPE yarp_peer_sync_remote_fresh gauge");
        output.Append("yarp_peer_sync_remote_fresh ")
            .Append(status?.RemoteReportedInCurrentMinute == true ? 1 : 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_last_accepted_age_seconds Monotonic age of the most recently accepted peer frame; NaN means no frame has been accepted");
        output.AppendLine("# TYPE yarp_peer_sync_last_accepted_age_seconds gauge");
        output.Append("yarp_peer_sync_last_accepted_age_seconds ")
            .Append(status?.LastAcceptedAgeSeconds is { } ageSeconds
                ? ageSeconds.ToString(CultureInfo.InvariantCulture) : "NaN").Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_attempts_total Outbound signed peer snapshot attempts");
        output.AppendLine("# TYPE yarp_peer_sync_publish_attempts_total counter");
        output.Append("yarp_peer_sync_publish_attempts_total ")
            .Append(publisher?.AttemptsTotal ?? 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_acknowledgements_total Successful outbound HTTPS peer acknowledgements");
        output.AppendLine("# TYPE yarp_peer_sync_publish_acknowledgements_total counter");
        output.Append("yarp_peer_sync_publish_acknowledgements_total ")
            .Append(publisher?.AcknowledgementsTotal ?? 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_http_failures_total Rejected outbound peer HTTP responses, excluding valid boot challenges");
        output.AppendLine("# TYPE yarp_peer_sync_publish_http_failures_total counter");
        output.Append("yarp_peer_sync_publish_http_failures_total ")
            .Append(publisher?.HttpFailuresTotal ?? 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_transport_failures_total Outbound peer transport failures");
        output.AppendLine("# TYPE yarp_peer_sync_publish_transport_failures_total counter");
        output.Append("yarp_peer_sync_publish_transport_failures_total ")
            .Append(publisher?.TransportFailuresTotal ?? 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_resynchronizations_total Receiver boot challenges that changed the known peer epoch");
        output.AppendLine("# TYPE yarp_peer_sync_publish_resynchronizations_total counter");
        output.Append("yarp_peer_sync_publish_resynchronizations_total ")
            .Append(publisher?.ResynchronizationsTotal ?? 0).Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_last_ack_age_seconds Monotonic age of the latest outbound HTTPS acknowledgement; NaN means none");
        output.AppendLine("# TYPE yarp_peer_sync_publish_last_ack_age_seconds gauge");
        output.Append("yarp_peer_sync_publish_last_ack_age_seconds ")
            .Append(publisher?.LastAcknowledgedAgeSeconds is { } ackAge
                ? ackAge.ToString(CultureInfo.InvariantCulture) : "NaN").Append('\n');
        output.AppendLine("# HELP yarp_peer_sync_publish_in_flight Outbound peer requests currently in flight (bounded to one by the publisher loop)");
        output.AppendLine("# TYPE yarp_peer_sync_publish_in_flight gauge");
        output.Append("yarp_peer_sync_publish_in_flight ")
            .Append(publisher?.InFlightRequests ?? 0).Append('\n');
    }
}
