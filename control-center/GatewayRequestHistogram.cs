using System.Diagnostics;
using System.Globalization;
using System.Text;

/// <summary>Fixed low-cardinality histogram. O(number of buckets) read and one atomic write/request.</summary>
public sealed class GatewayRequestHistogram
{
    public static readonly double[] UpperBoundsSeconds = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];
    private readonly long[] _exclusiveBucketCounts = new long[UpperBoundsSeconds.Length + 1];
    private long _inflight;
    public void Started() => Interlocked.Increment(ref _inflight);
    public long InFlight => Interlocked.Read(ref _inflight);
    public void Finished(long elapsedTicks)
    {
        Interlocked.Decrement(ref _inflight);
        var seconds = elapsedTicks / (double)Stopwatch.Frequency;
        var index = 0;
        for (; index < UpperBoundsSeconds.Length; index++)
            if (seconds <= UpperBoundsSeconds[index]) break;
        Interlocked.Increment(ref _exclusiveBucketCounts[index]);
    }
    public void Append(StringBuilder output)
    {
        output.AppendLine("# HELP yarp_control_http_inflight_requests Non-admin requests currently in flight");
        output.AppendLine("# TYPE yarp_control_http_inflight_requests gauge");
        output.Append("yarp_control_http_inflight_requests ").Append(InFlight).Append('\n');
        output.AppendLine("# HELP yarp_control_http_duration_seconds Gateway non-admin HTTP request duration");
        output.AppendLine("# TYPE yarp_control_http_duration_seconds histogram");
        long cumulative = 0;
        for (var i = 0; i < _exclusiveBucketCounts.Length; i++)
        {
            cumulative += Interlocked.Read(ref _exclusiveBucketCounts[i]);
            output.Append("yarp_control_http_duration_seconds_bucket{le=\"")
                .Append(i < UpperBoundsSeconds.Length
                    ? UpperBoundsSeconds[i].ToString("R", CultureInfo.InvariantCulture)
                    : "+Inf")
                .Append("\"} ").Append(cumulative).Append('\n');
        }
        output.Append("yarp_control_http_duration_seconds_count ").Append(cumulative).Append('\n');
    }
}
