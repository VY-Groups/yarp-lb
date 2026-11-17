using System.Diagnostics;

internal static class GatewayMetricsTests
{
    public static void Run()
    {
        var histogram = new GatewayRequestHistogram();
        histogram.Started();
        histogram.Finished(Stopwatch.Frequency / 1000); // 1 ms
        histogram.Started();
        histogram.Finished(Stopwatch.Frequency / 50); // 20 ms
        histogram.Started();
        histogram.Finished(Stopwatch.Frequency * 11); // overflow bucket
        var buckets = histogram.Snapshot();
        Check(histogram.InFlight == 0 && buckets.Count == 12,
            "duration snapshot is bounded and returns all fixed buckets");
        Check(buckets[0].UpperBoundSeconds == "0.005" && buckets[0].Requests == 1,
            "duration snapshot reports the 5 ms bucket");
        Check(buckets[2].UpperBoundSeconds == "0.025" && buckets[2].Requests == 1,
            "duration snapshot reports the 25 ms bucket");
        Check(buckets[^1].UpperBoundSeconds == "+Inf" && buckets[^1].Requests == 1,
            "duration snapshot reports the overflow bucket");
    }

    private static void Check(bool passed, string label)
    {
        if (!passed) throw new Exception("FAIL: " + label);
        Console.WriteLine("PASS: " + label);
    }
}
