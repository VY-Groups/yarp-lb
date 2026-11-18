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

        var generatedUtc = DateTimeOffset.Parse("2026-11-18T12:00:00+00:00");
        var reportRows = GatewayTrafficReportCsv.DurationBucketRows(
            generatedUtc, generatedUtc.AddHours(-1), "=report,gateway", buckets);
        Check(reportRows.Count == buckets.Count,
            "traffic CSV exports every bounded duration histogram bucket");
        Check(reportRows[0].StartsWith("duration_bucket,", StringComparison.Ordinal) &&
              reportRows[0].EndsWith(",\"0.005\"", StringComparison.Ordinal) &&
              reportRows[^1].EndsWith(",\"'+Inf\"", StringComparison.Ordinal),
            "traffic CSV names exclusive bucket bounds including overflow");
        Check(reportRows.All(row => CsvFieldCount(row) == 12),
            "duration bucket CSV rows match the stable 12-column report schema");
        Check(reportRows[0].Contains("\"'=report,gateway\"", StringComparison.Ordinal),
            "formula-like gateway IDs are spreadsheet-safe in CSV reports");
    }

    private static void Check(bool passed, string label)
    {
        if (!passed) throw new Exception("FAIL: " + label);
        Console.WriteLine("PASS: " + label);
    }

    private static int CsvFieldCount(string row)
    {
        var fields = 1;
        var quoted = false;
        for (var i = 0; i < row.Length; i++)
        {
            if (row[i] == '"')
            {
                if (quoted && i + 1 < row.Length && row[i + 1] == '"') i++;
                else quoted = !quoted;
            }
            else if (row[i] == ',' && !quoted) fields++;
        }
        return fields;
    }
}
