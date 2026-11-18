using System.Globalization;

/// <summary>CSV rows for the fixed-cardinality gateway duration histogram.</summary>
public static class GatewayTrafficReportCsv
{
    public static IReadOnlyList<string> DurationBucketRows(
        DateTimeOffset generatedUtc,
        DateTimeOffset processStartedUtc,
        string gateway,
        IReadOnlyList<GatewayRequestDurationBucket> buckets)
    {
        ArgumentNullException.ThrowIfNull(gateway);
        ArgumentNullException.ThrowIfNull(buckets);
        return buckets.Select(bucket => string.Join(',', new[]
        {
            "duration_bucket",
            Csv(generatedUtc.ToString("O", CultureInfo.InvariantCulture)),
            Csv(processStartedUtc.ToString("O", CultureInfo.InvariantCulture)),
            Csv(gateway),
            "",
            bucket.Requests.ToString(CultureInfo.InvariantCulture),
            "", "", "", "", "",
            Csv(bucket.UpperBoundSeconds)
        })).ToArray();
    }

    private static string Csv(string value)
    {
        var firstNonWhitespace = value.TrimStart();
        if (firstNonWhitespace.Length > 0 && firstNonWhitespace[0] is '=' or '+' or '-' or '@')
            value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
