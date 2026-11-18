internal static class DestinationTelemetryTests
{
    public static void Run()
    {
        var telemetry = new DestinationTelemetry();
        for (var i = 0; i < DestinationTelemetry.MaximumTrackedDestinations; i++)
        {
            if (!telemetry.Record("cluster/destination-" + i, 200, 1.25))
                throw new Exception("FAIL: destination below the cap should be tracked");
        }

        Check(telemetry.TrackedDestinationCount == DestinationTelemetry.MaximumTrackedDestinations,
            "destination telemetry stops at its fixed cardinality cap");
        Check(!telemetry.Record("cluster/churn-a", 503, 5) &&
              !telemetry.Record("cluster/churn-b", 404, 7) &&
              !telemetry.Record("cluster/churn-a", 200, 1),
            "overflow destinations are omitted rather than assigned new metric labels");
        Check(telemetry.TrackedDestinationCount == DestinationTelemetry.MaximumTrackedDestinations &&
              telemetry.UntrackedRequests == 3,
            "destination churn is observable in one aggregate counter while cardinality stays bounded");
        Check(telemetry.Record("cluster/destination-0", 502, 2) &&
              telemetry.TryGetValue("cluster/destination-0", out var tracked) &&
              tracked.Requests == 2 && tracked.ServerErrors == 1 &&
              telemetry.UntrackedRequests == 3,
            "already tracked destinations continue updating after the cap is reached");

        var concurrent = new DestinationTelemetry();
        Parallel.For(0, 1000, _ => concurrent.Record("cluster/shared", 200, 1));
        Check(concurrent.TrackedDestinationCount == 1 &&
              concurrent.TryGetValue("cluster/shared", out var shared) && shared.Requests == 1000,
            "concurrent first requests share a single destination counter");
    }

    private static void Check(bool passed, string label)
    {
        if (!passed) throw new Exception("FAIL: " + label);
        Console.WriteLine("PASS: " + label);
    }
}
