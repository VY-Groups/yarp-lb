using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.AspNetCore.Http;

internal static class GatewayTelemetryLifecycleTests
{
    public static void Run()
    {
        var stopped = new ConcurrentQueue<Activity>();
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == GatewayOpenTelemetry.ActivitySourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stopped.Enqueue(activity)
        };
        ActivitySource.AddActivityListener(listener);

        var context = new DefaultHttpContext();
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        var activity = GatewayOpenTelemetry.StartProxyActivity(context);
        if (activity is null)
            throw new InvalidOperationException("Proxy telemetry listener did not create an activity");

        GatewayOpenTelemetry.CompleteProxyActivity(activity, context, "backend_a");

        if (activity.Duration <= TimeSpan.Zero || activity.Status != ActivityStatusCode.Error ||
            activity.GetTagItem("gateway.destination.id") as string != "backend_a" ||
            stopped.Count != 1 || !ReferenceEquals(stopped.Single(), activity))
            throw new InvalidOperationException("Proxy telemetry completion must tag and stop its activity once");

        Console.WriteLine("PASS: proxy telemetry activity is tagged and stopped once");
    }
}
